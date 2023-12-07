#include <linux/can.h>
#include <linux/can/can-ml.h>
#include <linux/can/dev.h>
#include <linux/can/raw.h>
#include <linux/can/rx-offload.h>
#include <linux/can/skb.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/types.h>

#define MODULE_NAME         "CanToEth"
#define CTEM_RX_BUFFER_SIZE 1800
#define CTEM_TX_BUFFER_SIZE 1000
#define CTEM_NAPI_WEIGHT    4

#define MAGIC_NUMBER     0x43324547   // C2EG
#define MAGIC_PACKET     0xc0fe
#define MAGIC_KEEP_ALIVE 0x57a7

struct net_device *ctem_dev;

static char *udp_dest_ip_str;
static int udp_dest_port = 8765;
static int udp_src_port = 8765;
static uint32_t ctx_timeout_ns = 10000000;

module_param(udp_dest_ip_str, charp, S_IRUGO);
module_param(udp_dest_port, int, S_IRUGO);
module_param(udp_src_port, int, S_IRUGO);
module_param(ctx_timeout_ns, uint, S_IRUGO);

typedef struct stats_and_keepalive_chunk {
    uint32_t total_frames_relayed;
    uint16_t cpu_free;
    uint16_t spi_busy;
    uint32_t free_heap;
    uint32_t min_heap;
    uint16_t timestamp_diff0;
    uint16_t timestamp_diff1;
    uint16_t free_fifo;
} stats_and_keepalive_chunk_t;

typedef int(sender_callback_t)(struct net_device *, void *, size_t);

typedef struct msgbuilder_pktbuilder {
    struct mutex mutex;
    uint16_t last_tx_seqno;
    unsigned pos;
    bool empty;
    struct timespec64 lastflush;
    uint32_t timeout_nsec;
    sender_callback_t *send;
    uint8_t buf[CTEM_TX_BUFFER_SIZE];
} pktbuilder_t;

int msgbuilder_init(struct net_device *dev);
void msgbuilder_start(struct net_device *dev);
int msgbuilder_flush_if_it_is_time(struct net_device *dev);
int msgbuilder_enqueue(struct net_device *dev, void *data, uint16_t len,
                       uint16_t ctype);
static void msgbuilder_teardown(struct net_device *dev);

struct can2eth_pkthdr {
    uint32_t magic;
    uint32_t tv_sec;
    uint32_t tv_nsec;
    uint16_t seqno;
    uint16_t size;
};

struct can2eth_can_chunk {
    uint32_t tv_sec;
    uint32_t tv_nsec;
    uint32_t can_id; /* 32 bit CAN_ID + EFF/RTR/ERR flags */
    uint8_t interface_idx;
    uint8_t reserved;
    uint8_t len;   /* frame payload length in byte (0 .. 64) */
    uint8_t flags; /* additional flags for CAN FD */
    uint8_t data[64] __attribute__((aligned(8)));
};

struct ctem_priv {
    /* Apparently this must be the first member when using alloc_candev() */
    struct can_priv can;
    struct can_rx_offload offload;
    struct rtnl_link_stats64 *stats;
    struct net_device *dev;
    struct socket *udp_socket;
    struct sockaddr *udp_addr_src;   // socket is listing to this
    struct sockaddr *udp_addr_dst;   // sending packets here
    pktbuilder_t *pkt_builder;
    struct task_struct *transmission_thread;
    struct task_struct *reception_thread;
};

static const struct ethtool_ops ctem_ethtool_ops = {
    .get_ts_info = ethtool_op_get_ts_info,
};

static int
internal_msgbuilder_flush(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);
    pktbuilder_t *pkt_builder = priv->pkt_builder;
    struct timespec64 ts;
    struct can2eth_pkthdr *pkthdr;
    int r;

    ktime_get_real_ts64(&ts);

    if (pkt_builder->empty) {
        pkt_builder->lastflush = ts;
        return 0;
    }

    pkthdr = (void *) pkt_builder->buf;
    pkthdr->magic = htonl(MAGIC_NUMBER);
    pkthdr->tv_sec = htonl(ts.tv_sec);
    pkthdr->tv_nsec = htonl(ts.tv_nsec);
    pkthdr->seqno = htons(++pkt_builder->last_tx_seqno);
    pkthdr->size = htons((uint16_t) pkt_builder->pos);

    r = pkt_builder->send(dev, pkt_builder->buf, pkt_builder->pos);
    pkt_builder->empty = true;
    pkt_builder->pos = sizeof(*pkthdr);
    pkt_builder->lastflush = ts;
    return r;
}

static int
ctem_send_packet(struct net_device *dev, void *data, size_t len) {
    struct ctem_priv *priv = netdev_priv(dev);
    struct msghdr msg;
    struct kvec iov;
    char *packet_data;
    int ret;

    packet_data = (char *) kmalloc(len * sizeof(char), GFP_KERNEL);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));

    memcpy(packet_data, data, len);

    iov.iov_base = packet_data;
    iov.iov_len = len;

    msg.msg_name = priv->udp_addr_dst;
    msg.msg_namelen = sizeof(*priv->udp_addr_dst);

    ret = kernel_sendmsg(priv->udp_socket, &msg, &iov, 1, iov.iov_len);

    if (ret < 0) {
        if (printk_ratelimit())
            printk(KERN_WARNING "%s: Did not send message! Error: %d\n",
                   MODULE_NAME, ret);

        priv->stats->tx_errors++;
        priv->stats->tx_dropped++;
    } else {
        if (printk_ratelimit())
            printk(KERN_INFO "%s: Send %d bytes.\n", MODULE_NAME, ret);
        priv->stats->tx_packets++;
        priv->stats->tx_bytes += ret;
    }

    return NETDEV_TX_OK;
}

static int
ctem_packet_transmission_thread(void *arg) {
    struct net_device *dev = (struct net_device *) arg;
    struct ctem_priv *priv = netdev_priv(dev);
    static struct timespec64 last_ka = {0};

    printk(KERN_INFO "%s: start transmission thread\n", MODULE_NAME);

    while (!kthread_should_stop()) {
        struct timespec64 now;

        msleep(100);
        msgbuilder_flush_if_it_is_time(dev);

        ktime_get_boottime_ts64(&now);
        if (timespec64_sub(now, last_ka).tv_sec >= 1) {
            stats_and_keepalive_chunk_t statchunk;
            last_ka = now;
            statchunk.total_frames_relayed = htonl(priv->stats->tx_packets);
            msgbuilder_enqueue(dev, &statchunk, sizeof(statchunk),
                               MAGIC_KEEP_ALIVE);
        }
    }

    printk(KERN_INFO "%s: stopped transmission thread\n", MODULE_NAME);

    return 0;
}

int
msgbuilder_init(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);
    pktbuilder_t *pkt_builder;

    priv->pkt_builder =
        (pktbuilder_t *) kmalloc(sizeof(pktbuilder_t), GFP_KERNEL);
    pkt_builder = priv->pkt_builder;

    pkt_builder->timeout_nsec = ctx_timeout_ns;
    pkt_builder->pos = sizeof(struct can2eth_pkthdr);
    pkt_builder->empty = true;
    pkt_builder->send = &ctem_send_packet;

    mutex_init(&pkt_builder->mutex);

    priv->transmission_thread = kthread_create(ctem_packet_transmission_thread,
                                               dev, "transmission_thread");
    if (IS_ERR(priv->transmission_thread)) {
        netdev_err(dev, "%s: Error creating UDP thread\n", MODULE_NAME);
        return PTR_ERR(priv->transmission_thread);
    }

    return 0;
}

void
msgbuilder_start(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);

    (void) wake_up_process(priv->transmission_thread);
}

static void
msgbuilder_teardown(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);

    if (priv->reception_thread != NULL)
        (void) kthread_stop(priv->transmission_thread);

    kfree(priv->pkt_builder);
}

int
msgbuilder_flush_if_it_is_time(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);
    pktbuilder_t *pkt_builder = priv->pkt_builder;
    struct timespec64 now;
    uint64_t now_ns;
    uint64_t lst_ns;
    uint64_t since;
    int result = -4;

    mutex_lock(&pkt_builder->mutex);

    ktime_get_real_ts64(&now);
    now_ns = now.tv_sec * 1000000000ULL + now.tv_nsec;
    lst_ns = pkt_builder->lastflush.tv_sec * 1000000000ULL +
             pkt_builder->lastflush.tv_nsec;
    since = now_ns - lst_ns;

    if (since > pkt_builder->timeout_nsec) {
        result = internal_msgbuilder_flush(dev);
    }

    mutex_unlock(&pkt_builder->mutex);

    return result;
}

int
msgbuilder_enqueue(struct net_device *dev, void *data, uint16_t len,
                   uint16_t ctype) {
    struct ctem_priv *priv = netdev_priv(dev);
    pktbuilder_t *pkt_builder = priv->pkt_builder;
    int result = -1;

    mutex_lock(&pkt_builder->mutex);

    if (pkt_builder->pos + len + 4 > CTEM_TX_BUFFER_SIZE) {
        int r = internal_msgbuilder_flush(dev);
        if (r < 0) {
            result = -3;
        }
    }

    if (pkt_builder->pos + len + 4 <= CTEM_TX_BUFFER_SIZE) {
        uint16_t chunksize = htons(len);
        uint16_t chunktype = htons(ctype);
        memcpy(pkt_builder->buf + pkt_builder->pos, &chunksize,
               sizeof(chunksize));
        pkt_builder->pos += 2;
        memcpy(pkt_builder->buf + pkt_builder->pos, &chunktype,
               sizeof(chunksize));
        pkt_builder->pos += 2;
        memcpy(pkt_builder->buf + pkt_builder->pos, data, len);
        pkt_builder->pos += len;
        pkt_builder->empty = false;
        result = 0;
    }

    mutex_unlock(&pkt_builder->mutex);

    result = msgbuilder_flush_if_it_is_time(dev);
    return result;
}

static int
setup_sock_addr(struct sockaddr **addr, int port, u32 ip) {
    struct sockaddr_in *udp_addr =
        kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

    if (!udp_addr)
        return -ENOMEM;

    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = PF_INET;
    udp_addr->sin_port = htons(port);
    udp_addr->sin_addr.s_addr = ip;
    *addr = (struct sockaddr *) udp_addr;

    return 0;
}

static void
ctem_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *storage) {
    struct ctem_priv *priv = netdev_priv(dev);

    netdev_dbg(dev, "%s: Get Stats64\n", MODULE_NAME);

    memcpy(storage, priv->stats, sizeof(struct rtnl_link_stats64));
}

static struct net_device_stats *
ctem_get_stats(struct net_device *dev) {
    struct rtnl_link_stats64 stats64;

    netdev_dbg(dev, "%s: Get Stats\n", MODULE_NAME);

    memset(&stats64, 0, sizeof(stats64));

    ctem_get_stats64(dev, &stats64);

    dev->stats.rx_bytes = stats64.rx_bytes;
    dev->stats.rx_dropped = stats64.rx_dropped;
    dev->stats.rx_errors = stats64.rx_errors;

    dev->stats.tx_bytes = stats64.tx_bytes;
    dev->stats.tx_dropped = stats64.tx_dropped;
    dev->stats.tx_errors = stats64.tx_errors;

    return &dev->stats;
}

static int
ctem_open(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);
    int err;

    netdev_dbg(dev, "%s: Opened %s\n", MODULE_NAME, dev->name);

    err = can_rx_offload_add_manual(dev, &priv->offload, CTEM_NAPI_WEIGHT);
    if (err) {
        close_candev(dev);
        return err;
    }

    can_rx_offload_enable(&priv->offload);

    priv->can.state = CAN_STATE_ERROR_ACTIVE;

    netif_carrier_on(dev);
    netif_start_queue(dev);
    return 0;
}

static int
ctem_stop(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);

    netdev_dbg(dev, "%s: Stopped %s\n", MODULE_NAME, dev->name);

    netif_carrier_off(dev);
    netif_stop_queue(dev);

    can_rx_offload_disable(&priv->offload);
    priv->can.state = CAN_STATE_STOPPED;
    can_rx_offload_del(&priv->offload);
    close_candev(dev);

    return 0;
}

static netdev_tx_t
ctem_xmit(struct sk_buff *skb, struct net_device *dev) {
    struct can2eth_can_chunk frame;
    struct timespec64 ts;

    memset(&frame, 0, sizeof(struct can2eth_can_chunk));

    ktime_get_real_ts64(&ts);

    if (skb->len > CAN_MTU) {
        /* Handle canfd */

        struct canfd_frame *canfd_frame = (struct canfd_frame *) skb->data;

        frame.can_id = cpu_to_be32(canfd_frame->can_id);
        frame.len = canfd_frame->len;
        frame.flags = canfd_frame->flags;

        memcpy(frame.data, canfd_frame->data, frame.len);
    }

    else {
        /* Handle can */

        struct can_frame *can_frame = (struct can_frame *) skb->data;

        frame.can_id = cpu_to_be32(can_frame->can_id);
        frame.len = can_frame->len;

        memcpy(frame.data, can_frame->data, frame.len);
    }

    frame.tv_nsec = htonl((uint32_t) ts.tv_nsec);
    frame.tv_sec = htonl((uint32_t) ts.tv_sec);

    return msgbuilder_enqueue(dev, &frame, sizeof(frame) - 64 + frame.len,
                              MAGIC_PACKET);
}

static int
ctem_parse_frame(struct net_device *dev, void *buf, size_t sz) {
    struct ctem_priv *priv = netdev_priv(dev);
    struct timespec64 hdr_ts;
    struct can2eth_pkthdr *hdr = (struct can2eth_pkthdr *) buf;
    int16_t size = htons(hdr->size);

    if (sz < sizeof(struct can2eth_pkthdr)) {
        netdev_err(
            dev,
            "%s: received datagram was too short to be a can2eth packet.\n",
            MODULE_NAME);
        return -1;
    }

    if (htonl(hdr->magic) != MAGIC_NUMBER) {
        netdev_err(
            dev, "%s: received datagram does not have can2eth magic number.\n",
            MODULE_NAME);
        return -2;
    }

    if (sz < size) {
        netdev_err(dev,
                   "%s: received datagram is shorter than what declared "
                   "in the can2eth header.\n",
                   MODULE_NAME);
        return -3;
    }

    hdr_ts.tv_sec = htonl(hdr->tv_sec);
    hdr_ts.tv_nsec = htonl(hdr->tv_nsec);
    buf += sizeof(struct can2eth_pkthdr);
    sz -= sizeof(struct can2eth_pkthdr);

    for (unsigned chunk_idx = 0; sz > 4; chunk_idx++) {
        uint16_t chunk_size = htons(((uint16_t *) buf)[0]);
        uint16_t chunk_type = htons(((uint16_t *) buf)[1]);
        sz -= 4;
        buf += 4;
        if (sz < chunk_size) {
            netdev_err(
                dev,
                "%s: a chunk in the received datagram is cut short. %d %u\n",
                MODULE_NAME, size, chunk_size);
            return -5;
        }

        switch (chunk_type) {
        case MAGIC_PACKET: {
            struct can2eth_can_chunk *can_chunk =
                (struct can2eth_can_chunk *) (buf);
            struct timespec64 ts;
            uint32_t can_id = htonl(can_chunk->can_id);
            uint8_t len = can_chunk->len;
            uint8_t data[64];
            struct sk_buff *skb;
            int ret;

            ts.tv_sec = htonl(can_chunk->tv_sec);
            ts.tv_nsec = htonl(can_chunk->tv_nsec);

            priv->stats->rx_bytes += can_chunk->len;
            priv->stats->rx_packets++;

            if (len + offsetof(struct can2eth_can_chunk, data) != chunk_size) {
                printk(KERN_WARNING
                       "%s: can chunk size is unexpected (16+%u / %u)\n",
                       MODULE_NAME, len, chunk_size);
                break;
            }
            memcpy(data, can_chunk->data, len);
            if (can_id & 0x80000000) {
                // canfd frames
                struct canfd_frame *frame;

                skb = alloc_canfd_skb(dev, &frame);
                if (!skb) {
                    netdev_err(dev,
                               "%s: Failed to allocate ksb for CANFD frame\n",
                               MODULE_NAME);
                    return -ENOMEM;
                }

                frame->can_id = htonl(can_chunk->can_id);
                frame->len = can_chunk->len;
                frame->flags = can_chunk->flags;
                for (unsigned i = 0; i < frame->len; i++) {
                    frame->data[i] = can_chunk->data[i];
                }
            } else {
                // can frames
                struct can_frame *frame;

                skb = alloc_can_skb(dev, &frame);
                if (!skb) {
                    netdev_err(dev,
                               "%s: Failed to allocate ksb for CAN frame\n",
                               MODULE_NAME);
                    return -ENOMEM;
                }
                frame->can_id = htonl(can_chunk->can_id);
                frame->len = can_chunk->len;
                for (unsigned i = 0; i < frame->len; i++) {
                    frame->data[i] = can_chunk->data[i];
                }
            }

            // set skb timestamp to timestamp from chunk
            skb->tstamp = timespec64_to_ktime(ts);

            ret = can_rx_offload_queue_tail(&priv->offload, skb);
            if (ret)
                priv->stats->rx_errors++;
            can_rx_offload_irq_finish(&priv->offload);

            break;
        }
        default: {
            printk(KERN_WARNING "%s: warning: unknown chunk type 0x%04x.\n",
                   MODULE_NAME, chunk_type);
            break;
        }
        }

        sz -= chunk_size;
        buf += chunk_size;
    }

    if (sz > 0) {
        netdev_err(dev, "%s: datagram has %lu leftover bytes.\n", MODULE_NAME,
                   sz);
        return -4;
    }

    return NET_RX_SUCCESS;
}

static int
ctem_packet_reception_thread(void *arg) {
    struct net_device *dev = (struct net_device *) arg;
    struct ctem_priv *priv = netdev_priv(dev);

    netdev_dbg(dev, "%s: Started listing\n", MODULE_NAME);

    while (!kthread_should_stop()) {
        struct msghdr msg;
        struct sockaddr_in sender_addr;
        struct kvec iov;
        unsigned char receive_buffer[CTEM_RX_BUFFER_SIZE];
        int ret;

        // initalize structs
        memset(&sender_addr, 0, sizeof(sender_addr));
        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));
        memset(receive_buffer, 0, sizeof(receive_buffer));

        // set up iov struct
        iov.iov_base = receive_buffer;
        iov.iov_len = sizeof(receive_buffer);

        ret = kernel_recvmsg(priv->udp_socket, &msg, &iov, 1, iov.iov_len,
                             MSG_WAITALL);
        if (ret < 0) {
            if (printk_ratelimit())
                netdev_dbg(dev, "%s: Error while listening to udp socket: %d\n",
                           MODULE_NAME, ret);

            priv->stats->rx_errors++;
        } else {
            int err;
            /*
             * TODO: Use workqueue here
             */
            if (printk_ratelimit())
                netdev_dbg(dev, "%s: Received %d Bytes.\n", MODULE_NAME, ret);

            /*
             * TODO: Handle return value
             */
            err = ctem_parse_frame(dev, receive_buffer, ret);
        }
    }

    netdev_dbg(dev, "%s: Stopped listing\n", MODULE_NAME);
    return 0;
}

static void
ctem_start_udp(struct net_device *dev) {
    struct ctem_priv *priv = netdev_priv(dev);

    (void) wake_up_process(priv->reception_thread);
}

static int
ctem_setup_udp(struct net_device *dev, u32 udp_dest_addr, int dest_port,
               int src_port) {
    int ret;
    struct ctem_priv *priv = netdev_priv(dev);

    ret = setup_sock_addr(&priv->udp_addr_src, src_port, INADDR_ANY);
    if (ret) {
        netdev_err(dev, "%s: Error setting up udp listen addr %lu:%d\n",
                   MODULE_NAME, INADDR_ANY, src_port);
        return ret;
    }
    netdev_dbg(dev, "%s: listening to udp %lu:%d", MODULE_NAME, INADDR_ANY,
               src_port);

    ret = setup_sock_addr(&priv->udp_addr_dst, dest_port, udp_dest_addr);
    if (ret) {
        netdev_err(dev, "%s: Error setting up udp send addr %u:%d\n",
                   MODULE_NAME, udp_dest_addr, dest_port);
        return ret;
    }
    netdev_dbg(dev, "%s: sending to udp %u:%d", MODULE_NAME, udp_dest_addr,
               dest_port);

    // set up UDP socket
    ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
                           &(priv->udp_socket));
    if (ret) {
        netdev_err(dev, "%s: Error creating UDP socket: %d\n", MODULE_NAME,
                   ret);
        return ret;
    }

    // bind UDP socket to udp_addr
    ret = kernel_bind(priv->udp_socket, priv->udp_addr_src,
                      sizeof(*(priv->udp_addr_src)));
    if (ret) {
        netdev_err(dev, "%s: Error binding UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    priv->reception_thread =
        kthread_create(ctem_packet_reception_thread, dev, "reception_thread");
    if (IS_ERR(priv->reception_thread)) {
        netdev_err(dev, "%s: Error creating UDP thread\n", MODULE_NAME);
        return PTR_ERR(priv->reception_thread);
    }

    return ret;
}

static void
ctem_teardown_udp(struct net_device *dev) {
    struct ctem_priv *priv;
    priv = netdev_priv(dev);

    if (priv->reception_thread != NULL)
        (void) kthread_stop(priv->reception_thread);
    if (priv->udp_socket != NULL)
        sock_release(priv->udp_socket);
    if (priv->udp_addr_src != NULL)
        kfree(priv->udp_addr_src);
    if (priv->udp_addr_dst != NULL)
        kfree(priv->udp_addr_dst);
}

static void
ctem_free_priv(struct ctem_priv *priv) {
    if (!priv)
        return;

    kfree(priv->stats);
    kfree(priv->udp_socket);
    kfree(priv->udp_addr_dst);
    kfree(priv->udp_addr_src);
}

static const struct net_device_ops ctem_netdev_ops = {
    .ndo_open = ctem_open,
    .ndo_stop = ctem_stop,
    .ndo_start_xmit = ctem_xmit,
    .ndo_get_stats64 = ctem_get_stats64,
    .ndo_get_stats = ctem_get_stats,
};

static int
ctem_init(struct net_device *dev) {
    struct ctem_priv *priv;
    priv = netdev_priv(dev);

    dev->type = ARPHRD_CAN;
    dev->mtu = CANFD_MTU;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->tx_queue_len = 10;

    dev->flags = IFF_NOARP;
    dev->features = NETIF_F_HW_CSUM;

    dev->netdev_ops = &ctem_netdev_ops;
    dev->ethtool_ops = &ctem_ethtool_ops;

    dev->needs_free_netdev = true;

    /*
     * Initialize priv field
     */
    memset(priv, 0, sizeof(struct ctem_priv));
    priv->dev = dev;

    // initialize stats struct
    priv->stats = kmalloc(sizeof(struct rtnl_link_stats64), GFP_KERNEL);

    if (!priv->stats)
        return -ENOMEM;

    memset(priv->stats, 0, sizeof(struct rtnl_link_stats64));

    return 0;
}

static __exit void
ctem_cleanup_module(void) {
    pr_debug("%s: Unregistering CAN to Eth Driver\n", MODULE_NAME);

    msgbuilder_teardown(ctem_dev);

    ctem_teardown_udp(ctem_dev);

    unregister_netdev(ctem_dev);
}

static __init int
ctem_init_module(void) {
    int r;
    u32 dest_addr = INADDR_ANY;

    pr_debug("%s: Registering CAN to Eth Driver\n", MODULE_NAME);

    if (!udp_dest_ip_str || strlen(udp_dest_ip_str) == 0)
        pr_warn("%s: No ip dest addr specified\n", MODULE_NAME);
    else {
        pr_warn("%s: Loaded with ip dest addr: %s\n", MODULE_NAME,
                udp_dest_ip_str);
        dest_addr = in_aton(udp_dest_ip_str);
    }

    ctem_dev = alloc_candev(sizeof(struct ctem_priv), 0);

    if (!ctem_dev)
        goto out;

    r = ctem_init(ctem_dev);
    if (r) {
        netdev_err(ctem_dev, "%s: Failed to initialize priv data\n",
                   MODULE_NAME);
        goto out_init;
    }

    r = ctem_setup_udp(ctem_dev, dest_addr, udp_dest_port, udp_src_port);
    if (r) {
        netdev_err(ctem_dev, "%s: Failed to setup udp\n", MODULE_NAME);
        goto out_udp;
    }

    r = msgbuilder_init(ctem_dev);
    if (r) {
        netdev_err(ctem_dev, "%s: Failed to initialize msgbuilder\n",
                   MODULE_NAME);
        goto out_msgbuilder;
    }

    ctem_start_udp(ctem_dev);

    msgbuilder_start(ctem_dev);

    r = register_candev(ctem_dev);
    if (r) {
        netdev_err(ctem_dev, "%s: Failed to register the network device\n",
                   MODULE_NAME);
        goto out_register;
    }

    return 0;

out_register:
    msgbuilder_teardown(ctem_dev);
out_msgbuilder:
    ctem_teardown_udp(ctem_dev);
out_udp:
    ctem_free_priv(netdev_priv(ctem_dev));
out_init:
    free_candev(ctem_dev);
out:
    return -1;
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_INFO(depends, "can-dev");
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");
