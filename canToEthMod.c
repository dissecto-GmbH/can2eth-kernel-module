#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/rx-offload.h>
#include <linux/delay.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>

#define MODULE_NAME "CanToEth"

#define CTEM_RX_BUFFER_SIZE 1500
#define CTEM_TX_BUFFER_SIZE 1500
#define CTEM_NAPI_WEIGHT 4

#define MAGIC_NUMBER 0x43324547 // C2EG
#define MAGIC_PACKET 0xc0fe
#define MAGIC_KEEP_ALIVE 0x57a7

#define NUM_ADDRESSES 10
#define NUM_INTERFACES 2

// this is the interval between checks for timeouts in the msgbuilder; since it
// uses usleep_range, a lower and upper limit have to be provided
#define CTEM_MIN_TIMEOUT_CHECK 900  // in microseconds
#define CTEM_MAX_TIMEOUT_CHECK 1100 // microseconds

static char *ip_addrs[NUM_ADDRESSES];
static int num_ip_addrs = 0; // the actual number of ip address provided
static int port = 8765;
static uint32_t timeout_ns = 10000000;

module_param_array(ip_addrs, charp, &num_ip_addrs, 0000);
module_param(port, int, S_IRUGO);
module_param(timeout_ns, uint, S_IRUGO);

struct ctem_comm_handler *ctem_communications;
struct net_device *ctem_devs[NUM_INTERFACES];

typedef int(sender_callback_t)(struct ctem_comm_handler *, void *, size_t);

typedef struct ctem_pktbuilder
{
    struct mutex mutex;
    uint16_t last_tx_seqno;
    unsigned pos;
    bool empty;
    struct timespec64 lastflush;
    uint32_t timeout_nsec;
    sender_callback_t *send;
    uint8_t buf[CTEM_TX_BUFFER_SIZE];
} pktbuilder_t;

struct ctem_comm_handler
{
    struct socket *udp_socket;
    struct sockaddr **dest_addrs;
    int num_addrs;
    uint16_t last_seqno;
    struct workqueue_struct *workqueue;
    struct ctem_pktbuilder *pktbuilder;
    struct task_struct *reception_thread;
    struct task_struct *transmission_thread;
};

struct can2eth_pkthdr
{
    uint32_t magic;
    uint32_t tv_sec;
    uint32_t tv_nsec;
    uint16_t seqno;
    uint16_t size;
};

struct can2eth_can_chunk
{
    uint32_t tv_sec;
    uint32_t tv_nsec;
    uint32_t can_id; /* 32 bit CAN_ID + EFF/RTR/ERR flags */
    uint8_t interface_idx;
    uint8_t reserved;
    uint8_t len;   /* frame payload length in byte (0 .. 64) */
    uint8_t flags; /* additional flags for CAN FD */
    uint8_t data[64] __attribute__((aligned(8)));
};

struct stats_and_keepalive_chunk
{
    uint32_t total_frames_relayed;
    uint16_t cpu_free;
    uint16_t spi_busy;
    uint32_t free_heap;
    uint32_t min_heap;
    uint16_t timestamp_diff0;
    uint16_t timestamp_diff1;
    uint16_t free_fifo;
};

struct ctem_priv
{
    struct can_priv can;
    struct can_rx_offload offload;
    struct mutex rx_mutex;
    size_t if_idx;
};

struct ctem_reception_work
{
    struct work_struct work;
    struct ctem_comm_handler *handler;
    unsigned char *buffer;
    size_t size;
};

static int
internal_msgbuilder_flush(struct ctem_comm_handler *handler)
{
    pktbuilder_t *pkt_builder = handler->pktbuilder;
    struct timespec64 ts;
    struct can2eth_pkthdr *pkthdr;
    int r;

    ktime_get_real_ts64(&ts);

    if (pkt_builder->empty)
    {
        pkt_builder->lastflush = ts;
        return 0;
    }

    pkthdr = (void *)pkt_builder->buf;
    pkthdr->magic = htonl(MAGIC_NUMBER);
    pkthdr->tv_sec = htonl(ts.tv_sec);
    pkthdr->tv_nsec = htonl(ts.tv_nsec);
    pkthdr->seqno = htons(++pkt_builder->last_tx_seqno);
    pkthdr->size = htons((uint16_t)pkt_builder->pos);

    r = pkt_builder->send(handler, pkt_builder->buf, pkt_builder->pos);
    pkt_builder->empty = true;
    pkt_builder->pos = sizeof(*pkthdr);
    pkt_builder->lastflush = ts;
    return r;
}

int msgbuilder_flush_if_it_is_time(struct ctem_comm_handler *handler)
{
    pktbuilder_t *pkt_builder = handler->pktbuilder;
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

    if (since > pkt_builder->timeout_nsec)
    {
        result = internal_msgbuilder_flush(handler);
    }

    mutex_unlock(&pkt_builder->mutex);

    return result;
}

int msgbuilder_enqueue(struct ctem_comm_handler *handler, void *data, uint16_t len,
                       uint16_t ctype)
{

    pktbuilder_t *pkt_builder = handler->pktbuilder;
    int result = -1;

    mutex_lock(&pkt_builder->mutex);

    if (pkt_builder->pos + len + 4 > CTEM_TX_BUFFER_SIZE)
    {
        int r = internal_msgbuilder_flush(handler);
        if (r < 0)
        {
            result = -3;
        }
    }

    if (pkt_builder->pos + len + 4 <= CTEM_TX_BUFFER_SIZE)
    {
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

    result = msgbuilder_flush_if_it_is_time(handler);
    return result;
}

static int
ctem_send_packet(struct ctem_comm_handler *handler, void *data, size_t len)
{
    for (unsigned int i = 0; i < handler->num_addrs; i++)
    {
        struct sockaddr *addr;
        struct msghdr msg;
        struct kvec iov;
        char *packet_data;
        int ret;

        if (!handler->dest_addrs[i])
            break;

        addr = handler->dest_addrs[i];

        packet_data = (char *)kmalloc(len * sizeof(char), GFP_KERNEL);
        if (!packet_data)
        {
            pr_err("%s: Error sending UDP Frame\n", MODULE_NAME);
            continue;
        }

        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));

        memcpy(packet_data, data, len);

        iov.iov_base = packet_data;
        iov.iov_len = len;

        msg.msg_name = addr;
        msg.msg_namelen = sizeof(*addr);

        ret = kernel_sendmsg(handler->udp_socket, &msg, &iov, 1, iov.iov_len);

        kfree(packet_data);
    }
    return NETDEV_TX_OK;
}

static int
ctem_transmission_thread(void *arg)
{
    struct ctem_comm_handler *handler = (struct ctem_comm_handler *)arg;
    static struct timespec64 last_ka = {0};

    pr_debug("%s: start transmission thread\n", MODULE_NAME);

    while (!kthread_should_stop())
    {
        struct timespec64 now;

        usleep_range(CTEM_MIN_TIMEOUT_CHECK, CTEM_MAX_TIMEOUT_CHECK);
        msgbuilder_flush_if_it_is_time(handler);

        ktime_get_real_ts64(&now);
        if (timespec64_sub(now, last_ka).tv_sec >= 1)
        {
            struct stats_and_keepalive_chunk statchunk;
            last_ka = now;
            // msgbuilder_enqueue(handler, &statchunk, sizeof(statchunk), MAGIC_KEEP_ALIVE);
        }
    }

    pr_debug("%s: stopped transmission thread\n", MODULE_NAME);

    return 0;
}

int msgbuilder_init(struct ctem_comm_handler *handler)
{
    pktbuilder_t *pkt_builder;

    handler->pktbuilder =
        (pktbuilder_t *)kmalloc(sizeof(pktbuilder_t), GFP_KERNEL);
    pkt_builder = handler->pktbuilder;

    pkt_builder->timeout_nsec = timeout_ns;
    pkt_builder->pos = sizeof(struct can2eth_pkthdr);
    pkt_builder->empty = true;
    pkt_builder->send = &ctem_send_packet;

    mutex_init(&pkt_builder->mutex);

    handler->transmission_thread = kthread_create(
        ctem_transmission_thread, handler, "ctem_transmission_thread");
    if (IS_ERR(handler->transmission_thread))
    {
        pr_err("%s: Error creating Transmission thread\n", MODULE_NAME);
        return PTR_ERR(handler->transmission_thread);
    }

    return 0;
}

static int
ctem_parse_frame(void *buf, size_t sz)
{
    struct timespec64 hdr_ts;
    struct can2eth_pkthdr *hdr = (struct can2eth_pkthdr *)buf;
    int16_t size = htons(hdr->size);

    if (sz < sizeof(struct can2eth_pkthdr))
    {
        pr_err("%s: received datagram was too short to be a can2eth packet.\n",
               MODULE_NAME);
        return -1;
    }

    if (htonl(hdr->magic) != MAGIC_NUMBER)
    {
        pr_err("%s: received datagram does not have can2eth magic number.\n",
               MODULE_NAME);
        return -2;
    }

    if (sz < size)
    {
        pr_err("%s: received datagram is shorter than what declared "
               "in the can2eth header.\n",
               MODULE_NAME);
        return -3;
    }

    if (hdr->seqno > ctem_communications->last_seqno + 1)
    {
        pr_warn("%s: Jump in sequence numbers detected. Went from %hu to %hu\n", MODULE_NAME, ctem_communications->last_seqno, hdr->seqno);
    }
    ctem_communications->last_seqno = hdr->seqno;

    hdr_ts.tv_sec = htonl(hdr->tv_sec);
    hdr_ts.tv_nsec = htonl(hdr->tv_nsec);
    buf += sizeof(struct can2eth_pkthdr);
    sz -= sizeof(struct can2eth_pkthdr);

    for (unsigned chunk_idx = 0; sz > 4; chunk_idx++)
    {
        uint16_t chunk_size = htons(((uint16_t *)buf)[0]);
        uint16_t chunk_type = htons(((uint16_t *)buf)[1]);
        sz -= 4;
        buf += 4;
        if (sz < chunk_size)
        {
            pr_err("%s: a chunk in the received datagram is cut short. %d %u\n",
                   MODULE_NAME, size, chunk_size);
            return -5;
        }

        switch (chunk_type)
        {
        case MAGIC_PACKET:
        {
            struct can2eth_can_chunk *can_chunk =
                (struct can2eth_can_chunk *)(buf);
            struct timespec64 ts;
            uint32_t can_id = htonl(can_chunk->can_id);
            uint8_t if_idx = can_chunk->interface_idx;
            uint8_t len = can_chunk->len;
            struct sk_buff *skb;
            struct net_device *dev;
            struct ctem_priv *priv;
            int ret;

            if (if_idx < NUM_INTERFACES)
            {
                dev = ctem_devs[if_idx];
                if (!netif_running(dev))
                {
                    netdev_err(dev, "%s: %s not running\n", MODULE_NAME,
                               dev->name);
                    break;
                }
            }
            else
            {
                pr_err("%s: Interface %d, index out of range\n", MODULE_NAME,
                       if_idx);
                break;
            }

            priv = netdev_priv(dev);

            ts.tv_sec = htonl(can_chunk->tv_sec);
            ts.tv_nsec = htonl(can_chunk->tv_nsec);

            if (len + offsetof(struct can2eth_can_chunk, data) != chunk_size)
            {
                netdev_warn(dev,
                            "%s: can chunk size is unexpected (16+%u / %u)\n",
                            MODULE_NAME, len, chunk_size);
                break;
            }

            if (can_chunk->flags)
            {
                // canfd frames
                struct canfd_frame *frame;

                skb = alloc_canfd_skb(dev, &frame);
                if (!skb)
                {
                    netdev_err(dev,
                               "%s: Failed to allocate ksb for CANFD frame\n",
                               MODULE_NAME);
                    return -ENOMEM;
                }

                frame->can_id = can_id;
                frame->len = can_chunk->len;
                frame->flags = can_chunk->flags;
                for (unsigned i = 0; i < frame->len; i++)
                {
                    frame->data[i] = can_chunk->data[i];
                }
            }
            else
            {
                // can frames
                struct can_frame *frame;

                skb = alloc_can_skb(dev, &frame);
                if (!skb)
                {
                    netdev_err(dev,
                               "%s: Failed to allocate ksb for CAN frame\n",
                               MODULE_NAME);
                    return -ENOMEM;
                }
                frame->can_id = can_id;
                frame->len = can_chunk->len;
                for (unsigned i = 0; i < frame->len; i++)
                {
                    frame->data[i] = can_chunk->data[i];
                }
            }

            // set skb timestamp to timestamp from chunk
            skb->tstamp = timespec64_to_ktime(ts);

            mutex_lock(&priv->rx_mutex);

            ret = can_rx_offload_queue_tail(&priv->offload, skb);
            can_rx_offload_irq_finish(&priv->offload);

            mutex_unlock(&priv->rx_mutex);

            break;
        }
        default:
        {
            pr_warn("%s: warning: unknown chunk type 0x%04x.\n", MODULE_NAME,
                    chunk_type);
            break;
        }
        }

        sz -= chunk_size;
        buf += chunk_size;
    }

    if (sz > 0)
    {
        pr_err("%s: datagram has %lu leftover bytes.\n", MODULE_NAME, sz);
        return -4;
    }

    return NET_RX_SUCCESS;
}

static void
ctem_reception_work_function(struct work_struct *work)
{
    struct ctem_reception_work *ctem_work =
        container_of(work, struct ctem_reception_work, work);

    ctem_parse_frame((void *)ctem_work->buffer, ctem_work->size);

    kfree(ctem_work->buffer);
    kfree(ctem_work);
}

static int
ctem_reception_thread(void *arg)
{
    struct ctem_comm_handler *handler = (struct ctem_comm_handler *)arg;

    pr_debug("%s: Started listing\n", MODULE_NAME);

    while (!kthread_should_stop())
    {
        struct msghdr msg = {0};
        struct kvec iov;
        unsigned char *receive_buffer =
            kmalloc(CTEM_RX_BUFFER_SIZE, GFP_KERNEL);
        int ret;

        if (!receive_buffer)
        {
            pr_err("%s: Failed to allocate reception buffer\n", MODULE_NAME);
            continue;
        }

        // set up iov struct
        iov.iov_base = receive_buffer;
        iov.iov_len = CTEM_RX_BUFFER_SIZE;

        ret = kernel_recvmsg(handler->udp_socket, &msg, &iov, 1, iov.iov_len,
                             MSG_WAITALL);
        if (ret < 0)
        {
            pr_err("%s: Error while listening to udp socket: %d\n", MODULE_NAME,
                   ret);
        }
        else
        {
            struct ctem_reception_work *work =
                kmalloc(sizeof(struct ctem_reception_work), GFP_KERNEL);

            if (!work)
            {
                pr_err("%s: Failed to allocate work\n", MODULE_NAME);
                kfree(receive_buffer);
                continue;
            }

            work->handler = handler;
            work->buffer = receive_buffer;
            work->size = ret;

            INIT_WORK(&work->work, ctem_reception_work_function);
            queue_work(handler->workqueue, &work->work);

            pr_debug("%s: Received %d Bytes.\n", MODULE_NAME, ret);
        }
    }

    pr_debug("%s: Stopped listing\n", MODULE_NAME);
    return 0;
}

int ctem_setup_udp(struct ctem_comm_handler *handler, int src_port)
{
    struct sockaddr *src_addr;
    int ret;

    struct sockaddr_in *udp_addr =
        kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

    if (!udp_addr)
    {
        pr_err("Error allocating the address the UDP is listing to\n");
        return -ENOMEM;
    }

    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = PF_INET;
    udp_addr->sin_port = htons(port);
    udp_addr->sin_addr.s_addr = INADDR_ANY;
    src_addr = (struct sockaddr *)udp_addr;

    // set up UDP socket
    ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
                           &handler->udp_socket);
    if (ret)
    {
        pr_err("%s: Error creating UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    // bind UDP socket to udp_addr
    ret = kernel_bind(handler->udp_socket, src_addr, sizeof(*src_addr));
    if (ret)
    {
        pr_err("%s: Error binding UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    return 0;
}

int parse_ip_port(const char *addr_port_str, u32 *ip_out, u16 *port_out)
{
    char ip_str[16];
    int ret;
    char *colon = strchr(addr_port_str, ':');

    if (!colon || colon == addr_port_str || !*(colon + 1))
        return -EINVAL;

    strncpy(ip_str, addr_port_str, colon - addr_port_str);
    ip_str[colon - addr_port_str] = '\0';

    ret = in4_pton(ip_str, -1, (u8 *)ip_out, -1, NULL);
    if (ret != 1)
        return -EINVAL;

    if (kstrtou16(colon + 1, 10, port_out))
        return -EINVAL;

    return 0;
}

int ctem_setup_communications(struct ctem_comm_handler *handler, int src_port,
                              char **addrs, int num_addrs)
{
    int ret;

    handler->dest_addrs = kmalloc(sizeof(struct sockaddr *), GFP_KERNEL);
    if (!handler->dest_addrs)
    {
        pr_err("Could not allocate destination addresses\n");
        return -ENOMEM;
    }

    handler->last_seqno = 0;

    // parse input ip addresses
    {
        u32 ip;
        u16 port;

        if (!num_addrs)
        {
            struct sockaddr_in *addr =
                kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
            if (!addr)
            {
                pr_err("Could not allocate ip addr\n");
                return -ENOMEM;
            }

            addr->sin_family = PF_INET;
            addr->sin_port = htons(port);
            addr->sin_addr.s_addr = INADDR_ANY;

            handler->dest_addrs[0] = (struct sockaddr *)addr;

            handler->num_addrs = 1;
        }
        else
        {

            for (int i = 0; i < num_addrs; i++)
            {
                ret = parse_ip_port(ip_addrs[i], &ip, &port);
                if (ret)
                {
                    pr_err("Invalid IP/port format: %s\n", ip_addrs[i]);
                }
                else
                {
                    pr_debug("Parsed IP: %pI4, Port: %u\n", &ip, port);
                    struct sockaddr_in *addr =
                        kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
                    if (!addr)
                    {
                        pr_err("Could not allocate ip addr\n");
                        return -ENOMEM;
                    }

                    addr->sin_family = PF_INET;
                    addr->sin_port = htons(port);
                    addr->sin_addr.s_addr = ip;

                    handler->dest_addrs[i] = (struct sockaddr *)addr;
                }

                handler->num_addrs = num_addrs;
            }
        }
    }

    ret = ctem_setup_udp(handler, src_port);

    ret = msgbuilder_init(handler);

    handler->workqueue = create_singlethread_workqueue("ctem_rx_workqueue");
    if (!handler->workqueue)
    {
        pr_err("%s: Failed to create workqueue\n", MODULE_NAME);
        return -ENOMEM;
    }

    handler->reception_thread =
        kthread_create(ctem_reception_thread, handler, "ctem_reception_thread");
    if (IS_ERR(handler->reception_thread))
    {
        pr_err("%s: Error creating reception thread\n", MODULE_NAME);
        return PTR_ERR(handler->reception_thread);
    }

    return 0;
}

void ctem_teardown_communications(struct ctem_comm_handler *handler)
{
    if (handler->reception_thread)
        (void)kthread_stop(handler->reception_thread);

    if (handler->transmission_thread)
        (void)kthread_stop(handler->transmission_thread);

    flush_workqueue(handler->workqueue);

    if (handler->udp_socket)
        sock_release(handler->udp_socket);

    for (int i = 0; i < handler->num_addrs; i++)
    {
        if (handler->dest_addrs[i])
            kfree(handler->dest_addrs[i]);
    }

    destroy_workqueue(handler->workqueue);
}

void ctem_start_communications(struct ctem_comm_handler *handler)
{
    (void)wake_up_process(handler->reception_thread);
    (void)wake_up_process(handler->transmission_thread);
}

static int
ctem_open(struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);
    int ret;

    netdev_dbg(dev, "%s: Opened %s\n", MODULE_NAME, dev->name);

    ret = can_rx_offload_add_manual(dev, &priv->offload, CTEM_NAPI_WEIGHT);
    if (ret)
    {
        close_candev(dev);
        return ret;
    }

    can_rx_offload_enable(&priv->offload);

    priv->can.state = CAN_STATE_ERROR_ACTIVE;

    netif_carrier_on(dev);
    netif_start_queue(dev);

    open_candev(dev);

    return 0;
}

static int
ctem_stop(struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);

    netdev_dbg(dev, "%s: Stopped %s\n", MODULE_NAME, dev->name);

    netif_carrier_off(dev);
    netif_stop_queue(dev);

    can_rx_offload_disable(&priv->offload);

    priv->can.state = CAN_STATE_STOPPED;
    can_rx_offload_del(&priv->offload);

    // close_candev(dev);

    return 0;
}

static netdev_tx_t
ctem_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct can2eth_can_chunk frame;
    struct timespec64 ts;
    struct ctem_priv *priv = netdev_priv(dev);

    memset(&frame, 0, sizeof(struct can2eth_can_chunk));

    ktime_get_boottime_ts64(&ts);

    if (skb->len > CAN_MTU)
    {
        /* Handle canfd */

        struct canfd_frame *canfd_frame = (struct canfd_frame *)skb->data;

        frame.can_id = htonl(canfd_frame->can_id);
        frame.len = canfd_frame->len;
        frame.flags = canfd_frame->flags;

        memcpy(frame.data, canfd_frame->data, frame.len);
    }

    else
    {
        /* Handle can */

        struct can_frame *can_frame = (struct can_frame *)skb->data;

        frame.can_id = htonl(can_frame->can_id);
        frame.len = can_frame->len;

        memcpy(frame.data, can_frame->data, frame.len);
    }

    frame.tv_nsec = htonl((uint32_t)ts.tv_nsec);
    frame.tv_sec = htonl((uint32_t)ts.tv_sec);

    frame.interface_idx = priv->if_idx;

    msgbuilder_enqueue(ctem_communications, &frame, sizeof(frame) - 64 + frame.len, MAGIC_PACKET);

    consume_skb(skb);

    return NETDEV_TX_OK;
}

static const struct net_device_ops ctem_netdev_ops = {
    .ndo_open = ctem_open,
    .ndo_stop = ctem_stop,
    .ndo_start_xmit = ctem_xmit,
};

static const struct ethtool_ops ctem_ethtool_ops = {
    .get_ts_info = ethtool_op_get_ts_info,
};

static int
ctem_init(struct net_device *dev, size_t if_idx)
{
    struct ctem_priv *priv;

    dev->type = ARPHRD_CAN;
    dev->mtu = CANFD_MTU;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->tx_queue_len = 0;
    dev->flags = IFF_NOARP;

    dev->netdev_ops = &ctem_netdev_ops;
    dev->ethtool_ops = &ctem_ethtool_ops;

    /*
     * Initialize priv field
     */
    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct ctem_priv));

    priv->can.bittiming.bitrate = 50000;

    mutex_init(&priv->rx_mutex);

    priv->if_idx = if_idx;

    return 0;
}

static __exit void
ctem_cleanup_module(void)
{
    pr_debug("%s: Starting cleanup of CAN to Eth Driver\n", MODULE_NAME);

    for (unsigned int i = 0; i < NUM_INTERFACES; i++)
    {
        if (ctem_devs[i])
        {
            unregister_candev(ctem_devs[i]);
            free_candev(ctem_devs[i]);
        }
    }

    ctem_teardown_communications(ctem_communications);

    kfree(ctem_communications);
}

static __init int
ctem_init_module(void)
{
    unsigned int allocate_idx;
    unsigned int registered_idx;
    int ret = -ENOMEM;

    pr_debug("%s: Registering CAN to Eth Driver\n", MODULE_NAME);

    ctem_communications = (struct ctem_comm_handler *)kmalloc(
        sizeof(struct ctem_comm_handler), GFP_KERNEL);

    if (!ctem_communications)
        goto out;

    for (allocate_idx = 0; allocate_idx < NUM_INTERFACES; allocate_idx++)
    {
        ctem_devs[allocate_idx] = alloc_candev(sizeof(struct ctem_priv), 0);

        if (!ctem_devs[allocate_idx])
            goto out_free_previous_devs;

        ret = ctem_init(ctem_devs[allocate_idx], allocate_idx);
        if (ret)
        {
            netdev_err(ctem_devs[allocate_idx],
                       "%s: Failed to initialize priv data\n", MODULE_NAME);
            free_candev(ctem_devs[allocate_idx]);
            goto out_free_previous_devs;
        }
    }

    ret = ctem_setup_communications(ctem_communications, port, ip_addrs,
                                    num_ip_addrs);
    if (ret)
        goto out_teardown_communications;

    for (registered_idx = 0; registered_idx < NUM_INTERFACES;
         registered_idx++)
    {
        ret = register_candev(ctem_devs[registered_idx]);
        if (ret)
        {
            netdev_err(ctem_devs[registered_idx],
                       "%s: Failed to register the can network device\n",
                       MODULE_NAME);
            goto out_unregister_devs;
        }
    }

    ctem_start_communications(ctem_communications);

    return 0;

out_unregister_devs:
    while (registered_idx-- > 0)
    {
        unregister_candev(ctem_devs[registered_idx]);
    }
out_teardown_communications:
    ctem_teardown_communications(ctem_communications);
out_free_previous_devs:
    while (allocate_idx-- > 0)
    {
        free_candev(ctem_devs[allocate_idx]);
    }
    kfree(ctem_communications);
out:
    return ret;
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_INFO(depends, "can-dev");
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");