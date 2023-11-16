#include "canToEthMod.h"

struct net_device *ctem_dev;

static int setup_sock_addr(struct sockaddr **addr, int port, u32 ip);

static int setup_sock_addr(struct sockaddr **addr, int port, u32 ip)
{
    struct sockaddr_in *udp_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

    if (udp_addr == NULL)
        return -ENOMEM;

    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = PF_INET;
    udp_addr->sin_port = htons(port);
    udp_addr->sin_addr.s_addr = ip;
    *addr = (struct sockaddr *)udp_addr;

    return 0;
}

static struct net_device_stats *ctem_get_stats(struct net_device *dev)
{
    struct rtnl_link_stats64 stats64;

    printk(KERN_DEBUG "%s: Get Stats\n", MODULE_NAME);

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

static void ctem_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *storage)
{
    struct ctem_priv *priv = netdev_priv(dev);

    printk(KERN_DEBUG "%s: Get Stats64\n", MODULE_NAME);

    memcpy(storage, priv->stats, sizeof(struct rtnl_link_stats64));
}

static int ctem_open(struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);
    int err;

    printk(KERN_DEBUG "%s: Opened %s\n", MODULE_NAME, dev->name);

    err = can_rx_offload_add_manual(dev, &priv->offload, CTEM_NAPI_WEIGHT);
    if (err)
    {
        close_candev(dev);
        return err;
    }

    can_rx_offload_enable(&priv->offload);

    priv->can.state = CAN_STATE_ERROR_ACTIVE;

    netif_carrier_on(dev);
    netif_start_queue(dev);
    return 0;
}

static int ctem_stop(struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);

    printk(KERN_DEBUG "%s: Stopped %s\n", MODULE_NAME, dev->name);

    netif_carrier_off(dev);
    netif_stop_queue(dev);

    can_rx_offload_disable(&priv->offload);
    priv->can.state = CAN_STATE_STOPPED;
    can_rx_offload_del(&priv->offload);
    close_candev(dev);

    return 0;
}

static netdev_tx_t ctem_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);
    struct can_frame *frame = (struct can_frame *)skb->data;
    struct msghdr msg;
    struct kvec iov;
    char can_frame_data[sizeof(struct can_frame)];
    int ret;

    if (printk_ratelimit())
        printk(KERN_INFO "%s: TX CAN - FRAME: Id: %d , %x %x %x %x %x %x %x %x\n", MODULE_NAME, frame->can_id, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4], frame->data[5], frame->data[6], frame->data[7]);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));

    memcpy(can_frame_data, frame, sizeof(can_frame_data));

    iov.iov_base = frame;
    iov.iov_len = sizeof(can_frame_data);

    msg.msg_name = priv->udp_addr_dst;
    msg.msg_namelen = sizeof(*priv->udp_addr_dst);

    ret = kernel_sendmsg(priv->udp_socket, &msg, &iov, 1, iov.iov_len);

    if (ret < 0)
    {
        if (printk_ratelimit())
            printk(KERN_WARNING "%s: Did not send message! Error: %d\n", MODULE_NAME, ret);

        priv->stats->tx_errors++;
        priv->stats->tx_dropped++;
    }
    else
    {
        if (printk_ratelimit())
            printk(KERN_INFO "%s: Send %d bytes.\n", MODULE_NAME, ret);
        priv->stats->tx_packets++;
        priv->stats->tx_bytes += ret;
    }

    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int ctem_parse_frame(struct net_device *dev, void *buf, size_t sz)
{
    struct ctem_priv *priv = netdev_priv(dev);
    struct timespec64 hdr_ts;
    struct can2eth_pkthdr *hdr = (struct can2eth_pkthdr *)buf;
    int16_t size = htons(hdr->size);

    if (sz < sizeof(struct can2eth_pkthdr))
    {
        printk(KERN_ERR "%s: received datagram was too short to be a can2eth packet.\n", MODULE_NAME);
        return -1;
    }

    if (htonl(hdr->magic) != 0x43324547)
    {
        printk(KERN_ERR "%s: received datagram does not have can2eth magic number.\n", MODULE_NAME);
        return -2;
    }

    if (sz < size)
    {
        printk(KERN_ERR "%s: received datagram is shorter than what declared in the can2eth header.\n", MODULE_NAME);
        return -3;
    }

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
            printk(KERN_ERR "%s: a chunk in the received datagram is cut short. %d %u\n", MODULE_NAME, size, chunk_size);
            return -5;
        }

        switch (chunk_type)
        {
        case 0xc0fe:
        {
            struct can2eth_can_chunk *can_chunk = (struct can2eth_can_chunk *)(buf);
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

            if (len + offsetof(struct can2eth_can_chunk, data) != chunk_size)
            {
                printk(KERN_WARNING "%s: can chunk size is unexpected (16+%u / %u)\n", MODULE_NAME, len, chunk_size);
                break;
            }
            memcpy(data, can_chunk->data, len);
            if (can_id & 0x80000000)
            {
                // canfd frames
                struct canfd_frame *frame;

                skb = alloc_canfd_skb(dev, &frame);
                if (!skb)
                {
                    printk(KERN_ERR "%s: Failed to allocate ksb for CANFD frame\n", MODULE_NAME);
                    return -ENOMEM;
                }

                frame->can_id = htonl(can_chunk->can_id);
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
                    printk(KERN_ERR "%s: Failed to allocate ksb for CAN frame\n", MODULE_NAME);
                    return -ENOMEM;
                }
                frame->can_id = htonl(can_chunk->can_id);
                frame->len = can_chunk->len;
                for (unsigned i = 0; i < frame->len; i++)
                {
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
        default:
        {
            printk(KERN_WARNING "%s: warning: unknown chunk type 0x%04x.\n", MODULE_NAME, chunk_type);
            break;
        }
        }

        sz -= chunk_size;
        buf += chunk_size;
    }

    if (sz > 0)
    {
        printk(KERN_ERR "%s: datagram has %lu leftover bytes.\n", MODULE_NAME, sz);
        return -4;
    }

    return NET_RX_SUCCESS;
}

static int ctem_packet_reception_thread(void *arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct ctem_priv *priv = netdev_priv(dev);

    printk(KERN_DEBUG "%s: Started listing\n", MODULE_NAME);

    while (!kthread_should_stop())
    {
        struct msghdr msg;
        struct sockaddr_in sender_addr;
        struct kvec iov;
        unsigned char receive_buffer[CTEM_BUFFER_SIZE];
        int ret;

        // initalize structs
        memset(&sender_addr, 0, sizeof(sender_addr));
        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));
        memset(receive_buffer, 0, sizeof(receive_buffer));

        // set up iov struct
        iov.iov_base = receive_buffer;
        iov.iov_len = sizeof(receive_buffer);

        ret = kernel_recvmsg(priv->udp_socket, &msg, &iov, 1, iov.iov_len, MSG_WAITALL);
        if (ret < 0)
        {
            if (printk_ratelimit())
                printk(KERN_DEBUG "%s: Error while listening to udp socket: %d\n", MODULE_NAME, ret);

            priv->stats->rx_errors++;
        }
        else
        {
            int err;
            /*
             * TODO: Use workqueue here
             */
            if (printk_ratelimit())
                printk(KERN_DEBUG "%s: Received %d Bytes.\n", MODULE_NAME, ret);

            /*
             * TODO: Handle return value
             */
            err = ctem_parse_frame(dev, receive_buffer, ret);
        }
    }

    printk(KERN_DEBUG "%s: Stopped listing\n", MODULE_NAME);
    return 0;
}

static void ctem_start_udp(struct net_device *dev)
{
    struct ctem_priv *priv = netdev_priv(dev);

    (void)wake_up_process(priv->udp_thread);
}

static int ctem_setup_udp(struct net_device *dev, u32 udp_dest_addr, int dest_port, int src_port)
{
    int ret;
    struct ctem_priv *priv = netdev_priv(dev);

    ret = setup_sock_addr(&priv->udp_addr_src, src_port, INADDR_ANY);
    if (ret)
    {
        printk(KERN_ERR "%s: Error setting up udp listen addr %lu:%d\n", MODULE_NAME, INADDR_ANY, src_port);
        return ret;
    }
    printk(KERN_DEBUG "%s: listening to udp %lu:%d", MODULE_NAME, INADDR_ANY, src_port);

    ret = setup_sock_addr(&priv->udp_addr_dst, dest_port, udp_dest_addr);
    if (ret)
    {
        printk(KERN_ERR "%s: Error setting up udp send addr %u:%d\n", MODULE_NAME, udp_dest_addr, dest_port);
        return ret;
    }
    printk(KERN_DEBUG "%s: sending to udp %u:%d", MODULE_NAME, udp_dest_addr, dest_port);

    // set up UDP socket
    ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &(priv->udp_socket));
    if (ret)
    {
        printk(KERN_ERR "%s: Error creating UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    // bind UDP socket to udp_addr
    ret = kernel_bind(priv->udp_socket, priv->udp_addr_src, sizeof(*(priv->udp_addr_src)));
    if (ret)
    {
        printk(KERN_ERR "%s: Error binding UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    priv->udp_thread = kthread_create(ctem_packet_reception_thread, dev, "udp_thread");
    if (IS_ERR(priv->udp_thread))
    {
        printk(KERN_ERR "%s: Error creating UDP thread\n", MODULE_NAME);
        return PTR_ERR(priv->udp_thread);
    }

    return ret;
}

static void ctem_teardown_udp(struct net_device *dev)
{
    struct ctem_priv *priv;
    priv = netdev_priv(dev);

    if (priv->udp_thread != NULL)
        (void)kthread_stop(priv->udp_thread);
    if (priv->udp_socket != NULL)
        sock_release(priv->udp_socket);
    if (priv->udp_addr_src != NULL)
        kfree(priv->udp_addr_src);
    if (priv->udp_addr_dst != NULL)
        kfree(priv->udp_addr_dst);
}

static void ctem_init(struct net_device *dev)
{
    struct ctem_priv *priv;

    dev->type = ARPHRD_CAN;
    dev->mtu = CAN_MTU;
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
    priv = netdev_priv(dev);
    memset(priv, 0, sizeof(struct ctem_priv));
    priv->dev = dev;
    priv->udp_socket = NULL;
    priv->udp_thread = NULL;
    priv->udp_addr_src = NULL;
    priv->udp_addr_dst = NULL;

    // initialize stats struct
    priv->stats = kmalloc(sizeof(struct rtnl_link_stats64), GFP_KERNEL);
    memset(priv->stats, 0, sizeof(struct rtnl_link_stats64));
}

static __exit void ctem_cleanup_module(void)
{
    printk(KERN_DEBUG "%s: Unregistering CAN to Eth Driver\n", MODULE_NAME);

    ctem_teardown_udp(ctem_dev);

    unregister_netdev(ctem_dev);
}

static __init int ctem_init_module(void)
{
    int ret;
    u32 dest_addr = INADDR_ANY;

    printk(KERN_DEBUG "%s: Registering CAN to Eth Driver\n", MODULE_NAME);

    if (udp_dest_ip_str == NULL || strlen(udp_dest_ip_str) == 0)
        printk(KERN_WARNING "%s: No ip dest addr specified\n", MODULE_NAME);
    else
    {
        printk(KERN_DEBUG "%s: Loaded with ip dest addr: %s\n", MODULE_NAME, udp_dest_ip_str);
        dest_addr = in_aton(udp_dest_ip_str);
    }

    ctem_dev = alloc_candev(sizeof(struct ctem_priv), 0);

    ctem_init(ctem_dev);

    ret = ctem_setup_udp(ctem_dev, dest_addr, udp_dest_port, udp_src_port);
    if (ret)
    {
        printk(KERN_ERR "%s: Failed to setup udp\n", MODULE_NAME);
        ctem_teardown_udp(ctem_dev);
        return ret;
    }

    ctem_start_udp(ctem_dev);

    ret = register_candev(ctem_dev);
    if (ret)
    {
        free_candev(ctem_dev);
        return ret;
    }

    return 0;
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");
