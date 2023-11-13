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

    memcpy(priv->stats, storage, sizeof(struct rtnl_link_stats64));
}

static int ctem_open(struct net_device *dev)
{
    printk(KERN_INFO "%s: Opened %s\n", MODULE_NAME, dev->name);

    netif_carrier_on(dev);
    netif_start_queue(dev);
    return 0;
}

static int ctem_stop(struct net_device *dev)
{
    printk(KERN_INFO "%s: Stopped %s\n", MODULE_NAME, dev->name);

    netif_carrier_off(dev);
    netif_stop_queue(dev);
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

static void ctem_parse_frame(struct net_device *dev, unsigned char *buf, int size)
{
    struct can_frame *can_frame;
    struct sk_buff *skb;
    struct ctem_priv *priv = netdev_priv(dev);
    int ret;

    skb = netdev_alloc_skb(dev, sizeof(struct can_frame));

    if (skb)
    {
        can_frame = (struct can_frame *)skb_put(skb, sizeof(struct can_frame));

        can_frame->can_id = (buf[2] << 8) | buf[3];
        can_frame->len = buf[4];
        memcpy(can_frame->data, &buf[8], can_frame->len);

        skb->dev = dev;
        skb->protocol = htons(ETH_P_CAN);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        ret = netif_rx(skb);

        // update stats
        if (ret == NET_RX_DROP)
            priv->stats->rx_dropped++;
        else if (ret == NET_RX_SUCCESS)
        {
            priv->stats->rx_bytes += can_frame->len;
            priv->stats->rx_packets++;
        }
    }
    else
    {
        priv->stats->rx_errors++;
    }
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
        unsigned char receive_buffer[2000];
        int ret;

        // initalize structs
        memset(&sender_addr, 0, sizeof(sender_addr));
        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));

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
            /*
             * TODO: Use workqueue here
             */
            if (printk_ratelimit())
                printk(KERN_DEBUG "%s: Received %d Bytes.\n", MODULE_NAME, ret);

            // ctem_parse_frame(dev, receive_buffer, sizeof(receive_buffer));
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
    struct can_ml_priv *can_ml;

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

    // set can middle layer priv data
    can_ml = (void *)priv + ALIGN(sizeof(*priv), NETDEV_ALIGN);
    can_set_ml_priv(dev, can_ml);
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

    ctem_dev = alloc_netdev(sizeof(struct ctem_priv), "can%d", NET_NAME_UNKNOWN, ctem_init);

    ret = ctem_setup_udp(ctem_dev, dest_addr, udp_dest_port, udp_src_port);
    if (ret)
    {
        printk(KERN_ERR "%s: Failed to setup udp\n", MODULE_NAME);
        ctem_teardown_udp(ctem_dev);
        return ret;
    }

    ctem_start_udp(ctem_dev);

    return register_netdev(ctem_dev);
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");