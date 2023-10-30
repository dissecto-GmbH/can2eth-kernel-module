#include "canToEthMod.h"

static int setup_sock_addr(struct sockaddr **addr, int port, u32 ip);

static int setup_sock_addr(struct sockaddr **addr, int port, u32 ip)
{
    struct sockaddr_in *udp_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);

    if (udp_addr == NULL)
        return -ENOMEM;

    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = PF_INET;
    udp_addr->sin_port = htons(port);
    udp_addr->sin_addr.s_addr = htonl(ip);
    *addr = (struct sockaddr *)udp_addr;

    return 0;
}

static void ctem_dellink(struct net_device *dev, struct list_head *head)
{
    struct ctem_priv *priv = netdev_priv(dev);

    printk(KERN_DEBUG "%s: dellink\n", MODULE_NAME);

    ctem_teardown_udp(dev);
    kfree(priv->stats);

    dev->flags |= IFF_DORMANT;

    unregister_netdevice_queue(dev, NULL);
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
        printk(KERN_INFO "%s: TX with %d CAN - FRAME: Id: %d , %x %x %x %x %x %x %x %x\n", MODULE_NAME, frame->can_id, frame->data[0], frame->data[1], frame->data[2], frame->data[3], frame->data[4], frame->data[5], frame->data[6], frame->data[7]);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));

    memcpy(can_frame_data, frame, sizeof(can_frame_data));

    iov.iov_base = frame;
    iov.iov_len = sizeof(can_frame_data);

    msg.msg_name = priv->udp_addr_send;
    msg.msg_namelen = sizeof(*priv->udp_addr_send);

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
        memcpy(can_frame->data, &buf[8], sizeof(CAN_MAX_DLEN));

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

static void ctem_test_parse_frame(struct net_device *dev)
{
    struct can_frame *cf;
    struct sk_buff *can_skb;
    int ans = 0x87654321;
    int packet_len = sizeof(int);

    int ans_net_byte_order = htonl(ans);

    can_skb = dev_alloc_skb(packet_len + sizeof(struct can_frame));
    if (can_skb)
    {
        cf = (struct can_frame *)skb_put(can_skb, sizeof(struct can_frame));
        cf->len = packet_len;
        cf->can_id = 0x321;
        memcpy(cf->data, &ans_net_byte_order, packet_len);

        // memcpy(skb_put(can_skb,packet_len),ans,packet_len);

        can_skb->dev = dev;
        can_skb->protocol = htons(ETH_P_CAN);
        can_skb->ip_summed = CHECKSUM_UNNECESSARY;

        netif_rx(can_skb);
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
        unsigned char receive_buffer[sizeof(struct can_frame)];
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
            // should propably use smth. like Work-Queues for this part
            // ctem_parse_frame(dev, receive_buffer, sizeof(receive_buffer));

            // just for testing
            ctem_test_parse_frame(dev);
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

static int ctem_setup_udp(struct net_device *dev, int udp_listen_port, int udp_send_port)
{
    int ret;
    struct ctem_priv *priv = netdev_priv(dev);

    ret = setup_sock_addr(&priv->udp_addr_listen, udp_listen_port, INADDR_ANY);
    if (ret)
    {
        printk(KERN_ERR "%s: Error setting up udp listen addr\n", MODULE_NAME);
        return ret;
    }

    ret = setup_sock_addr(&priv->udp_addr_send, udp_send_port, in_aton("192.168.122.1"));
    if (ret)
    {
        printk(KERN_ERR "%s: Error setting up udp send addr\n", MODULE_NAME);
        return ret;
    }

    // set up UDP socket
    ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &(priv->udp_socket));
    if (ret)
    {
        printk(KERN_ERR "%s: Error creating UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    // bind UDP socket to udp_addr
    ret = kernel_bind(priv->udp_socket, priv->udp_addr_listen, sizeof(*(priv->udp_addr_listen)));
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

    if (priv->udp_socket != NULL)
        sock_release(priv->udp_socket);
    if (priv->udp_thread != NULL)
        (void)kthread_stop(priv->udp_thread);
    if (priv->udp_addr_listen != NULL)
        kfree(priv->udp_addr_listen);
    if (priv->udp_addr_send != NULL)
        kfree(priv->udp_addr_send);
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
    priv->udp_addr_listen = NULL;
    priv->udp_addr_send = NULL;

    // initialize stats struct
    priv->stats = kmalloc(sizeof(struct rtnl_link_stats64), GFP_KERNEL);
    memset(priv->stats, 0, sizeof(struct rtnl_link_stats64));

    // set can middle layer priv data
    can_ml = (void *)priv + ALIGN(sizeof(*priv), NETDEV_ALIGN);
    can_set_ml_priv(dev, can_ml);
}

static void ctem_setup(struct net_device *dev)
{
    int ret;

    ctem_init(dev);

    ret = ctem_setup_udp(dev, 1069, 1069);
    if (ret)
    {
        printk(KERN_ERR "%s: Failed to setup udp\n", MODULE_NAME);
    }

    ctem_start_udp(dev);
}

static __exit void ctem_cleanup_module(void)
{
    printk(KERN_DEBUG "%s: Unregistering CAN to Eth Driver\n", MODULE_NAME);

    rtnl_link_unregister(&ctem_link_ops);
}

static __init int ctem_init_module(void)
{
    printk(KERN_DEBUG "%s: Registering CAN to Eth Driver\n", MODULE_NAME);

    return rtnl_link_register(&ctem_link_ops);
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");