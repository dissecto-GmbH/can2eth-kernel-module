#include "canToEthMod.h"

struct net_device *ctem_dev;

static int setup_sock_addr(struct sockaddr** addr,int port);

static int setup_sock_addr(struct sockaddr** addr,int port)
{
    struct sockaddr_in *udp_addr = kmalloc(sizeof(struct sockaddr_in),GFP_KERNEL);

    if (udp_addr == NULL) return -ENOMEM;

    memset(udp_addr, 0, sizeof(struct sockaddr_in));
    udp_addr->sin_family = PF_INET;
    udp_addr->sin_port = htons(port);
    udp_addr->sin_addr.s_addr = htonl(INADDR_ANY);
    *addr = (struct sockaddr*)udp_addr;

    return 0;
}

static int ctem_open(struct net_device *dev)
{   
    printk(KERN_INFO "%s: Opened %s\n",MODULE_NAME, dev->name);
    netif_carrier_on(dev);
    netif_start_queue(dev);
    return 0;
}

static int ctem_stop(struct net_device *dev)
{
    printk(KERN_INFO "%s: Stopped %s\n",MODULE_NAME, dev->name);
    netif_carrier_off(dev);
    netif_stop_queue(dev);
    return 0;
}

static netdev_tx_t ctem_xmit(struct sk_buff* skb, struct net_device *dev )
{
    dev_kfree_skb(skb);
    return NETDEV_TX_OK;
}

static int ctem_packet_reception_thread(void *arg)
{
    struct net_device *dev = (struct net_device*) arg;
    struct ctem_priv *priv = netdev_priv(dev);

    printk(KERN_DEBUG "%s: Started listing\n", MODULE_NAME); 

    while(!kthread_should_stop())
    {
        struct msghdr msg;
        struct sockaddr_in sender_addr;
        struct kvec iov;
        struct can_frame can_frame;       
        int ret;
        
        // initalize structs
        memset(&sender_addr, 0, sizeof(sender_addr));
        memset(&msg, 0, sizeof(msg));
        memset(&iov, 0, sizeof(iov));
        memset(&can_frame, 0, sizeof(can_frame));

        // set up iov struct
        iov.iov_base = &can_frame;
        iov.iov_len = sizeof(struct can_frame);

        ret = kernel_recvmsg(priv->udp_socket, &msg, &iov, 1, iov.iov_len, MSG_WAITALL);
        if (ret < 0)
        {
            if(printk_ratelimit()) printk(KERN_DEBUG "%s: Error while listening to udp socket: %d\n", MODULE_NAME, ret);
        }
        else
        {
            if(printk_ratelimit()){                
                printk(KERN_DEBUG "%s: Received %d Bytes\nCAN frame - ID: %x, DLC: %d, Data: %x %x %x %x %x %x %x %x\n", MODULE_NAME, ret, can_frame.can_id, can_frame.can_dlc, can_frame.data[0], can_frame.data[1], can_frame.data[2], can_frame.data[3], can_frame.data[4], can_frame.data[5], can_frame.data[6], can_frame.data[7]);     
            }
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

    ret = setup_sock_addr(&priv->udp_addr_listen, udp_listen_port);
    if(ret)
    {
        printk(KERN_ERR "%s: Error setting up udp listen addr\n", MODULE_NAME);
        return ret;
    }

    ret = setup_sock_addr(&priv->udp_addr_send, udp_send_port);
    if(ret)
    {
        printk(KERN_ERR "%s: Error setting up udp send addr\n", MODULE_NAME);
        return ret;
    }

    // set up UDP socket
    ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,&(priv->udp_socket));
    if (ret) {
        printk(KERN_ERR "%s: Error creating UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    // bind UDP socket to udp_addr
    ret = kernel_bind(priv->udp_socket, priv->udp_addr_listen, sizeof(*(priv->udp_addr_listen)));
    if(ret){
        printk(KERN_ERR "%s: Error binding UDP socket: %d\n", MODULE_NAME, ret);
        return ret;
    }

    priv->udp_thread = kthread_create(ctem_packet_reception_thread,dev,"udp_thread");
    if (IS_ERR(priv->udp_thread)){
        printk(KERN_ERR "%s: Error creating UDP thread\n",MODULE_NAME);
        return PTR_ERR(priv->udp_thread);
    }

    return ret;
}

static void ctem_teardown_udp(struct net_device *dev)
{
    struct ctem_priv *priv;
    priv = netdev_priv(dev);

    if(priv->udp_socket != NULL) 
        sock_release(priv->udp_socket);
    if(priv->udp_thread != NULL)
        (void)kthread_stop(priv->udp_thread);
    if(priv->udp_addr_listen != NULL)
        kfree(priv->udp_addr_listen);
    if(priv->udp_addr_send != NULL)
        kfree(priv->udp_addr_send);
}

void ctem_init(struct net_device *dev)
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
}

static __exit void ctem_cleanup_module(void)
{       
    printk(KERN_INFO "%s: Exiting Module\n",MODULE_NAME);

    unregister_netdev(ctem_dev);    
    ctem_teardown_udp(ctem_dev);
    free_netdev(ctem_dev);
}

static __init int ctem_init_module(void)
{
    int ret = -ENOMEM;

    printk(KERN_DEBUG "%s: Initalizing Module %s\n",MODULE_NAME, MODULE_NAME);   

    // Allocate devices
    ctem_dev = alloc_netdev(sizeof(struct ctem_priv), "can%d", NET_NAME_UNKNOWN, ctem_init);   
    if (ctem_dev == NULL){
        printk(KERN_ERR "%s: Failed to allocate device\n",MODULE_NAME);
        goto out_alloc;
    }
    printk(KERN_DEBUG "%s: Allocated device.\n",MODULE_NAME);    

    ret = ctem_setup_udp(ctem_dev,1069,1069);
    if (ret)
    {
        printk(KERN_ERR "%s: Failed to setup udp\n", MODULE_NAME);
        goto out_udp;
    }

    ctem_start_udp(ctem_dev);

    // register devices    
    ret = -ENODEV;
    ret = register_netdev(ctem_dev);
    if (ret){
        printk(KERN_ERR "%s: error %i registering device %s\n",MODULE_NAME,ret,ctem_dev->name);
        goto out_register;
    }        
    printk(KERN_DEBUG "%s: Registered device.\n",MODULE_NAME);

    ret = 0;
    goto out;

    out_register: unregister_netdev(ctem_dev);
    out_udp: ctem_teardown_udp(ctem_dev); 
    out_alloc: free_netdev(ctem_dev);
    out: return ret;
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("CAN To Ethernet Kernel Module");