#include "canToEthMod.h"

struct net_device *ctem_dev;

void ctem_init(struct net_device *dev)
{
    dev->type = ARPHRD_CAN;
	dev->mtu = CAN_MTU;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 10;

	/* New-style flags. */
	dev->flags = IFF_NOARP;
	dev->features = NETIF_F_HW_CSUM;
}

static void __exit ctem_cleanup_module(void)
{   
    struct ctem_priv *priv;

    printk(KERN_INFO "%s: Exiting Module\n",MODULE_NAME);

    priv = netdev_priv(ctem_dev);
    unregister_netdev(ctem_dev);    
    kthread_stop(priv->thread);
    sock_release(priv->udp_receive_socket);  
    free_netdev(ctem_dev);
}

static int __init ctem_init_module(void)
{
    int ret = -ENOMEM;

    printk(KERN_DEBUG "%s: Initalizing Module %s\n",MODULE_NAME, MODULE_NAME);   

    // Allocate devices
    ctem_dev = alloc_netdev(0, "can%d", NET_NAME_UNKNOWN, ctem_init);   
    if (ctem_dev == NULL){
        printk(KERN_ERR "%s: Failed to allocate device\n",MODULE_NAME);
        goto out_alloc;
    }
    printk(KERN_DEBUG "%s: Allocated device.\n",MODULE_NAME);   

    // register devices    
    ret = register_netdev(ctem_dev);
    if (ret){
        printk(KERN_ERR "%s: error %i registering device %s\n",MODULE_NAME,ret,ctem_dev->name);
        goto out_register;
    }        
    printk(KERN_DEBUG "%s: Registered device.\n",MODULE_NAME);

    
    goto out;

    out_register: unregister_netdev(ctem_dev);    
    out_alloc: free_netdev(ctem_dev);
    out: return ret;
}

module_init(ctem_init_module);
module_exit(ctem_cleanup_module);
MODULE_AUTHOR("Matthias Unterrainer");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION(MODULE_NAME);