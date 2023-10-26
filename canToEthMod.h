#ifndef _CAN_TO_ETH_MOD_H
#define _CAN_TO_ETH_MOD_H

#include <linux/can.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/socket.h>

#define MODULE_NAME "CAN_TO_ETH_MODULE"

extern struct net_device *ctem_dev;

struct ctem_priv {
    struct net_device_stats stats;
    struct net_device *dev;
    struct socket *udp_receive_socket;
    struct task_struct *thread;
};

void ctem_init(struct net_device *dev);

static void __exit ctem_cleanup_module(void);
static int __init ctem_init_module(void);

#endif /* _CAN_TO_ETH_MOD_H */