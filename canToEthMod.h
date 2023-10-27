#ifndef _CAN_TO_ETH_MOD_H
#define _CAN_TO_ETH_MOD_H

#include <linux/can.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/socket.h>

#define MODULE_NAME "CAN_TO_ETH_MODULE"

struct ctem_priv {
    struct net_device_stats stats;
    struct net_device *dev;
    struct socket *udp_socket;
    struct task_struct *udp_thread;
    struct sockaddr *udp_addr_listen;
    struct sockaddr *udp_addr_send;
};

static int ctem_open(struct net_device *dev);
static int ctem_stop(struct net_device *dev);
static netdev_tx_t ctem_xmit(struct sk_buff* skb, struct net_device *dev );

static const struct net_device_ops ctem_netdev_ops = {
    .ndo_open = ctem_open,
    .ndo_stop = ctem_stop,
    .ndo_start_xmit = ctem_xmit,
};

void ctem_init(struct net_device *dev);
static void ctem_start_udp(struct net_device *dev);
static int ctem_setup_udp(struct net_device *dev, int udp_listen_port, int udp_send_port);
static void ctem_teardown_udp(struct net_device *dev);

static int ctem_packet_reception_thread(void *arg);

static __exit void ctem_cleanup_module(void);
static __init int ctem_init_module(void);

#endif /* _CAN_TO_ETH_MOD_H */