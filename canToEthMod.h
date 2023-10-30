#ifndef _CAN_TO_ETH_MOD_H
#define _CAN_TO_ETH_MOD_H

#include <linux/can.h>
#include <linux/can/core.h>
#include <linux/can/can-ml.h>
#include <linux/can/raw.h>
#include <linux/errno.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <net/rtnetlink.h>

#define MODULE_NAME "CanToEth"

struct ctem_priv
{
    struct rtnl_link_stats64 *stats;
    struct net_device *dev;
    struct socket *udp_socket;
    struct task_struct *udp_thread;
    struct sockaddr *udp_addr_listen;
    struct sockaddr *udp_addr_send;
    int bitrate;
};

static const struct ethtool_ops ctem_ethtool_ops = {
    .get_ts_info = ethtool_op_get_ts_info,
};

static void ctem_setup(struct net_device *dev);
static void ctem_dellink(struct net_device *dev, struct list_head *head);

static struct rtnl_link_ops ctem_link_ops __read_mostly = {
    .kind = MODULE_NAME,
    .priv_size = sizeof(struct ctem_priv) + sizeof(struct can_ml_priv),
    .setup = ctem_setup,
    .dellink = ctem_dellink,
};

static int ctem_open(struct net_device *dev);
static int ctem_stop(struct net_device *dev);
static netdev_tx_t ctem_xmit(struct sk_buff *skb, struct net_device *dev);
static void ctem_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *storage);
static struct net_device_stats *ctem_get_stats(struct net_device *dev);

static const struct net_device_ops ctem_netdev_ops = {
    .ndo_open = ctem_open,
    .ndo_stop = ctem_stop,
    .ndo_start_xmit = ctem_xmit,
    .ndo_get_stats64 = ctem_get_stats64,
    .ndo_get_stats = ctem_get_stats,
};

static void ctem_init(struct net_device *dev);
static void ctem_start_udp(struct net_device *dev);
static int ctem_setup_udp(struct net_device *dev, int udp_listen_port, int udp_send_port);
static void ctem_teardown_udp(struct net_device *dev);

static int ctem_packet_reception_thread(void *arg);
static void ctem_parse_frame(struct net_device *dev, unsigned char *buf, int size);

static __exit void ctem_cleanup_module(void);
static __init int ctem_init_module(void);

#endif /* _CAN_TO_ETH_MOD_H */