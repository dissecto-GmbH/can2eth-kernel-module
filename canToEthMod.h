#ifndef _CAN_TO_ETH_MOD_H
#define _CAN_TO_ETH_MOD_H

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

#define MODULE_NAME "CanToEth"
#define CTEM_RX_BUFFER_SIZE 2000
#define CTEM_TX_BUFFER_SIZE 1000
#define CTEM_NAPI_WEIGHT 4

static char *udp_dest_ip_str;
static int udp_dest_port = 8765;
static int udp_src_port = 8765;
static uint32_t ctx_timeout_ns = 10000000;

extern struct net_device *ctem_dev;

module_param(udp_dest_ip_str, charp, S_IRUGO);
module_param(udp_dest_port, int, S_IRUGO);
module_param(udp_src_port, int, S_IRUGO);
module_param(ctx_timeout_ns, uint, S_IRUGO);

typedef struct stats_and_keepalive_chunk
{
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

typedef struct msgbuilder_pktbuilder
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

int msgbuilder_init(struct net_device *dev);
void msgbuilder_start(struct net_device *dev);
int msgbuilder_flush_if_it_is_time(struct net_device *dev);
int msgbuilder_enqueue(struct net_device *dev, void *data, uint16_t len, uint16_t ctype);
static void msgbuilder_teardown(struct net_device *dev);

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

static const struct can_bittiming_const ctem_can_fd_bit_timing_max = {
    .name = "ctem_can_fd",
    .tseg1_min = 2,
    .tseg1_max = 190,
    .tseg2_min = 1,
    .tseg2_max = 63,
    .sjw_max = 31,
    .brp_min = 1,
    .brp_max = 8,
    .brp_inc = 1,
};

struct ctem_priv
{
    /* Apparently this must be the first member when using alloc_candev() */
    struct can_priv can;
    struct can_rx_offload offload;
    struct rtnl_link_stats64 *stats;
    struct net_device *dev;
    struct socket *udp_socket;
    struct sockaddr *udp_addr_src; // socket is listing to this
    struct sockaddr *udp_addr_dst; // sending packets here
    pktbuilder_t *pkt_builder;
    struct task_struct *transmission_thread;
    struct task_struct *reception_thread;
};

static const struct ethtool_ops ctem_ethtool_ops = {
    .get_ts_info = ethtool_op_get_ts_info,
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

static int ctem_init(struct net_device *dev);
static void ctem_free_priv(struct ctem_priv *priv);
static void ctem_start_udp(struct net_device *dev);
static int ctem_setup_udp(struct net_device *dev, u32 dest_addr, int dest_port, int src_port);
static void ctem_teardown_udp(struct net_device *dev);

static int ctem_packet_reception_thread(void *arg);
static int ctem_parse_frame(struct net_device *dev, void *buf, size_t size);

static int ctem_packet_transmission_thread(void *arg);
static int ctem_send_packet(struct net_device *dev, void *data, size_t size);

static __exit void ctem_cleanup_module(void);
static __init int ctem_init_module(void);

#endif /* _CAN_TO_ETH_MOD_H */