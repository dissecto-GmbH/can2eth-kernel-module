// SPDX-License-Identifier: GPL-2.0

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

#define MODULE_NAME "Can2Eth"

#define CTEM_RX_BUFFER_SIZE 1500
#define CTEM_TX_BUFFER_SIZE 1500
#define CTEM_NAPI_WEIGHT 4

#define SEC_TO_NS 1000000000ULL

#define MAGIC_NUMBER 0x43324547 /* C2EG */
#define MAGIC_PACKET 0xc0fe
#define MAGIC_KEEP_ALIVE 0x57a7
#define MAGIC_ERROR 0xfa11

#define NUM_ADDRESSES 10
#define NUM_INTERFACES 2

/*
 * this is the interval between checks for timeouts in the msgbuilder; since it
 * uses usleep_range, a lower and upper limit have to be provided in
 * microseconds.
 */
#define CTEM_MIN_TIMEOUT_CHECK 900
#define CTEM_MAX_TIMEOUT_CHECK 1100

struct ctem_comm_handler;
typedef int(sender_callback_t)(struct ctem_comm_handler *, void *, size_t);

struct ctem_pktbuilder {
	spinlock_t mutex;
	unsigned int last_tx_seqno;
	unsigned pos;
	bool empty;
	struct timespec64 lastflush;
	unsigned int timeout_nsec;
	sender_callback_t *send;
	uint8_t buf[CTEM_TX_BUFFER_SIZE];
};

struct ctem_comm_handler {
	struct socket *udp_socket;
	struct sockaddr **dest_addrs;
	int num_addrs;
	unsigned int last_seqno;
	struct ctem_pktbuilder *pktbuilder;
	struct task_struct *reception_thread;
	struct task_struct *transmission_thread;
};

struct can2eth_pkthdr {
	u32 magic;
	u32 tv_sec;
	u32 tv_nsec;
	u16 seqno;
	u16 size;
};

struct can2eth_can_chunk {
	u32 tv_sec;
	u32 tv_nsec;
	u32 can_id; /* 32 bit CAN_ID + EFF/RTR/ERR flags */
	u8 interface_idx;
	u8 reserved;
	u8 len; /* frame payload length in byte (0 .. 64) */
	u8 flags; /* additional flags for CAN FD */
	u8 data[64] __attribute__((aligned(8)));
} __attribute__((packed));

struct stats_and_keepalive_chunk {
	unsigned int total_frames_relayed;
	unsigned int cpu_free;
	unsigned int spi_busy;
	unsigned int free_heap;
	unsigned int min_heap;
	unsigned int timestamp_diff0;
	unsigned int timestamp_diff1;
	unsigned int free_fifo;
};

struct ctem_priv {
	struct can_priv can;
	struct can_rx_offload offload;
	struct mutex rx_mutex;
	unsigned int if_idx;
};

static char *ip_addrs[NUM_ADDRESSES];
static int num_ip_addrs = 0; /* the actual number of ip address provided */
static int port = 8765;
static unsigned int timeout_ns = 10000000;

module_param_array(ip_addrs, charp, &num_ip_addrs, 0000);
module_param(port, int, S_IRUGO);
module_param(timeout_ns, uint, S_IRUGO);

static struct ctem_comm_handler *ctem_communications;
static struct net_device *ctem_devs[NUM_INTERFACES];

static int internal_msgbuilder_flush(struct ctem_comm_handler *handler)
{
	struct ctem_pktbuilder *pkt_builder = handler->pktbuilder;
	struct timespec64 ts;
	struct can2eth_pkthdr *pkthdr;
	int ret;

	ktime_get_real_ts64(&ts);

	if (pkt_builder->empty) {
		pkt_builder->lastflush = ts;
		return 0;
	}

	pkthdr = (void *)pkt_builder->buf;
	pkthdr->magic = htonl(MAGIC_NUMBER);
	pkthdr->tv_sec = htonl(ts.tv_sec);
	pkthdr->tv_nsec = htonl(ts.tv_nsec);
	pkthdr->seqno = htons(++pkt_builder->last_tx_seqno);
	pkthdr->size = htons((u16)pkt_builder->pos);

	ret = pkt_builder->send(handler, pkt_builder->buf, pkt_builder->pos);
	pkt_builder->empty = true;
	pkt_builder->pos = sizeof(*pkthdr);
	pkt_builder->lastflush = ts;

	return ret;
}

int msgbuilder_flush_if_it_is_time(struct ctem_comm_handler *handler)
{
	struct ctem_pktbuilder *pkt_builder = handler->pktbuilder;
	struct timespec64 now;
	uint64_t now_ns;
	uint64_t lst_ns;
	uint64_t since;
	int ret;

	spin_lock(&pkt_builder->mutex);

	ktime_get_real_ts64(&now);
	now_ns = now.tv_sec * SEC_TO_NS + now.tv_nsec;

	lst_ns = pkt_builder->lastflush.tv_sec * SEC_TO_NS +
		 pkt_builder->lastflush.tv_nsec;
	since = now_ns - lst_ns;

	if (since > pkt_builder->timeout_nsec)
		ret = internal_msgbuilder_flush(handler);

	spin_unlock(&pkt_builder->mutex);

	return ret;
}

static int msgbuilder_enqueue(struct ctem_comm_handler *handler, void *data,
			      u16 len, u16 ctype)
{
	struct ctem_pktbuilder *pkt_builder = handler->pktbuilder;
	int ret;
	u16 chunksize, chunktype;

	spin_lock(&pkt_builder->mutex);

	/*
	 * Checks if there is enough space left in the buffer for the frame
	 * with size len and the two 2 Byte fields chunksize and chunktype
	 */
	if (pkt_builder->pos + len + 4 > CTEM_TX_BUFFER_SIZE) {
		ret = internal_msgbuilder_flush(handler);
		if (ret < 0)
			return ret;
	}

	if (pkt_builder->pos + len + 4 <= CTEM_TX_BUFFER_SIZE) {
		chunksize = htons(len);
		chunktype = htons(ctype);
		memcpy(pkt_builder->buf + pkt_builder->pos, &chunksize,
		       sizeof(chunksize));
		pkt_builder->pos += 2;
		memcpy(pkt_builder->buf + pkt_builder->pos, &chunktype,
		       sizeof(chunksize));
		pkt_builder->pos += 2;
		memcpy(pkt_builder->buf + pkt_builder->pos, data, len);
		pkt_builder->pos += len;
		pkt_builder->empty = false;
	}

	spin_unlock(&pkt_builder->mutex);

	return msgbuilder_flush_if_it_is_time(handler);
}

static int ctem_send_packet(struct ctem_comm_handler *handler, void *data,
			    size_t len)
{
	struct msghdr msg;
	struct kvec iov;
	char *packet_data;
	int ret;
	unsigned int i;

	packet_data = (char *)kmalloc(len * sizeof(char), GFP_KERNEL);
	if (!packet_data) {
		pr_err("%s: Error could not allocate memory for the udp packet.\n",
		       MODULE_NAME);
		return -ENOMEM;
	}

	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	memcpy(packet_data, data, len);

	iov.iov_base = packet_data;
	iov.iov_len = len;

	for (i = 0; i < handler->num_addrs; i++) {
		if (!handler->dest_addrs[i])
			break;

		msg.msg_name = handler->dest_addrs[i];
		msg.msg_namelen = sizeof(struct sockaddr);

		ret = kernel_sendmsg(handler->udp_socket, &msg, &iov, 1,
				     iov.iov_len);
		if (ret < 0) {
			pr_err("%s: Error sending udp frame to address %u.\n",
			       MODULE_NAME, i);
			kfree(packet_data);
			return ret;
		}
	}

	kfree(packet_data);
	return NETDEV_TX_OK;
}

static int ctem_transmission_thread(void *arg)
{
	struct ctem_comm_handler *handler = (struct ctem_comm_handler *)arg;

	pr_debug("%s: start transmission thread\n", MODULE_NAME);

	while (!kthread_should_stop()) {
		usleep_range(CTEM_MIN_TIMEOUT_CHECK, CTEM_MAX_TIMEOUT_CHECK);
		msgbuilder_flush_if_it_is_time(handler);
	}

	pr_debug("%s: stopped transmission thread\n", MODULE_NAME);

	return 0;
}

static int msgbuilder_init(struct ctem_comm_handler *handler)
{
	struct ctem_pktbuilder *pkt_builder;

	handler->pktbuilder = (struct ctem_pktbuilder *)kmalloc(
		sizeof(struct ctem_pktbuilder), GFP_KERNEL);

	if (!handler->pktbuilder)
		return -ENOMEM;

	pkt_builder = handler->pktbuilder;

	pkt_builder->timeout_nsec = timeout_ns;
	pkt_builder->pos = sizeof(struct can2eth_pkthdr);
	pkt_builder->empty = true;
	pkt_builder->send = &ctem_send_packet;

	spin_lock_init(&pkt_builder->mutex);

	handler->transmission_thread = kthread_create(
		ctem_transmission_thread, handler, "ctem_transmission_thread");
	if (IS_ERR(handler->transmission_thread)) {
		pr_err("%s: Error creating Transmission thread\n", MODULE_NAME);
		return PTR_ERR(handler->transmission_thread);
	}

	return 0;
}

static int ctem_parse_magic_chunk(void *buf, u16 chunk_size)
{
	struct can2eth_can_chunk *can_chunk = (struct can2eth_can_chunk *)(buf);
	struct timespec64 ts;
	uint32_t can_id = htonl(can_chunk->can_id);
	uint8_t if_idx = can_chunk->interface_idx;
	uint8_t len = can_chunk->len;
	struct sk_buff *skb;
	struct net_device *dev;
	struct ctem_priv *priv;
	struct can_frame *can_frame;
	struct canfd_frame *canfd_frame;
	int ret;

	if (if_idx < NUM_INTERFACES) {
		dev = ctem_devs[if_idx];
		if (!netif_running(dev)) {
			netdev_err(dev, "%s: %s not running\n", MODULE_NAME,
				   dev->name);
			return -ENETDOWN;
		}
	} else {
		pr_err("%s: Interface %d, index out of range\n", MODULE_NAME,
		       if_idx);
		return -ENODEV;
	}

	priv = netdev_priv(dev);

	ts.tv_sec = htonl(can_chunk->tv_sec);
	ts.tv_nsec = htonl(can_chunk->tv_nsec);

	if (len + offsetof(struct can2eth_can_chunk, data) != chunk_size) {
		netdev_warn(dev,
			    "%s: can chunk size is unexpected (16+%u / %u)\n",
			    MODULE_NAME, len, chunk_size);
		return -EMSGSIZE;
	}

	if (can_chunk->flags) {
		/* handle canfd frames */

		skb = alloc_canfd_skb(dev, &canfd_frame);
		if (!skb) {
			netdev_err(
				dev,
				"%s: Failed to allocate ksb for CANFD frame\n",
				MODULE_NAME);
			return -ENOMEM;
		}

		canfd_frame->can_id = can_id;
		canfd_frame->len = can_chunk->len;
		canfd_frame->flags = can_chunk->flags;
		memcpy(canfd_frame->data, can_chunk->data, canfd_frame->len);
	} else {
		/* handle can frames */
		skb = alloc_can_skb(dev, &can_frame);
		if (!skb) {
			netdev_err(dev,
				   "%s: Failed to allocate ksb for CAN frame\n",
				   MODULE_NAME);
			return -ENOMEM;
		}
		can_frame->can_id = can_id;
		can_frame->len = can_chunk->len;
		memcpy(can_frame->data, can_chunk->data, can_frame->len);
	}

	/* set skb timestamp to timestamp from chunk */
	skb->tstamp = timespec64_to_ktime(ts);

	mutex_lock(&priv->rx_mutex);

	ret = can_rx_offload_queue_tail(&priv->offload, skb);
	can_rx_offload_irq_finish(&priv->offload);

	mutex_unlock(&priv->rx_mutex);

	return ret;
}

static int ctem_parse_frame(void *buf, size_t sz)
{
	struct timespec64 hdr_ts;
	struct can2eth_pkthdr *hdr = (struct can2eth_pkthdr *)buf;
	u16 size = htons(hdr->size);
	u16 chunk_size, chunk_type;
	unsigned chunk_idx;
	int ret;

	if (sz < sizeof(struct can2eth_pkthdr)) {
		pr_err("%s: received datagram was too short to be a can2eth packet.\n",
		       MODULE_NAME);
		return -EMSGSIZE;
	}

	if (htonl(hdr->magic) != MAGIC_NUMBER) {
		pr_err("%s: received datagram does not have can2eth magic number.\n",
		       MODULE_NAME);
		return -EINVAL;
	}

	if (sz < size) {
		pr_err("%s: received datagram is shorter than what declared "
		       "in the can2eth header. Declared were %hu bytes, but only %lu bytes "
		       "were "
		       "received\n",
		       MODULE_NAME, size, sz);
		return -EINVAL;
	}

	if (hdr->seqno != ctem_communications->last_seqno + 1) {
		pr_warn("%s: Jump in sequence numbers detected. Went from %hu to %hu\n",
			MODULE_NAME, ctem_communications->last_seqno,
			hdr->seqno);
	}

	ctem_communications->last_seqno = hdr->seqno;

	hdr_ts.tv_sec = htonl(hdr->tv_sec);
	hdr_ts.tv_nsec = htonl(hdr->tv_nsec);
	buf += sizeof(struct can2eth_pkthdr);
	sz -= sizeof(struct can2eth_pkthdr);

	for (chunk_idx = 0; sz > 4; chunk_idx++) {
		/* read chunk size and type, and advance buf to the actual start of the chunk */
		chunk_size = htons(((u16 *)buf)[0]);
		chunk_type = htons(((u16 *)buf)[1]);
		sz -= 4;
		buf += 4;

		if (sz < chunk_size) {
			pr_err("%s: a chunk in the received datagram is cut short. Tried to read "
			       "%u bytes, but could only find %lu bytes\n",
			       MODULE_NAME, chunk_size, sz);
			return -EINVAL;
		}

		if (chunk_type == MAGIC_PACKET)
			ret = ctem_parse_magic_chunk(buf, chunk_size);
		else
			pr_warn("%s: warning: unknown chunk type 0x%04x.\n",
				MODULE_NAME, chunk_type);

		sz -= chunk_size;
		buf += chunk_size;
	}

	if (sz > 0) {
		pr_err("%s: datagram has %lu leftover bytes.\n", MODULE_NAME,
		       sz);
		return -EMSGSIZE;
	}

	return NET_RX_SUCCESS;
}

static int ctem_reception_thread(void *arg)
{
	struct ctem_comm_handler *handler = (struct ctem_comm_handler *)arg;
	unsigned char *receive_buffer;
	struct msghdr msg;
	struct kvec iov;
	int ret;

	receive_buffer = kmalloc(CTEM_RX_BUFFER_SIZE, GFP_KERNEL);
	if (!receive_buffer) {
		pr_err("%s: Failed to allocate reception buffer\n",
		       MODULE_NAME);
		return -1;
	}

	pr_debug("%s: Started listing\n", MODULE_NAME);

	while (!kthread_should_stop()) {
		memset(&msg, 0, sizeof(struct msghdr));

		iov.iov_base = receive_buffer;
		iov.iov_len = CTEM_RX_BUFFER_SIZE;

		ret = kernel_recvmsg(handler->udp_socket, &msg, &iov, 1,
				     iov.iov_len, MSG_WAITALL);
		if (ret < 0) {
			pr_err("%s: Error while listening to udp socket: %d\n",
			       MODULE_NAME, ret);
		} else {
			ctem_parse_frame(receive_buffer, ret);
			pr_debug("%s: Received %d Bytes.\n", MODULE_NAME, ret);
		}
	}

	kfree(receive_buffer);
	pr_debug("%s: Stopped listing\n", MODULE_NAME);
	return 0;
}

int ctem_setup_udp(struct ctem_comm_handler *handler, int src_port)
{
	struct sockaddr_in *udp_addr;
	struct sockaddr *src_addr;
	int ret;

	udp_addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
	if (!udp_addr) {
		pr_err("Error allocating the address the UDP is listing to\n");
		return -ENOMEM;
	}

	memset(udp_addr, 0, sizeof(struct sockaddr_in));
	udp_addr->sin_family = PF_INET;
	udp_addr->sin_port = htons(port);
	udp_addr->sin_addr.s_addr = INADDR_ANY;
	src_addr = (struct sockaddr *)udp_addr;

	ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP,
			       &handler->udp_socket);
	if (ret) {
		pr_err("%s: Error creating UDP socket: %d\n", MODULE_NAME, ret);
		return ret;
	}

	ret = kernel_bind(handler->udp_socket, src_addr, sizeof(*src_addr));
	if (ret) {
		pr_err("%s: Error binding UDP socket: %d\n", MODULE_NAME, ret);
		sock_release(handler->udp_socket);
		return ret;
	}

	kfree(udp_addr);

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
	struct sockaddr_in *addr;
	u32 ip;
	u16 port = 0;
	int ret;
	int i;

	handler->dest_addrs = kmalloc(sizeof(struct sockaddr *), GFP_KERNEL);
	if (!handler->dest_addrs) {
		pr_err("Could not allocate destination addresses\n");
		return -ENOMEM;
	}

	handler->last_seqno = 0;
	handler->num_addrs = 0;

	/* parse input ip addresses */
	if (!num_addrs) {
		addr = kmalloc(sizeof(struct sockaddr_in), GFP_KERNEL);
		if (!addr) {
			pr_err("Could not allocate ip addr\n");
			return -ENOMEM;
		}

		addr->sin_family = PF_INET;
		addr->sin_port = htons(port);
		addr->sin_addr.s_addr = INADDR_ANY;

		handler->dest_addrs[0] = (struct sockaddr *)addr;

		handler->num_addrs = 1;
	} else {
		for (i = 0; i < num_addrs; i++) {
			ret = parse_ip_port(ip_addrs[i], &ip, &port);
			if (ret) {
				pr_err("Invalid IP/port format: %s\n",
				       ip_addrs[i]);
			} else {
				pr_debug("Parsed IP: %pI4, Port: %u\n", &ip,
					 port);
				addr = kmalloc(sizeof(struct sockaddr_in),
					       GFP_KERNEL);
				if (!addr) {
					pr_err("Could not allocate ip addr\n");
					return -ENOMEM;
				}

				addr->sin_family = PF_INET;
				addr->sin_port = htons(port);
				addr->sin_addr.s_addr = ip;

				handler->dest_addrs[handler->num_addrs] =
					(struct sockaddr *)addr;
				handler->num_addrs++;
			}
		}
	}

	ret = ctem_setup_udp(handler, src_port);
	if (ret)
		return ret;

	ret = msgbuilder_init(handler);
	if (ret)
		return ret;

	handler->reception_thread = kthread_create(
		ctem_reception_thread, handler, "ctem_reception_thread");
	if (IS_ERR(handler->reception_thread)) {
		pr_err("%s: Error creating reception thread\n", MODULE_NAME);
		return PTR_ERR(handler->reception_thread);
	}

	return 0;
}

static int ctem_teardown_communications(struct ctem_comm_handler *handler)
{
	int ret, i;

	if (handler->reception_thread) {
		ret = kthread_stop(handler->reception_thread);
		if (ret < 0) {
			pr_err("%s: Error could not stop reception thread!\n",
			       MODULE_NAME);
			return ret;
		}
	}

	if (handler->transmission_thread) {
		ret = kthread_stop(handler->transmission_thread);
		if (ret < 0) {
			pr_err("%s: Error could not stop transmission thread!\n",
			       MODULE_NAME);
			return ret;
		}
	}

	if (handler->udp_socket)
		sock_release(handler->udp_socket);

	for (i = 0; i < handler->num_addrs; i++) {
		if (handler->dest_addrs[i])
			kfree(handler->dest_addrs[i]);
	}

	return ret;
}

static int ctem_start_communications(struct ctem_comm_handler *handler)
{
	int ret;

	ret = wake_up_process(handler->reception_thread);
	if (ret < 0) {
		printk(KERN_ERR "Failed to start reception thread: %d\n", ret);
		return ret;
	}

	ret = wake_up_process(handler->transmission_thread);
	if (ret < 0) {
		printk(KERN_ERR "Failed to start transmission thread: %d\n",
		       ret);
		return ret;
	}

	return 0;
}

static int ctem_open(struct net_device *dev)
{
	struct ctem_priv *priv = netdev_priv(dev);
	int ret;

	ret = can_rx_offload_add_manual(dev, &priv->offload, CTEM_NAPI_WEIGHT);
	if (ret) {
		close_candev(dev);
		return ret;
	}

	can_rx_offload_enable(&priv->offload);

	priv->can.state = CAN_STATE_ERROR_ACTIVE;

	netif_carrier_on(dev);
	netif_start_queue(dev);

	open_candev(dev);

	netdev_dbg(dev, "%s: Opened %s\n", MODULE_NAME, dev->name);

	return 0;
}

void can_flush_echo_skb(struct net_device *dev)
{
	struct can_priv *priv = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	int i;

	for (i = 0; i < priv->echo_skb_max; i++) {
		if (priv->echo_skb[i]) {
			kfree_skb(priv->echo_skb[i]);
			priv->echo_skb[i] = NULL;
			stats->tx_dropped++;
			stats->tx_aborted_errors++;
		}
	}
}

static int ctem_stop(struct net_device *dev)
{
	struct ctem_priv *priv = netdev_priv(dev);

	netdev_dbg(dev, "%s: Stopped %s\n", MODULE_NAME, dev->name);

	netif_carrier_off(dev);
	netif_stop_queue(dev);

	can_rx_offload_disable(&priv->offload);

	priv->can.state = CAN_STATE_STOPPED;
	can_rx_offload_del(&priv->offload);

	return 0;
}

static netdev_tx_t ctem_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct can2eth_can_chunk frame;
	struct timespec64 ts;
	struct ctem_priv *priv = netdev_priv(dev);
	struct canfd_frame *canfd_frame;
	struct can_frame *can_frame;

	ktime_get_boottime_ts64(&ts);

	memset(&frame, 0, sizeof(struct can2eth_can_chunk));

	if (skb->len > CAN_MTU) {
		/* Handle canfd */
		canfd_frame = (struct canfd_frame *)skb->data;

		frame.can_id = htonl(canfd_frame->can_id);
		frame.len = canfd_frame->len;
		frame.flags = canfd_frame->flags;
		memcpy(frame.data, canfd_frame->data, frame.len);
	} else {
		/* Handle can */
		can_frame = (struct can_frame *)skb->data;

		frame.can_id = htonl(can_frame->can_id);
		frame.len = can_frame->len;
		memcpy(frame.data, can_frame->data, frame.len);
	}

	frame.tv_nsec = htonl((u32)ts.tv_nsec);
	frame.tv_sec = htonl((u32)ts.tv_sec);

	frame.interface_idx = priv->if_idx;

	msgbuilder_enqueue(ctem_communications, &frame,
			   sizeof(frame) - 64 + frame.len, MAGIC_PACKET);

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

static int ctem_init(struct net_device *dev, size_t if_idx)
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

	/* Initialize priv field */
	priv = netdev_priv(dev);
	memset(priv, 0, sizeof(struct ctem_priv));
	priv->can.bittiming.bitrate = 50000;
	mutex_init(&priv->rx_mutex);
	priv->if_idx = if_idx;

	return 0;
}

static __exit void ctem_cleanup_module(void)
{
	unsigned int i;

	pr_debug("%s: Starting cleanup of CAN to Eth Driver\n", MODULE_NAME);

	for (i = 0; i < NUM_INTERFACES; i++) {
		if (ctem_devs[i]) {
			unregister_candev(ctem_devs[i]);
			free_candev(ctem_devs[i]);
		}
	}

	ctem_teardown_communications(ctem_communications);

	kfree(ctem_communications);
}

static __init int ctem_init_module(void)
{
	unsigned int allocate_idx;
	unsigned int registered_idx;
	int ret = -ENOMEM;

	pr_debug("%s: Registering CAN to Eth Driver\n", MODULE_NAME);

	ctem_communications = (struct ctem_comm_handler *)kmalloc(
		sizeof(struct ctem_comm_handler), GFP_KERNEL);
	if (!ctem_communications)
		return -ENOMEM;

	/* Initialize can interfaces */
	for (allocate_idx = 0; allocate_idx < NUM_INTERFACES; allocate_idx++) {
		ctem_devs[allocate_idx] =
			alloc_candev(sizeof(struct ctem_priv), 0);

		if (!ctem_devs[allocate_idx])
			goto out_free_previous_devs;

		ret = ctem_init(ctem_devs[allocate_idx], allocate_idx);
		if (ret) {
			netdev_err(ctem_devs[allocate_idx],
				   "%s: Failed to initialize interface %u\n",
				   MODULE_NAME, allocate_idx);
			free_candev(ctem_devs[allocate_idx]);
			goto out_free_previous_devs;
		}
	}

	ret = ctem_setup_communications(ctem_communications, port, ip_addrs,
					num_ip_addrs);
	if (ret)
		goto out_teardown_communications;

	/* Register can interfaces */
	for (registered_idx = 0; registered_idx < NUM_INTERFACES;
	     registered_idx++) {
		ret = register_candev(ctem_devs[registered_idx]);
		if (ret) {
			netdev_err(
				ctem_devs[registered_idx],
				"%s: Failed to register the can network device\n",
				MODULE_NAME);
			goto out_unregister_devs;
		}
	}

	ctem_start_communications(ctem_communications);

	return 0;

out_unregister_devs:
	while (registered_idx-- > 0) {
		unregister_candev(ctem_devs[registered_idx]);
	}
out_teardown_communications:
	ctem_teardown_communications(ctem_communications);
out_free_previous_devs:
	while (allocate_idx-- > 0) {
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
