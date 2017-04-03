/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#ifndef PACKETS_H
#define PACKETS_H

#include "noise.h"
#include "messages.h"
#include "socket.h"

#include <linux/types.h>

struct wireguard_device;
struct wireguard_peer;
struct sk_buff;

struct packet_cb {
	struct noise_keypair *keypair;
	u64 nonce;
	atomic_t state;
	u8 ds;
};
#define PACKET_CB(skb) ((struct packet_cb *)skb->cb)
enum packet_state { PACKET_ENQUEUED, PACKET_KEYPAIRING, PACKET_KEYPAIRED, PACKET_CRYPTING, PACKET_CRYPTED, PACKET_XMITTING };

/* receive.c */
void packet_receive(struct wireguard_device *wg, struct sk_buff *skb);
void packet_decrypt(struct work_struct *work);
void packet_process_queued_handshake_packets(struct work_struct *work);

/* send.c */
void packet_send_queue(struct wireguard_peer *peer);
void packet_encrypt(struct work_struct *work);
void packet_send_keepalive(struct wireguard_peer *peer);
void packet_queue_handshake_initiation(struct wireguard_peer *peer);
void packet_send_queued_handshakes(struct work_struct *work);
void packet_send_handshake_response(struct wireguard_peer *peer);
void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index);

static inline void skb_reset(struct sk_buff *skb)
{
	skb_scrub_packet(skb, true);
	memset(&skb->headers_start, 0, offsetof(struct sk_buff, headers_end) - offsetof(struct sk_buff, headers_start));
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
	skb_reset_tc(skb);
#endif
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);
	skb_reset_inner_headers(skb);
}

#ifdef DEBUG
bool packet_counter_selftest(void);
#endif

#endif
