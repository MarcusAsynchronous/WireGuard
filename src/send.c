/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "packets.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>

static void packet_send_handshake_initiation(struct wireguard_peer *peer)
{
	struct message_handshake_initiation packet;

	down_write(&peer->handshake.lock);
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT)) {
		up_write(&peer->handshake.lock);
		return; /* This function is rate limited. */
	}
	peer->last_sent_handshake = get_jiffies_64();
	up_write(&peer->handshake.lock);

	net_dbg_ratelimited("Sending handshake initiation to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);

	if (noise_handshake_create_initiation(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		timers_any_authenticated_packet_traversal(peer);
		socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_initiation), HANDSHAKE_DSCP);
		timers_handshake_initiated(peer);
	}
}

void packet_send_queued_handshakes(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, transmit_handshake_work);
	packet_send_handshake_initiation(peer);
	peer_put(peer);
}

void packet_queue_handshake_initiation(struct wireguard_peer *peer)
{
	/* First checking the timestamp here is just an optimization; it will
	 * be caught while properly locked inside the actual work queue. */
	if (!time_is_before_jiffies64(peer->last_sent_handshake + REKEY_TIMEOUT))
		return;

	peer = peer_rcu_get(peer);
	if (unlikely(!peer))
		return;

	/* Queues up calling packet_send_queued_handshakes(peer), where we do a peer_put(peer) after: */
	if (!queue_work(peer->device->workqueue, &peer->transmit_handshake_work))
		peer_put(peer); /* If the work was already queued, we want to drop the extra reference */
}

void packet_send_handshake_response(struct wireguard_peer *peer)
{
	struct message_handshake_response packet;

	net_dbg_ratelimited("Sending handshake response to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
	peer->last_sent_handshake = get_jiffies_64();

	if (noise_handshake_create_response(&packet, &peer->handshake)) {
		cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (noise_handshake_begin_session(&peer->handshake, &peer->keypairs, false)) {
			timers_ephemeral_key_created(peer);
			timers_any_authenticated_packet_traversal(peer);
			socket_send_buffer_to_peer(peer, &packet, sizeof(struct message_handshake_response), HANDSHAKE_DSCP);
		}
	}
}

void packet_send_handshake_cookie(struct wireguard_device *wg, struct sk_buff *initiating_skb, __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("Sending cookie response for denied handshake message for %pISpfsc\n", initiating_skb);
	cookie_message_create(&packet, initiating_skb, sender_index, &wg->cookie_checker);
	socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet, sizeof(packet));
}

static inline void keep_key_fresh(struct wireguard_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	rcu_read_lock_bh();
	keypair = rcu_dereference(peer->keypairs.current_keypair);
	if (likely(keypair && keypair->sending.is_valid) &&
	   (unlikely(atomic64_read(&keypair->sending.counter.counter) > REKEY_AFTER_MESSAGES) ||
	   (keypair->i_am_the_initiator && unlikely(time_is_before_eq_jiffies64(keypair->sending.birthdate + REKEY_AFTER_TIME)))))
		send = true;
	rcu_read_unlock_bh();

	if (send)
		packet_queue_handshake_initiation(peer);
}

void packet_send_keepalive(struct wireguard_peer *peer)
{
	struct sk_buff *skb;
	if (!skb_queue_len(&peer->tx_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH, GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = netdev_pub(peer->device);
		skb_queue_tail(&peer->tx_packet_queue, skb);
		net_dbg_ratelimited("Sending keepalive packet to peer %Lu (%pISpfsc)\n", peer->internal_id, &peer->endpoint.addr);
	}
	packet_send_queue(peer);
}

static inline unsigned int skb_padding(struct sk_buff *skb)
{
	/* We do this modulo business with the MTU, just in case the networking layer
	 * gives us a packet that's bigger than the MTU. Now that we support GSO, this
	 * shouldn't be a real problem, and this can likely be removed. But, caution! */
	unsigned int last_unit = skb->len % skb->dev->mtu;
	unsigned int padded_size = (last_unit + MESSAGE_PADDING_MULTIPLE - 1) & ~(MESSAGE_PADDING_MULTIPLE - 1);
	if (padded_size > skb->dev->mtu)
		padded_size = skb->dev->mtu;
	return padded_size - last_unit;
}

static inline bool skb_encrypt(struct sk_buff *skb, bool have_simd)
{
	struct scatterlist *sg;
	struct message_data *header;
	unsigned int padding_len, plaintext_len, trailer_len;
	int num_frags;
	struct sk_buff *trailer;

	/* Store the ds bit in the cb */
	PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0 /* No outer TOS: no leak. TODO: should we use flowi->tos as outer? */, ip_hdr(skb), skb);

	/* Calculate lengths */
	padding_len = skb_padding(skb);
	trailer_len = padding_len + noise_encrypted_len(0);
	plaintext_len = skb->len + padding_len;

	/* Expand data section to have room for padding and auth tag */
	num_frags = skb_cow_data(skb, trailer_len, &trailer);
	if (unlikely(num_frags < 0 || num_frags > 128))
		return false;

	/* Set the padding to zeros, and make sure it and the auth tag are part of the skb */
	memset(skb_tail_pointer(trailer), 0, padding_len);

	/* Expand head section to have room for our header and the network stack's headers. */
	if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0))
		return false;

	/* We have to remember to add the checksum to the innerpacket, in case the receiver forwards it. */
	if (likely(!skb_checksum_setup(skb, true)))
		skb_checksum_help(skb);

	/* Only after checksumming can we safely add on the padding at the end and the header. */
	header = (struct message_data *)skb_push(skb, sizeof(struct message_data));
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = PACKET_CB(skb)->keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	pskb_put(skb, trailer, trailer_len);

	/* Now we can encrypt the scattergather segments */
	sg = __builtin_alloca(num_frags * sizeof(struct scatterlist)); /* bounded to 128 */
	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, sizeof(struct message_data), noise_encrypted_len(plaintext_len)) <= 0)
		return false;
	return chacha20poly1305_encrypt_sg(sg, sg, plaintext_len, NULL, 0, PACKET_CB(skb)->nonce, PACKET_CB(skb)->keypair->sending.key, have_simd);
}

void packet_encrypt(struct work_struct *work)
{
	struct wireguard_peer *peer = container_of(work, struct wireguard_peer, encrypt_packet_work);
	struct sk_buff *skb, *tmp;
	bool have_simd;

	if (unlikely(!peer_rcu_get(peer)))
		return;

	spin_lock_bh(&peer->tx_packet_queue.lock);
	have_simd = chacha20poly1305_init_simd();
	skb_queue_walk_safe(&peer->tx_packet_queue, skb, tmp) {
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, PACKET_KEYPAIRED, PACKET_CRYPTING) != PACKET_KEYPAIRED)
			continue;
		if (unlikely(!skb_encrypt(skb, have_simd))) {
			noise_keypair_put(PACKET_CB(skb)->keypair);
			__skb_unlink(skb, &peer->tx_packet_queue);
			kfree_skb(skb);
			peer_put(peer);
			continue;
		}
		skb_reset(skb);
		noise_keypair_put(PACKET_CB(skb)->keypair);
		atomic_set(&PACKET_CB(skb)->state, PACKET_CRYPTED);
	}
	chacha20poly1305_deinit_simd(have_simd);
	spin_unlock_bh(&peer->tx_packet_queue.lock);

	spin_lock_bh(&peer->tx_packet_queue.lock);
	skb_queue_walk_safe(&peer->tx_packet_queue, skb, tmp) {
		bool is_keepalive;
		enum packet_state prev_state = atomic_cmpxchg(&PACKET_CB(skb)->state, PACKET_CRYPTED, PACKET_XMITTING);
		if (prev_state == PACKET_XMITTING)
			continue;
		else if (prev_state != PACKET_CRYPTED)
			break;
		__skb_unlink(skb, &peer->tx_packet_queue);
		timers_any_authenticated_packet_traversal(peer);
		is_keepalive = skb->len == message_data_len(0);

		if (likely(!socket_send_skb_to_peer(peer, skb, PACKET_CB(skb)->ds) && !is_keepalive))
			timers_data_sent(peer);
		keep_key_fresh(peer);
		peer_put(peer);
	}
	spin_unlock_bh(&peer->tx_packet_queue.lock);
	peer_put(peer);
}

static inline bool get_encryption_nonce(u64 *nonce, struct noise_symmetric_key *key)
{
	if (unlikely(!key))
		return false;

	if (unlikely(!key->is_valid || time_is_before_eq_jiffies64(key->birthdate + REJECT_AFTER_TIME))) {
		key->is_valid = false;
		return false;
	}

	*nonce = atomic64_inc_return(&key->counter.counter) - 1;
	if (*nonce >= REJECT_AFTER_MESSAGES) {
		key->is_valid = false;
		return false;
	}

	return true;
}

void packet_send_queue(struct wireguard_peer *peer)
{
	struct sk_buff *skb;

	spin_lock_bh(&peer->tx_packet_queue.lock);
	skb_queue_walk(&peer->tx_packet_queue, skb) {
		if (atomic_cmpxchg(&PACKET_CB(skb)->state, PACKET_ENQUEUED, PACKET_KEYPAIRING) != PACKET_ENQUEUED)
			continue;

		rcu_read_lock_bh();
		PACKET_CB(skb)->keypair = noise_keypair_get(rcu_dereference(peer->keypairs.current_keypair));
		if (unlikely(!PACKET_CB(skb)->keypair)) {
			rcu_read_unlock_bh();
			packet_queue_handshake_initiation(peer);
			goto err;
		}
		rcu_read_unlock_bh();

		if (unlikely(!peer_rcu_get(peer)))
			goto err_keypair;
		if (unlikely(!get_encryption_nonce(&PACKET_CB(skb)->nonce, &PACKET_CB(skb)->keypair->sending)))
			goto err_keypair_peer;

		atomic_set(&PACKET_CB(skb)->state, PACKET_KEYPAIRED);
		/* TODO: If this function returns false, it means the work is already on the queue, but it could
		 * be about to exit, in which case, the packet doesn't get sent. What to do? */
		queue_work_on(smp_processor_id(), peer->device->parallel_encrypt, &peer->encrypt_packet_work);
	}

	goto out;

err_keypair_peer:
	peer_put(peer);
err_keypair:
	noise_keypair_put(PACKET_CB(skb)->keypair);
err:
	atomic_set(&PACKET_CB(skb)->state, PACKET_ENQUEUED);
out:
	spin_unlock_bh(&peer->tx_packet_queue.lock);
}
