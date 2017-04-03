/* Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "packets.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/blake2s.h"
#include "crypto/curve25519.h"

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <net/rtnetlink.h>

static int __init mod_init(void)
{
	int ret;

	chacha20poly1305_fpu_init();
	blake2s_fpu_init();
	curve25519_fpu_init();
#ifdef DEBUG
	if (!routing_table_selftest() || !packet_counter_selftest() || !curve25519_selftest() || !chacha20poly1305_selftest() || !blake2s_selftest())
		return -ENOTRECOVERABLE;
#endif
	noise_init();

	ret = ratelimiter_module_init();
	if (ret < 0)
		return ret;

	ret = device_init();
	if (ret < 0)
		goto err;

	pr_info("WireGuard " WIREGUARD_VERSION " loaded. See www.wireguard.io for information.\n");
	pr_info("Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");

	return 0;

err:
	ratelimiter_module_deinit();
	return ret;
}

static void __exit mod_exit(void)
{
	device_uninit();
	ratelimiter_module_deinit();
	pr_debug("WireGuard has been unloaded\n");
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Fast, secure, and modern VPN tunnel");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
MODULE_VERSION(WIREGUARD_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
