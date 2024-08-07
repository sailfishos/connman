/*
 *  ConnMan VPN daemon
 *
 *  Copyright (C) 2019  Daniel Wagner. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/log.h>
#include <connman/task.h>
#include <connman/ipconfig.h>
#include <connman/inet.h>
#include <connman/dbus.h>
#include <connman/setting.h>
#include <connman/vpn-dbus.h>

#include "../vpn-provider.h"
#include "../vpn.h"

#include "vpn.h"
#include "wireguard.h"

#define DNS_RERESOLVE_TIMEOUT 20
#define DNS_RERESOLVE_ERROR_LIMIT 5
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

struct wireguard_info {
	struct vpn_provider *provider;
	struct wg_device device;
	struct wg_peer peer;
	char *endpoint_fqdn;
	char *port;
	int reresolve_id;
};

struct sockaddr_u {
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
};

struct {
	const char	*opt;
	bool		save;
} wg_options[] = {
	{"WireGuard.Address", true},
	{"WireGuard.ListenPort", true},
	{"WireGuard.DNS", true},
	{"WireGuard.PrivateKey", true}, // TODO set false after agent support
	{"WireGuard.PresharedKey", true}, // TODO set false after agent support
	{"WireGuard.PublicKey", true},
	{"WireGuard.AllowedIPs", true},
	{"WireGuard.EndpointPort", true},
	{"WireGuard.PersistentKeepalive", true}
};

static int parse_key(const char *str, wg_key key)
{
	unsigned char *buf;
	size_t len;

	buf = g_base64_decode(str, &len);

	if (len != 32) {
		g_free(buf);
		return -EINVAL;
	}

	memcpy(key, buf, 32);

	g_free(buf);
	return 0;
}

static int parse_allowed_ips(const char *allowed_ips, wg_peer *peer)
{
	struct wg_allowedip *curaip, *allowedip;
	char buf[INET6_ADDRSTRLEN];
	char **tokens, **toks;
	char *send;
	int i;

	curaip = NULL;
	tokens = g_strsplit(allowed_ips, ", ", -1);
	for (i = 0; tokens[i]; i++) {
		toks = g_strsplit(tokens[i], "/", -1);
		if (g_strv_length(toks) != 2) {
			DBG("Ignore AllowedIPs value %s", tokens[i]);
			g_strfreev(toks);
			continue;
		}

		allowedip = g_malloc0(sizeof(*allowedip));

		if (inet_pton(AF_INET, toks[0], buf) == 1) {
			allowedip->family = AF_INET;
			memcpy(&allowedip->ip4, buf, sizeof(allowedip->ip4));
		} else if (inet_pton(AF_INET6, toks[0], buf) == 1) {
			allowedip->family = AF_INET6;
			memcpy(&allowedip->ip6, buf, sizeof(allowedip->ip6));
		} else {
			DBG("Ignore AllowedIPs value %s", tokens[i]);
			g_free(allowedip);
			g_strfreev(toks);
			continue;
		}

		allowedip->cidr = g_ascii_strtoull(toks[1], &send, 10);

		if (!curaip)
			peer->first_allowedip = allowedip;
		else
			curaip->next_allowedip = allowedip;

		curaip = allowedip;
	}

	peer->last_allowedip = curaip;
	g_strfreev(tokens);

	return 0;
}

static int parse_endpoint(const char *host, const char *port, struct sockaddr_u *addr)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sk;
	int err;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	err = getaddrinfo(host, port, &hints, &result);
	if (err < 0) {
		DBG("Failed to resolve host address: %s", gai_strerror(err));
		return -EINVAL;
	}

	for (rp = result; rp; rp = rp->ai_next) {
		sk = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sk < 0)
			continue;
		if (connect(sk, rp->ai_addr, rp->ai_addrlen) != -1) {
			/* success */
			close(sk);
			break;
		}

		close(sk);
	}

	if (!rp) {
		freeaddrinfo(result);
		return -EINVAL;
	}

	memcpy(addr, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(result);

	return 0;
}

static int parse_address(const char *address, const char *gateway,
		struct connman_ipaddress **ipaddress)
{
	char buf[INET6_ADDRSTRLEN];
	unsigned char prefixlen;
	char **tokens;
	char *end, *netmask;
	int err;

	tokens = g_strsplit(address, "/", -1);
	if (g_strv_length(tokens) != 2) {
		g_strfreev(tokens);
		return -EINVAL;
	}

	prefixlen = g_ascii_strtoull(tokens[1], &end, 10);

	if (inet_pton(AF_INET, tokens[0], buf) == 1) {
		netmask = g_strdup_printf("%d.%d.%d.%d",
				((0xffffffff << (32 - prefixlen)) >> 24) & 0xff,
				((0xffffffff << (32 - prefixlen)) >> 16) & 0xff,
				((0xffffffff << (32 - prefixlen)) >> 8) & 0xff,
				((0xffffffff << (32 - prefixlen)) >> 0) & 0xff);

		*ipaddress = connman_ipaddress_alloc(AF_INET);
		err = connman_ipaddress_set_ipv4(*ipaddress, tokens[0],
						netmask, gateway);
		g_free(netmask);
	} else if (inet_pton(AF_INET6, tokens[0], buf) == 1) {
		*ipaddress = connman_ipaddress_alloc(AF_INET6);
		err = connman_ipaddress_set_ipv6(*ipaddress, tokens[0],
						prefixlen, gateway);
	} else {
		DBG("Invalid Wireguard.Address value");
		err = -EINVAL;
	}

	connman_ipaddress_set_p2p(*ipaddress, true);

	g_strfreev(tokens);
	if (err)
		connman_ipaddress_free(*ipaddress);

	return err;
}

struct ifname_data {
	char *ifname;
	bool found;
};

static void ifname_check_cb(int index, void *user_data)
{
	struct ifname_data *data = (struct ifname_data *)user_data;
	char *ifname;

	ifname = connman_inet_ifname(index);

	if (!g_strcmp0(ifname, data->ifname))
		data->found = true;
}

static char *get_ifname(void)
{
	struct ifname_data data;
	int i;

	for (i = 0; i < 256; i++) {
		data.ifname = g_strdup_printf("wg%d", i);
		data.found = false;
		vpn_ipconfig_foreach(ifname_check_cb, &data);

		if (!data.found)
			return data.ifname;

		g_free(data.ifname);
	}

	return NULL;
}

static bool sockaddr_cmp_addr(struct sockaddr_u *a, struct sockaddr_u *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return false;

	if (a->sa.sa_family == AF_INET)
		return !memcmp(&a->sin, &b->sin, sizeof(struct sockaddr_in));
	else if (a->sa.sa_family == AF_INET6)
		return !memcmp(a->sin6.sin6_addr.s6_addr,
				b->sin6.sin6_addr.s6_addr,
				sizeof(a->sin6.sin6_addr.s6_addr));

	return false;
}

static void run_dns_reresolve(struct wireguard_info *info);

static gboolean wg_dns_reresolve_cb(gpointer user_data)
{
	struct wireguard_info *info = user_data;
	struct sockaddr_u addr;
	int err;

	if (vpn_provider_get_connection_errors(info->provider) >=
						DNS_RERESOLVE_ERROR_LIMIT) {
		connman_warn("reresolve error limit reached");
		vpn_died(NULL, -ENONET, info->provider);
		return G_SOURCE_REMOVE;
	}

	/* If this fails after being connected it means configuration error
	 * that results in connection errors. */
	err = parse_endpoint(info->endpoint_fqdn,
			info->port, &addr);
	if (err) {
		if (info->provider)
			vpn_provider_add_error(info->provider,
					VPN_PROVIDER_ERROR_CONNECT_FAILED);
		run_dns_reresolve(info);
		return G_SOURCE_REMOVE;
	}

	if (sockaddr_cmp_addr(&addr,
			(struct sockaddr_u *)&info->peer.endpoint.addr)) {
		run_dns_reresolve(info);
		return G_SOURCE_REMOVE;
	}

	if (addr.sa.sa_family == AF_INET)
		memcpy(&info->peer.endpoint.addr, &addr.sin,
			sizeof(info->peer.endpoint.addr4));
	else
		memcpy(&info->peer.endpoint.addr, &addr.sin6,
			sizeof(info->peer.endpoint.addr6));

	DBG("Endpoint address has changed, udpate WireGuard device");
	err = wg_set_device(&info->device);
	if (err)
		DBG("Failed to update Endpoint address for WireGuard device %s",
			info->device.name);

	run_dns_reresolve(info);
	return G_SOURCE_REMOVE;
}

static void run_dns_reresolve(struct wireguard_info *info)
{
	if (info->reresolve_id)
		g_source_remove(info->reresolve_id);

	info->reresolve_id = g_timeout_add_seconds(DNS_RERESOLVE_TIMEOUT,
						wg_dns_reresolve_cb, info);
}

static int wg_connect(struct vpn_provider *provider,
			struct connman_task *task, const char *if_name,
			vpn_provider_connect_cb_t cb,
			const char *dbus_sender, void *user_data)
{
	struct connman_ipaddress *ipaddress = NULL;
	struct wireguard_info *info;
	const char *option, *gateway;
	char *ifname;
	int err = -EINVAL;

	info = g_malloc0(sizeof(struct wireguard_info));
	info->peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS;
	info->device.flags = WGDEVICE_HAS_PRIVATE_KEY;
	info->device.first_peer = &info->peer;
	info->device.last_peer = &info->peer;
	info->provider = vpn_provider_ref(provider);

	DBG("");

	vpn_provider_set_plugin_data(provider, info);
	vpn_provider_set_auth_error_limit(provider, 1);

	option = vpn_provider_get_string(provider, "WireGuard.ListenPort");
	if (option) {
		char *end;
		info->device.listen_port = g_ascii_strtoull(option, &end, 10);
		info->device.flags |= WGDEVICE_HAS_LISTEN_PORT;
	}

	option = vpn_provider_get_string(provider, "WireGuard.DNS");
	if (option) {
		err = vpn_provider_set_nameservers(provider, option);
		if (err) {
			DBG("Cannot set nameservers %s", option);
			goto error;
		}
	}

	option = vpn_provider_get_string(provider, "WireGuard.PrivateKey");
	if (!option) {
		DBG("WireGuard.PrivateKey is missing");
		goto error;
	}
	err = parse_key(option, info->device.private_key);
	if (err) {
		DBG("Failed to parse private key");
		goto error;
	}

	option = vpn_provider_get_string(provider, "WireGuard.PublicKey");
	if (!option) {
		DBG("WireGuard.PublicKey is missing");
		goto error;
	}
	err = parse_key(option, info->peer.public_key);
	if (err) {
		DBG("Failed to parse public key");
		goto error;
	}

	option = vpn_provider_get_string(provider, "WireGuard.PresharedKey");
	if (option) {
		info->peer.flags |= WGPEER_HAS_PRESHARED_KEY;
		err = parse_key(option, info->peer.preshared_key);
		if (err) {
			DBG("Failed to parse pre-shared key");
			goto error;
		}
	}

	option = vpn_provider_get_string(provider, "WireGuard.AllowedIPs");
	if (!option) {
		DBG("WireGuard.AllowedIPs is missing");
		goto error;
	}
	err = parse_allowed_ips(option, &info->peer);
	if (err) {
		DBG("Failed to parse allowed IPs %s", option);
		goto error;
	}

	option = vpn_provider_get_string(provider,
					"WireGuard.PersistentKeepalive");
	if (option) {
		char *end;
		info->peer.persistent_keepalive_interval =
			g_ascii_strtoull(option, &end, 10);
		info->peer.flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
	}

	option = vpn_provider_get_string(provider, "WireGuard.EndpointPort");
	if (!option)
		option = "51820";

	gateway = vpn_provider_get_string(provider, "Host");
	err = parse_endpoint(gateway, option,
			(struct sockaddr_u *)&info->peer.endpoint.addr);
	if (err) {
		DBG("Failed to parse endpoint %s:%s", gateway, option);
		goto error;
	}

	info->endpoint_fqdn = g_strdup(gateway);
	info->port = g_strdup(option);

	option = vpn_provider_get_string(provider, "WireGuard.Address");
	if (!option) {
		DBG("Missing WireGuard.Address configuration");
		goto error;
	}
	err = parse_address(option, gateway, &ipaddress);
	if (err) {
		DBG("Failed to parse address %s gateway %s", option, gateway);
		goto error;
	}

	ifname = get_ifname();
	if (!ifname) {
		DBG("Failed to find an usable device name");
		err = -ENOENT;
		goto done;
	}
	stpncpy(info->device.name, ifname, sizeof(info->device.name) - 1);
	g_free(ifname);

	err = wg_add_device(info->device.name);
	if (err) {
		DBG("Failed to creating WireGuard device %s", info->device.name);
		goto done;
	}

	err = wg_set_device(&info->device);
	if (err) {
		DBG("Failed to configure WireGuard device %s", info->device.name);
		wg_del_device(info->device.name);
	}

	vpn_set_ifname(provider, info->device.name);
	if (ipaddress)
		vpn_provider_set_ipaddress(provider, ipaddress);

done:
	if (cb)
		cb(provider, user_data, -err);

	connman_ipaddress_free(ipaddress);

	if (!err)
		run_dns_reresolve(info);

	return err;

error:
	/* 
	 * TODO: add own category for parameter errors. This is to avoid
	 * looping when parameters are incorrect and VPN stays in failed
	 * state.
	 */
	vpn_provider_add_error(provider, VPN_PROVIDER_ERROR_LOGIN_FAILED);
	err = -ECONNABORTED;
	goto done;
}

static void wg_disconnect(struct vpn_provider *provider)
{
	struct wireguard_info *info;
	int exit_code;

	DBG("");

	info = vpn_provider_get_plugin_data(provider);
	if (!info)
		return;

	if (info->reresolve_id > 0)
		g_source_remove(info->reresolve_id);

	vpn_provider_set_plugin_data(provider, NULL);

	vpn_provider_set_state(provider, VPN_PROVIDER_STATE_DISCONNECT);

	exit_code = wg_del_device(info->device.name);

	vpn_provider_unref(info->provider);
	g_free(info->endpoint_fqdn);
	g_free(info->port);
	g_free(info);

	DBG("exiting with %d", exit_code);

	/* No task for no daemon VPN - use VPN died with no task. */
	vpn_died(NULL, exit_code, provider);
}

static int wg_error_code(struct vpn_provider *provider, int exit_code)
{
	DBG("exit_code %d", exit_code);

	switch (exit_code) {
	/* Failed to parse configuration -> wg_del_device() has no to delete */
	case -ENODEV:
		return 0;
	default:
		return exit_code;
	}
}

static int wg_save(struct vpn_provider *provider, GKeyFile *keyfile)
{
	const char *option;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(wg_options); i++) {
		if (!wg_options[i].save)
			continue;

		option = vpn_provider_get_string(provider, wg_options[i].opt);
		if (!option)
			continue;

		g_key_file_set_string(keyfile,
					vpn_provider_get_save_group(provider),
					wg_options[i].opt, option);
	}

	return 0;
}

static struct vpn_driver vpn_driver = {
	.flags		= VPN_FLAG_NO_TUN | VPN_FLAG_NO_DAEMON,
	.connect	= wg_connect,
	.disconnect	= wg_disconnect,
	.save		= wg_save,
	.error_code	= wg_error_code
};

static int wg_init(void)
{
	return vpn_register("wireguard", &vpn_driver, NULL);
}

static void wg_exit(void)
{
	vpn_unregister("wireguard");
}

CONNMAN_PLUGIN_DEFINE(wireguard, "WireGuard VPN plugin", VERSION,
	CONNMAN_PLUGIN_PRIORITY_DEFAULT, wg_init, wg_exit)
