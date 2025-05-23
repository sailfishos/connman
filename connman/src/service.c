/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2014-2020  Jolla Ltd.
 *  Copyright (C) 2020-2021  Open Mobile Platform LLC.
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <gdbus.h>
#include <ctype.h>
#include <stdint.h>

#include <gutil_misc.h>

#include <connman/storage.h>
#include <connman/setting.h>
#include <connman/agent.h>
#include <connman/provision.h>
#include <connman/wakeup_timer.h>

#include "src/shared/util.h"

#include "connman.h"

#define CONNECT_TIMEOUT		120

#define CONNECT_RETRY_TIMEOUT_STEP	5
#define CONNECT_RETRY_TIMEOUT_MAX	1800

// Maximum time between failed online checks is ONLINE_CHECK_RETRY_COUNT^2 seconds
#define ONLINE_CHECK_RETRY_COUNT 12

#define VPN_AUTOCONNECT_TIMEOUT_DEFAULT 1
#define VPN_AUTOCONNECT_TIMEOUT_STEP 30
#define VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD 270

/* (Some) property names */
#define PROP_ACCESS                     "Access"
#define PROP_DEFAULT_ACCESS             "DefaultAccess"
#define PROP_AVAILABLE                  "Available"
#define PROP_SAVED                      "Saved"
#define PROP_PASSPHRASE                 "Passphrase"
#define PROP_IDENTITY                   "Identity"
#define PROP_EAP                        "EAP"
#define PROP_PHASE2                     "Phase2"
#define PROP_NAME                       "Name"
#define PROP_SSID                       "SSID"
#define PROP_CA_CERT                    "CACert"
#define PROP_CA_CERT_FILE               "CACertFile"
#define PROP_DOMAIN_SUFFIX_MATCH        "DomainSuffixMatch"
#define PROP_CLIENT_CERT                "ClientCert"
#define PROP_CLIENT_CERT_FILE           "ClientCertFile"
#define PROP_PRIVATE_KEY                "PrivateKey"
#define PROP_PRIVATE_KEY_FILE           "PrivateKeyFile"
#define PROP_PRIVATE_KEY_PASSPHRASE     "PrivateKeyPassphrase"
#define PROP_ANONYMOUS_IDENTITY         "AnonymousIdentity"

/* Get/set properties */
#define GET_ACCESS_ACCESS               CONNMAN_ACCESS_ALLOW
#define SET_ACCESS_ACCESS               CONNMAN_ACCESS_DENY
#define GET_DEFAULT_ACCESS_ACCESS       GET_ACCESS_ACCESS
#define SET_DEFAULT_ACCESS_ACCESS       SET_ACCESS_ACCESS
#define GET_PASSPHRASE_ACCESS           CONNMAN_ACCESS_DENY
#define SET_PASSPHRASE_ACCESS           CONNMAN_ACCESS_DENY
#define GET_IDENTITY_ACCESS             CONNMAN_ACCESS_DENY
#define SET_IDENTITY_ACCESS             CONNMAN_ACCESS_DENY
#define GET_EAP_ACCESS                  CONNMAN_ACCESS_ALLOW
#define SET_EAP_ACCESS                  CONNMAN_ACCESS_DENY
#define GET_PHASE2_ACCESS               CONNMAN_ACCESS_ALLOW
#define SET_PHASE2_ACCESS               CONNMAN_ACCESS_DENY
#define GET_CA_CERT_ACCESS              CONNMAN_ACCESS_ALLOW
#define SET_CA_CERT_ACCESS              CONNMAN_ACCESS_DENY
#define GET_CA_CERT_FILE_ACCESS         CONNMAN_ACCESS_ALLOW
#define SET_CA_CERT_FILE_ACCESS         CONNMAN_ACCESS_DENY
#define GET_DOMAIN_SUFFIX_MATCH_ACCESS  CONNMAN_ACCESS_ALLOW
#define SET_DOMAIN_SUFFIX_MATCH_ACCESS  CONNMAN_ACCESS_DENY
#define GET_CLIENT_CERT_ACCESS          CONNMAN_ACCESS_ALLOW
#define SET_CLIENT_CERT_ACCESS          CONNMAN_ACCESS_DENY
#define GET_PRIVATE_KEY_ACCESS          CONNMAN_ACCESS_ALLOW
#define SET_PRIVATE_KEY_ACCESS          CONNMAN_ACCESS_DENY
#define GET_PRIVATE_KEY_PASSPHRASE_ACCESS \
					CONNMAN_ACCESS_ALLOW
#define SET_PRIVATE_KEY_PASSPHRASE_ACCESS \
	                                CONNMAN_ACCESS_DENY
#define GET_ANONYMOUS_IDENTITY_ACCESS   CONNMAN_ACCESS_ALLOW
#define SET_ANONYMOUS_IDENTITY_ACCESS   CONNMAN_ACCESS_DENY

/* Set properties (Get is always ACCESS_ALLOW for these) */
#define SET_PROXYCONFIG_ACCESS          CONNMAN_ACCESS_DENY

/* Other methods */
#define CLEAR_PROPERTY_ACCESS           CONNMAN_ACCESS_ALLOW
#define CONNECT_ACCESS                  CONNMAN_ACCESS_ALLOW
#define DISCONNECT_ACCESS               CONNMAN_ACCESS_ALLOW
#define REMOVE_ACCESS                   CONNMAN_ACCESS_ALLOW
#define RESET_COUNTERS_ACCESS           CONNMAN_ACCESS_ALLOW

/* Access descriptors */
#define ACCESS_PROP_ACCESS              0x00000001
#define ACCESS_PROP_DEFAULT_ACCESS      0x00000002
#define ACCESS_PROP_PASSPHRASE          0x00000004
#define ACCESS_PROP_IDENTITY            0x00000008
#define ACCESS_PROP_EAP                 0x00000010
#define ACCESS_PROP_PHASE2              0x00000020
#define ACCESS_PROP_CA_CERT             0x00000040
#define ACCESS_PROP_CA_CERT_FILE        0x00000080
#define ACCESS_PROP_DOMAIN_SUFFIX_MATCH 0x00000100
#define ACCESS_PROP_CLIENT_CERT         0x00000200
#define ACCESS_PROP_CLIENT_CERT_FILE    0x00000400
#define ACCESS_PROP_PRIVATE_KEY         0x00000800
#define ACCESS_PROP_PRIVATE_KEY_FILE    0x00001000
#define ACCESS_PROP_PRIVATE_KEY_PASSPHRASE \
					0x00002000
#define ACCESS_PROP_ANONYMOUS_IDENTITY  0x00004000

#define ACCESS_METHOD_CLEAR_PROPERTY    0x00000001
#define ACCESS_METHOD_CONNECT           0x00000002
#define ACCESS_METHOD_DISCONNECT        0x00000004
#define ACCESS_METHOD_REMOVE            0x00000008
#define ACCESS_METHOD_RESET_COUNTERS    0x00000010
#define ACCESS_METHOD_GET_PROPERTIES    0x00000020
#define ACCESS_METHOD_GET_PROPERTY      0x00000040
#define ACCESS_METHOD_SET_PROPERTY      0x00000080

/* These are alwas allowed, individual properties are checked */
#define ACCESS_METHOD_ALWAYS_ALLOWED (\
	ACCESS_METHOD_CLEAR_PROPERTY | \
	ACCESS_METHOD_GET_PROPERTIES | \
	ACCESS_METHOD_GET_PROPERTY   | \
	ACCESS_METHOD_SET_PROPERTY)

static const struct connman_service_property_access {
	guint32 flag;
	const char *name;
	enum connman_access default_get_access;
	enum connman_access default_set_access;
} service_property_access[] = {
	{
		ACCESS_PROP_ACCESS,
		PROP_ACCESS,
		GET_ACCESS_ACCESS,
		SET_ACCESS_ACCESS
	},{
		ACCESS_PROP_DEFAULT_ACCESS,
		PROP_DEFAULT_ACCESS,
		GET_DEFAULT_ACCESS_ACCESS,
		SET_DEFAULT_ACCESS_ACCESS
	},{
		ACCESS_PROP_PASSPHRASE,
		PROP_PASSPHRASE,
		GET_PASSPHRASE_ACCESS,
		SET_PASSPHRASE_ACCESS
	},{
		ACCESS_PROP_IDENTITY,
		PROP_IDENTITY,
		GET_IDENTITY_ACCESS,
		SET_IDENTITY_ACCESS
	},{
		ACCESS_PROP_EAP,
		PROP_EAP,
		GET_EAP_ACCESS,
		SET_EAP_ACCESS
	},{
		ACCESS_PROP_PHASE2,
		PROP_PHASE2,
		GET_PHASE2_ACCESS,
		SET_PHASE2_ACCESS
	},{
		ACCESS_PROP_CA_CERT,
		PROP_CA_CERT,
		GET_CA_CERT_ACCESS,
		SET_CA_CERT_ACCESS
	},{
		ACCESS_PROP_CA_CERT_FILE,
		PROP_CA_CERT_FILE,
		GET_CA_CERT_FILE_ACCESS,
		SET_CA_CERT_FILE_ACCESS
	},{
		ACCESS_PROP_DOMAIN_SUFFIX_MATCH,
		PROP_DOMAIN_SUFFIX_MATCH,
		GET_DOMAIN_SUFFIX_MATCH_ACCESS,
		SET_DOMAIN_SUFFIX_MATCH_ACCESS
	},{
		ACCESS_PROP_CLIENT_CERT,
		PROP_CLIENT_CERT,
		GET_CLIENT_CERT_ACCESS,
		SET_CLIENT_CERT_ACCESS
	},{
		ACCESS_PROP_CLIENT_CERT_FILE,
		PROP_CLIENT_CERT_FILE,
		GET_CLIENT_CERT_ACCESS,
		SET_CLIENT_CERT_ACCESS
	},{
		ACCESS_PROP_PRIVATE_KEY,
		PROP_PRIVATE_KEY,
		GET_PRIVATE_KEY_ACCESS,
		SET_PRIVATE_KEY_ACCESS
	},{
		ACCESS_PROP_PRIVATE_KEY_FILE,
		PROP_PRIVATE_KEY_FILE,
		GET_PRIVATE_KEY_ACCESS,
		SET_PRIVATE_KEY_ACCESS
	},{
		ACCESS_PROP_PRIVATE_KEY_PASSPHRASE,
		PROP_PRIVATE_KEY_PASSPHRASE,
		GET_PRIVATE_KEY_PASSPHRASE_ACCESS,
		SET_PRIVATE_KEY_PASSPHRASE_ACCESS
	},{
		ACCESS_PROP_ANONYMOUS_IDENTITY,
		PROP_ANONYMOUS_IDENTITY,
		GET_ANONYMOUS_IDENTITY_ACCESS,
		SET_ANONYMOUS_IDENTITY_ACCESS
	}
};

static const struct connman_service_method_access {
	guint32 flag;
	enum connman_access_service_methods method;
	enum connman_access default_access;
} service_method_access[] = {
	{
		ACCESS_METHOD_CONNECT,
		CONNMAN_ACCESS_SERVICE_CONNECT,
		CONNECT_ACCESS
	},{
		ACCESS_METHOD_DISCONNECT,
		CONNMAN_ACCESS_SERVICE_DISCONNECT,
		DISCONNECT_ACCESS
	},{
		ACCESS_METHOD_REMOVE,
		CONNMAN_ACCESS_SERVICE_REMOVE,
		REMOVE_ACCESS
	},{
		ACCESS_METHOD_RESET_COUNTERS,
		CONNMAN_ACCESS_SERVICE_RESET_COUNTERS,
		RESET_COUNTERS_ACCESS
	}
};

static DBusConnection *connection = NULL;

static GList *service_list = NULL;
static GHashTable *service_hash = NULL;
static GSList *counter_list = NULL;
static unsigned int autoconnect_id = 0;
static unsigned int vpn_autoconnect_id = 0;
static struct connman_service *current_default = NULL;
static bool services_dirty = false;
static bool autoconnect_paused = false;
static guint load_wifi_services_id = 0;
static GHashTable **service_type_hash;
static unsigned int online_check_initial_interval = 0;
static unsigned int online_check_max_interval = 0;

struct connman_service_boolean_property {
	const char *name;
	gboolean (*value)(struct connman_service *service);
};

struct connman_stats_counter_data {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t rx_errors;
	uint64_t tx_errors;
	uint64_t rx_dropped;
	uint64_t tx_dropped;
	uint64_t time;
};

struct connman_stats_counter {
	bool append_all;
	struct connman_stats_counter_data stats;
	struct connman_stats_counter_data stats_roaming;
};

struct connman_service {
	int refcount;
	char *identifier;
	char *path;
	enum connman_service_type type;
	enum connman_service_security security;
	enum connman_service_state state;
	enum connman_service_state state_ipv4;
	enum connman_service_state state_ipv6;
	enum connman_service_error error;
	enum connman_service_connect_reason connect_reason;
	uint8_t strength;
	bool favorite;
	bool immutable;
	bool hidden;
	bool ignore;
	bool autoconnect;
	struct timeval modified;
	unsigned int order;
	char *name;
	char *passphrase;
	bool roaming;
	struct connman_ipconfig *ipconfig_ipv4;
	struct connman_ipconfig *ipconfig_ipv6;
	struct connman_network *network;
	struct connman_provider *provider;
	char **nameservers;
	char **nameservers_config;
	char **nameservers_auto;
	int nameservers_timeout;
	int nameservers_ipv4_refcount;
	int nameservers_ipv6_refcount;
	char **domains;
	bool mdns;
	bool mdns_config;
	char *hostname;
	char *domainname;
	char **timeservers;
	char **timeservers_config;
	/* 802.1x settings from the config files */
	char *eap;
	char *identity;
	char *anonymous_identity;
	char *agent_identity;
	char *ca_cert_file;
	char *ca_cert;
	char *subject_match;
	char *altsubject_match;
	char *domain_suffix_match;
	char *domain_match;
	char *client_cert_file;
	char *client_cert;
	char *private_key_file;
	char *private_key;
	char *private_key_passphrase;
	char *phase2;
	DBusMessage *pending;
	DBusMessage *provider_pending;
	guint timeout;
	struct connman_stats *stats;
	struct connman_stats *stats_roaming;
	GTimer *stats_timer;
	uint64_t stats_update_time;
	GHashTable *counter_table;
	enum connman_service_proxy_method proxy;
	enum connman_service_proxy_method proxy_config;
	char **proxies;
	char **excludes;
	char *pac;
	bool wps;
	bool wps_advertizing;
	unsigned int online_check_interval_ipv4;
	unsigned int online_check_interval_ipv6;
	guint online_timeout_ipv4;
	guint online_timeout_ipv6;
	guint connect_retry_timer;
	guint connect_retry_timeout;
	bool do_split_routing;
	bool new_service;
	bool hidden_service;
	char *config_file;
	char *config_entry;
	GBytes *ssid;
	struct connman_access_service_policy *policy;
	char *access;
	gboolean disabled;
};

static const char *service_get_access(struct connman_service *service);
static void service_set_access(struct connman_service *service,
					const char *access);
static void string_changed(struct connman_service *service,
					const char *name, const char *value);
static bool allow_property_changed(struct connman_service *service);

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method);
static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index);
static void dns_changed(struct connman_service *service);
static void vpn_auto_connect(void);

static bool is_connecting(enum connman_service_state state);
static bool is_connected(enum connman_service_state state);

static void switch_default_service(struct connman_service *default_service,
	struct connman_service *downgrade_service);

static GList* preferred_tech_list_get(void);

static void stats_init(struct connman_service *service);
static void service_send_initial_stats(const char *counter);
static gboolean is_available(struct connman_service *service);

struct find_data {
	const char *path;
	struct connman_service *service;
};

void __connman_service_foreach(void (*fn) (struct connman_service *service,
					void *user_data), void *user_data)
{
	GList *l;

	/* Assume that the callback is not modifying the service list */
	for (l = service_list; l; l = l->next) {
		fn((struct connman_service *)l->data, user_data);
	}
}

GBytes *__connman_service_get_ssid(struct connman_service *service)
{
	return service ? service->ssid : NULL;
}

enum connman_service_connect_reason
	__connman_service_get_connect_reason(struct connman_service *service)
{
	return service ? service->connect_reason :
		CONNMAN_SERVICE_CONNECT_REASON_NONE;
}

/*
 * It's hard to tell the difference between hidden and hidden_service
 * flags, so this function checks both.
 */
bool __connman_service_is_really_hidden(struct connman_service *service)
{
	return service && (service->hidden || service->hidden_service);
}

static void get_config_string(GKeyFile *keyfile, const char *group,
					const char *key, char **value)
{
	char *str = g_key_file_get_string(keyfile, group, key, NULL);
	if (str) {
		g_free(*value);
		*value = str;
	}
}

static void set_config_string(GKeyFile *keyfile, const char *group,
					const char *key, const char *value)
{
	if (value)
		g_key_file_set_string(keyfile, group, key, value);
	else
		g_key_file_remove_key(keyfile, group, key, NULL);
}

static inline char *service_path(const char *ident)
{
	return g_strconcat(CONNMAN_PATH, "/service/", ident, NULL);
}


static void count_available_service_type(struct connman_service *service,
								bool add)
{
	GHashTable *table;
	enum connman_service_type type;

	if (!service)
		return;

	type = service->type;
	table = service_type_hash[type];

	DBG("%p/%s %s %c 1", service, service->name,
					__connman_service_type2string(type),
					add ? '+' : '-');

	if (add) {
		if (!is_available(service)) {
			DBG("service %p/%s not available", service,
							service->identifier);
			return;
		}

		if (!table)
			table = service_type_hash[type] = g_hash_table_new(
						g_str_hash, g_str_equal);

		g_hash_table_replace(table, service->identifier, service);
	} else if (table) {
		g_hash_table_remove(table, service->identifier);
	}

	DBG("%s service count: %d", __connman_service_type2string(type),
					table ? g_hash_table_size(table) : 0);
}

static void service_remove(struct connman_service *service)
{
	count_available_service_type(service, false);
	service_list = g_list_remove(service_list, service);
	g_hash_table_remove(service_hash, service->identifier);
}

static void compare_path(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct find_data *data = user_data;

	if (data->service)
		return;

	if (g_strcmp0(service->path, data->path) == 0)
		data->service = service;
}

static struct connman_service *find_service(const char *path)
{
	struct find_data data = { .path = path, .service = NULL };

	DBG("path %s", path);

	g_list_foreach(service_list, compare_path, &data);

	return data.service;
}

static const char *reason2string(enum connman_service_connect_reason reason)
{

	switch (reason) {
	case CONNMAN_SERVICE_CONNECT_REASON_NONE:
		return "none";
	case CONNMAN_SERVICE_CONNECT_REASON_USER:
		return "user";
	case CONNMAN_SERVICE_CONNECT_REASON_AUTO:
		return "auto";
	case CONNMAN_SERVICE_CONNECT_REASON_SESSION:
		return "session";
	}

	return "unknown";
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return "system";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "gadget";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "p2p";
	}

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	if (strncmp(str, "ethernet", 8) == 0)
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	if (strncmp(str, "gadget", 6) == 0)
		return CONNMAN_SERVICE_TYPE_GADGET;
	if (strncmp(str, "wifi", 4) == 0)
		return CONNMAN_SERVICE_TYPE_WIFI;
	if (strncmp(str, "cellular", 8) == 0)
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	if (strncmp(str, "bluetooth", 9) == 0)
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	if (strncmp(str, "vpn", 3) == 0)
		return CONNMAN_SERVICE_TYPE_VPN;
	if (strncmp(str, "gps", 3) == 0)
		return CONNMAN_SERVICE_TYPE_GPS;
	if (strncmp(str, "system", 6) == 0)
		return CONNMAN_SERVICE_TYPE_SYSTEM;
	if (strncmp(str, "p2p", 3) == 0)
		return CONNMAN_SERVICE_TYPE_P2P;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

enum connman_service_security __connman_service_string2security(const char *str)
{
	if (!str)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	if (!strcmp(str, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	if (!strcmp(str, "ieee8021x") || !strcmp(str, "8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	if (!strcmp(str, "none") || !strcmp(str, "open"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	if (!strcmp(str, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;

	return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

const char *__connman_service_security2string(enum connman_service_security security)
{
	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		break;
	case CONNMAN_SERVICE_SECURITY_NONE:
		return "none";
	case CONNMAN_SERVICE_SECURITY_WEP:
		return "wep";
	case CONNMAN_SERVICE_SECURITY_PSK:
	case CONNMAN_SERVICE_SECURITY_WPA:
	case CONNMAN_SERVICE_SECURITY_RSN:
		return "psk";
	case CONNMAN_SERVICE_SECURITY_8021X:
		return "ieee8021x";
	}

	return NULL;
}

static const char *state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_SERVICE_STATE_READY:
		return "ready";
	case CONNMAN_SERVICE_STATE_ONLINE:
		return "online";
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_SERVICE_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}

static const char *error2string(enum connman_service_error error)
{
	switch (error) {
	case CONNMAN_SERVICE_ERROR_UNKNOWN:
		break;
	case CONNMAN_SERVICE_ERROR_OUT_OF_RANGE:
		return "out-of-range";
	case CONNMAN_SERVICE_ERROR_PIN_MISSING:
		return "pin-missing";
	case CONNMAN_SERVICE_ERROR_DHCP_FAILED:
		return "dhcp-failed";
	case CONNMAN_SERVICE_ERROR_CONNECT_FAILED:
		return "connect-failed";
	case CONNMAN_SERVICE_ERROR_LOGIN_FAILED:
		return "login-failed";
	case CONNMAN_SERVICE_ERROR_AUTH_FAILED:
		return "auth-failed";
	case CONNMAN_SERVICE_ERROR_INVALID_KEY:
		return "invalid-key";
	case CONNMAN_SERVICE_ERROR_BLOCKED:
		return "blocked";
	}

	return NULL;
}

static const char *proxymethod2string(enum connman_service_proxy_method method)
{
	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		return "direct";
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		return "manual";
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		return "auto";
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		break;
	}

	return NULL;
}

static enum connman_service_proxy_method string2proxymethod(const char *method)
{
	if (g_strcmp0(method, "direct") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
	else if (g_strcmp0(method, "auto") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_AUTO;
	else if (g_strcmp0(method, "manual") == 0)
		return CONNMAN_SERVICE_PROXY_METHOD_MANUAL;
	else
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;
}

void __connman_service_split_routing_changed(struct connman_service *service)
{
	dbus_bool_t split_routing;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	split_routing = service->do_split_routing;
	if (!connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "SplitRouting",
					DBUS_TYPE_BOOLEAN, &split_routing))
		connman_warn("cannot send SplitRouting property change on %s",
					service->identifier);
}

void __connman_service_set_split_routing(struct connman_service *service,
			bool value)
{
	bool change;

	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		return;

	DBG("%p/%s value %s", service, service->identifier,
						value ? "true" : "false");

	change = service->do_split_routing != value;

	service->do_split_routing = value;

	if (service->do_split_routing)
		service->order = 0;
	else
		service->order = 10;

	/*
	 * Change IPv6 on the VPN transport when split routing value changes
	 * on a connected VPN. If IPv6 is enabled, VPN transport 
	 */
	if (change && is_connected(service->state)) {
		if (__connman_provider_set_ipv6_for_connected(
							service->provider,
							value))
			DBG("cannot %s IPv6 for VPN service %p provider %p",
						value ? "enable" : "disable",
						service, service->provider);
	}

	/*
	 * In order to make sure the value is propagated also when loading the
	 * VPN service signal the value regardless of the value change.
	 */
	__connman_service_split_routing_changed(service);
}

int __connman_service_load_modifiable(struct connman_service *service)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gchar *str;
	bool autoconnect;

	DBG("service %p", service);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return -EIO;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		__connman_service_set_split_routing(service,
						g_key_file_get_boolean(keyfile,
						service->identifier,
						"SplitRouting", NULL));

		/* fall through */
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			connman_service_set_autoconnect(service, autoconnect);
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		util_iso8601_to_timeval(str, &service->modified);
		g_free(str);
	}

	g_key_file_unref(keyfile);

	return 0;
}

static void service_apply(struct connman_service *service, GKeyFile *keyfile)
{
	GError *error = NULL;
	gsize length;
	gchar *str;
	bool autoconnect;
	unsigned int ssid_len;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		__connman_service_set_split_routing(service,
						g_key_file_get_boolean(keyfile,
						service->identifier,
						"SplitRouting", NULL));

		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			connman_service_set_autoconnect(service, autoconnect);
		g_clear_error(&error);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		str = g_key_file_get_string(keyfile,
					service->identifier, PROP_NAME, NULL);
		if (str) {
			if (g_strcmp0(service->name, str)) {
				g_free(service->name);
				service->name = str;
				string_changed(service, PROP_NAME, str);
			} else {
				g_free(str);
			}

			if (service->network)
				connman_network_set_name(service->network,
							service->name);
		}

		str = g_key_file_get_string(keyfile, service->identifier,
							PROP_SSID, NULL);
		if (str) {
			GBytes *ssid = gutil_hex2bytes(str, -1);
			if (ssid) {
				if (!service->ssid ||
					!g_bytes_equal(service->ssid, ssid)) {
					if (service->ssid)
						g_bytes_unref(service->ssid);
					service->ssid = ssid;
				} else {
					g_bytes_unref(ssid);
				}
			}
			g_free(str);
		}

		if (service->ssid && service->network &&
				!connman_network_get_blob(service->network,
						"WiFi.SSID", &ssid_len)) {
			connman_network_set_blob(service->network, "WiFi.SSID",
				g_bytes_get_data(service->ssid, NULL),
				g_bytes_get_size(service->ssid));
		}
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		service->favorite = g_key_file_get_boolean(keyfile,
				service->identifier, "Favorite", NULL);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		autoconnect = g_key_file_get_boolean(keyfile,
				service->identifier, "AutoConnect", &error);
		if (!error)
			connman_service_set_autoconnect(service, autoconnect);
		g_clear_error(&error);
		break;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Modified", NULL);
	if (str) {
		util_iso8601_to_timeval(str, &service->modified);
		g_free(str);
	}

	get_config_string(keyfile, service->identifier, PROP_EAP,
					&service->eap);
	get_config_string(keyfile, service->identifier, PROP_IDENTITY,
					&service->identity);
	get_config_string(keyfile, service->identifier, "AnonymousIdentity",
					&service->anonymous_identity);
	get_config_string(keyfile, service->identifier, PROP_CA_CERT_FILE,
					&service->ca_cert_file);
	get_config_string(keyfile, service->identifier, PROP_CA_CERT,
					&service->ca_cert);
	get_config_string(keyfile, service->identifier, "SubjectMatch",
					&service->subject_match);
	get_config_string(keyfile, service->identifier, "AltSubjectMatch",
					&service->altsubject_match);
	get_config_string(keyfile, service->identifier, PROP_DOMAIN_SUFFIX_MATCH,
					&service->domain_suffix_match);
	get_config_string(keyfile, service->identifier, "DomainMatch",
					&service->domain_match);
	get_config_string(keyfile, service->identifier, PROP_CLIENT_CERT_FILE,
					&service->client_cert_file);
	get_config_string(keyfile, service->identifier, PROP_CLIENT_CERT,
					&service->client_cert);
	get_config_string(keyfile, service->identifier, PROP_PRIVATE_KEY_FILE,
					&service->private_key_file);
	get_config_string(keyfile, service->identifier, PROP_PRIVATE_KEY,
					&service->private_key);
	get_config_string(keyfile, service->identifier, PROP_PRIVATE_KEY_PASSPHRASE,
					&service->private_key_passphrase);
	get_config_string(keyfile, service->identifier, PROP_PHASE2,
					&service->phase2);

	str = g_key_file_get_string(keyfile,
				service->identifier, PROP_ACCESS, NULL);
	if (str) {
		service_set_access(service, str);
		g_free(str);
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Passphrase", NULL);
	if (str) {
		g_free(service->passphrase);
		service->passphrase = str;
	}

	if (service->ipconfig_ipv4)
		__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
					service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
					service->identifier, "IPv6.");

	service->nameservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Nameservers", &length, NULL);
	if (service->nameservers_config && length == 0) {
		g_strfreev(service->nameservers_config);
		service->nameservers_config = NULL;
	}

	service->timeservers_config = g_key_file_get_string_list(keyfile,
			service->identifier, "Timeservers", &length, NULL);
	if (service->timeservers_config && length == 0) {
		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;
	}

	service->domains = g_key_file_get_string_list(keyfile,
			service->identifier, "Domains", &length, NULL);
	if (service->domains && length == 0) {
		g_strfreev(service->domains);
		service->domains = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.Method", NULL);
	if (str)
		service->proxy_config = string2proxymethod(str);

	g_free(str);

	service->proxies = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Servers", &length, NULL);
	if (service->proxies && length == 0) {
		g_strfreev(service->proxies);
		service->proxies = NULL;
	}

	service->excludes = g_key_file_get_string_list(keyfile,
			service->identifier, "Proxy.Excludes", &length, NULL);
	if (service->excludes && length == 0) {
		g_strfreev(service->excludes);
		service->excludes = NULL;
	}

	str = g_key_file_get_string(keyfile,
				service->identifier, "Proxy.URL", NULL);
	if (str) {
		g_free(service->pac);
		service->pac = str;
	}

	service->mdns_config = g_key_file_get_boolean(keyfile,
				service->identifier, "mDNS", NULL);

	service->hidden_service = g_key_file_get_boolean(keyfile,
					service->identifier, "Hidden", NULL);

	count_available_service_type(service, true);
}

static int service_load(struct connman_service *service)
{
	GKeyFile *keyfile;

	DBG("service %p %s", service, service->identifier);

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile) {
		service->new_service = true;
		return -EIO;
	} else
		service->new_service = false;

	service_apply(service, keyfile);
	g_key_file_unref(keyfile);

	return 0;
}

static int service_save(struct connman_service *service)
{
	GKeyFile *keyfile;
	gchar *str;
	guint freq;
	const char *cst_str = NULL;
	int err = 0;

	DBG("service %p new %d", service, service->new_service);

	if (service->new_service)
		return -ESRCH;

	keyfile = g_key_file_new();
	if (!keyfile)
		return -EIO;

	if (service->name)
		g_key_file_set_string(keyfile, service->identifier,
						"Name", service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		g_key_file_set_boolean(keyfile, service->identifier,
				"SplitRouting", service->do_split_routing);
		if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->ssid) {
			gsize ssid_len = 0;
			const unsigned char *ssid;

			ssid = g_bytes_get_data(service->ssid, &ssid_len);
			if (ssid && ssid_len > 0 && ssid[0] != '\0') {
				char *identifier = service->identifier;
				GString *ssid_str;
				unsigned int i;

				ssid_str = g_string_sized_new(ssid_len * 2);
				if (!ssid_str) {
					err = -ENOMEM;
					goto done;
				}

				for (i = 0; i < ssid_len; i++)
					g_string_append_printf(ssid_str,
							"%02x", ssid[i]);

				g_key_file_set_string(keyfile, identifier,
							"SSID", ssid_str->str);

				g_string_free(ssid_str, TRUE);
			}
		}
		if (service->network) {
			freq = connman_network_get_frequency(service->network);
			g_key_file_set_integer(keyfile, service->identifier,
						"Frequency", freq);
		}
		set_config_string(keyfile, service->identifier,
			PROP_EAP, service->eap);
		set_config_string(keyfile, service->identifier,
			PROP_IDENTITY, service->identity);
		set_config_string(keyfile, service->identifier,
			"AnonymousIdentity", service->anonymous_identity);
		set_config_string(keyfile, service->identifier,
			"CACertFile", service->ca_cert_file);
		set_config_string(keyfile, service->identifier,
			"CACert", service->ca_cert);
		set_config_string(keyfile, service->identifier,
			"SubjectMatch", service->subject_match);
		set_config_string(keyfile, service->identifier,
			"AltSubjectMatch", service->altsubject_match);
		set_config_string(keyfile, service->identifier,
			"DomainSuffixMatch", service->domain_suffix_match);
		set_config_string(keyfile, service->identifier,
			"DomainMatch", service->domain_match);
		set_config_string(keyfile, service->identifier,
			PROP_CLIENT_CERT_FILE, service->client_cert_file);
		set_config_string(keyfile, service->identifier,
			PROP_CLIENT_CERT, service->client_cert);
		set_config_string(keyfile, service->identifier,
			PROP_PRIVATE_KEY_FILE, service->private_key_file);
		set_config_string(keyfile, service->identifier,
			PROP_PRIVATE_KEY, service->private_key);
		set_config_string(keyfile, service->identifier,
			PROP_PRIVATE_KEY_PASSPHRASE,
			service->private_key_passphrase);
		set_config_string(keyfile, service->identifier,
			PROP_PHASE2, service->phase2);
		/* fall through */

	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		g_key_file_set_boolean(keyfile, service->identifier,
					"Favorite", service->favorite);

		/* fall through */

	case CONNMAN_SERVICE_TYPE_ETHERNET:
		//if (service->favorite)
			g_key_file_set_boolean(keyfile, service->identifier,
					"AutoConnect", service->autoconnect);
		break;
	}

	set_config_string(keyfile, service->identifier, PROP_ACCESS,
					service_get_access(service));

	str = util_timeval_to_iso8601(&service->modified);
	if (str) {
		g_key_file_set_string(keyfile, service->identifier, "Modified",
					str);
		g_free(str);
	}

	if (service->passphrase && strlen(service->passphrase) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Passphrase", service->passphrase);

	if (service->ipconfig_ipv4)
		__connman_ipconfig_save(service->ipconfig_ipv4, keyfile,
				service->identifier, "IPv4.");

	if (service->ipconfig_ipv6)
		__connman_ipconfig_save(service->ipconfig_ipv6, keyfile,
				service->identifier, "IPv6.");

	if (service->nameservers_config) {
		guint len = g_strv_length(service->nameservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Nameservers",
				(const gchar **) service->nameservers_config, len);
	}

	if (service->timeservers_config) {
		guint len = g_strv_length(service->timeservers_config);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Timeservers",
				(const gchar **) service->timeservers_config, len);
	}

	if (service->domains) {
		guint len = g_strv_length(service->domains);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Domains",
				(const gchar **) service->domains, len);
	}

	cst_str = proxymethod2string(service->proxy_config);
	if (cst_str)
		g_key_file_set_string(keyfile, service->identifier,
				"Proxy.Method", cst_str);

	if (service->proxies) {
		guint len = g_strv_length(service->proxies);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Servers",
				(const gchar **) service->proxies, len);
	}

	if (service->excludes) {
		guint len = g_strv_length(service->excludes);

		g_key_file_set_string_list(keyfile, service->identifier,
				"Proxy.Excludes",
				(const gchar **) service->excludes, len);
	}

	if (service->pac && strlen(service->pac) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Proxy.URL", service->pac);

	if (service->mdns_config)
		g_key_file_set_boolean(keyfile, service->identifier,
								"mDNS", TRUE);
	else
		g_key_file_remove_key(keyfile, service->identifier,
								"mDNS", NULL);

	if (service->hidden_service)
		g_key_file_set_boolean(keyfile, service->identifier,
				"Hidden", TRUE);

	if (service->config_file && strlen(service->config_file) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.file", service->config_file);

	if (service->config_entry && strlen(service->config_entry) > 0)
		g_key_file_set_string(keyfile, service->identifier,
				"Config.ident", service->config_entry);

done:
	__connman_storage_save_service(keyfile, service->identifier);

	g_key_file_unref(keyfile);

	return err;
}

void __connman_service_save(struct connman_service *service)
{
	if (!service)
		return;

	service_save(service);
}

static enum connman_service_state combine_state(
					enum connman_service_state state_a,
					enum connman_service_state state_b)
{
	enum connman_service_state result;

	if (state_a == state_b) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_UNKNOWN) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_b;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_IDLE) {
		result = state_a;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ONLINE) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_READY) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_READY) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_CONFIGURATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_ASSOCIATION) {
		result = state_b;
		goto done;
	}

	if (state_a == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_a;
		goto done;
	}

	if (state_b == CONNMAN_SERVICE_STATE_DISCONNECT) {
		result = state_b;
		goto done;
	}

	result = CONNMAN_SERVICE_STATE_FAILURE;

done:
	return result;
}

static bool is_connecting(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return true;
	}

	return false;
}

static bool is_connected(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		break;
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		return true;
	}

	return false;
}

static bool is_idle(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_DISCONNECT:
	case CONNMAN_SERVICE_STATE_FAILURE:
		return true;
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
	case CONNMAN_SERVICE_STATE_READY:
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	}

	return false;
}

static int nameservers_changed_cb(void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	service->nameservers_timeout = 0;
	if ((is_idle(service->state) && !service->nameservers) ||
			is_connected(service->state))
		dns_changed(service);

	return FALSE;
}

static void nameservers_changed(struct connman_service *service)
{
	if (!service->nameservers_timeout)
		service->nameservers_timeout = g_idle_add(nameservers_changed_cb,
							service);
}

static bool nameserver_available(struct connman_service *service,
				enum connman_ipconfig_type type,
				const char *ns)
{
	int family;

	family = connman_inet_check_ipaddress(ns);

	if (family == AF_INET) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
			return false;

		return is_connected(service->state_ipv4);
	}

	if (family == AF_INET6) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			return false;

		return is_connected(service->state_ipv6);
	}

	return false;
}

static int searchdomain_add_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	if (service->domains) {
		while (service->domains[i]) {
			connman_resolver_append(index, service->domains[i],
						NULL);
			i++;
		}

		return 0;
	}

	if (service->domainname)
		connman_resolver_append(index, service->domainname, NULL);

	return 0;

}

static int searchdomain_remove_all(struct connman_service *service)
{
	int index, i = 0;

	if (!is_connected(service->state))
		return -ENOTCONN;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->domains && service->domains[i]) {
		connman_resolver_remove(index, service->domains[i], NULL);
		i++;
	}

	if (service->domainname)
		connman_resolver_remove(index, service->domainname, NULL);

	return 0;
}

static int nameserver_add(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	ret = connman_resolver_append(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_add_all(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	int i = 0;

	if (service->nameservers_config) {
		while (service->nameservers_config[i]) {
			nameserver_add(service, type,
				service->nameservers_config[i]);
			i++;
		}
	} else if (service->nameservers) {
		while (service->nameservers[i]) {
			nameserver_add(service, type,
				service->nameservers[i]);
			i++;
		}
	}

	if (!i)
		__connman_resolver_append_fallback_nameservers();

	searchdomain_add_all(service);

	return 0;
}

static int nameserver_remove(struct connman_service *service,
			enum connman_ipconfig_type type,
			const char *nameserver)
{
	int index, ret;

	if (!nameserver_available(service, type, nameserver))
		return 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	ret = connman_resolver_remove(index, NULL, nameserver);
	if (ret >= 0)
		nameservers_changed(service);

	return ret;
}

static int nameserver_remove_all(struct connman_service *service,
				enum connman_ipconfig_type type)
{
	int index, i = 0;

	index = __connman_service_get_index(service);
	if (index < 0)
		return -ENXIO;

	while (service->nameservers_config && service->nameservers_config[i]) {

		nameserver_remove(service, type,
				service->nameservers_config[i]);
		i++;
	}

	i = 0;
	while (service->nameservers && service->nameservers[i]) {
		nameserver_remove(service, type, service->nameservers[i]);
		i++;
	}

	searchdomain_remove_all(service);

	return 0;
}

/*
 * The is_auto variable is set to true when IPv6 autoconf nameservers are
 * inserted to resolver via netlink message (see rtnl.c:rtnl_newnduseropt()
 * for details) and not through service.c
 */
int __connman_service_nameserver_append(struct connman_service *service,
				const char *nameserver, bool is_auto)
{
	char **nameservers;
	int len, i;

	DBG("service %p nameserver %s auto %d",	service, nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	if (nameservers) {
		for (i = 0; nameservers[i]; i++) {
			if (g_strcmp0(nameservers[i], nameserver) == 0)
				return -EEXIST;
		}

		len = g_strv_length(nameservers);
		nameservers = g_try_renew(char *, nameservers, len + 2);
	} else {
		len = 0;
		nameservers = g_try_new0(char *, len + 2);
	}

	if (!nameservers)
		return -ENOMEM;

	nameservers[len] = g_strdup(nameserver);
	nameservers[len + 1] = NULL;

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
		nameserver_add(service, CONNMAN_IPCONFIG_TYPE_ALL, nameserver);
	}

	nameservers_changed(service);

	searchdomain_add_all(service);

	return 0;
}

int __connman_service_nameserver_remove(struct connman_service *service,
				const char *nameserver, bool is_auto)
{
	char **servers, **nameservers;
	bool found = false;
	int len, i, j;

	DBG("service %p nameserver %s auto %d", service, nameserver, is_auto);

	if (!nameserver)
		return -EINVAL;

	if (is_auto)
		nameservers = service->nameservers_auto;
	else
		nameservers = service->nameservers;

	if (!nameservers)
		return 0;

	for (i = 0; nameservers[i]; i++)
		if (g_strcmp0(nameservers[i], nameserver) == 0) {
			found = true;
			break;
		}

	if (!found)
		return 0;

	len = g_strv_length(nameservers);

	if (len == 1) {
		servers = NULL;
		goto set_servers;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(nameservers[i], nameserver)) {
			servers[j] = nameservers[i];
			j++;
		} else
			g_free(nameservers[i]);

		nameservers[i] = NULL;
	}
	servers[len - 1] = NULL;

set_servers:
	g_strfreev(nameservers);
	nameservers = servers;

	if (is_auto) {
		service->nameservers_auto = nameservers;
	} else {
		service->nameservers = nameservers;
		nameserver_remove(service, CONNMAN_IPCONFIG_TYPE_ALL,
				nameserver);
	}

	return 0;
}

void __connman_service_nameserver_clear(struct connman_service *service)
{
	nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);

	g_strfreev(service->nameservers);
	service->nameservers = NULL;

	nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
}

static void add_nameserver_route(int family, int index, char *nameserver,
				const char *gw)
{
	switch (family) {
	case AF_INET:
		if (connman_inet_compare_subnet(index, nameserver))
			break;

		if (connman_inet_add_host_route(index, nameserver, gw) < 0)
			/* For P-t-P link the above route add will fail */
			connman_inet_add_host_route(index, nameserver, NULL);
		break;

	case AF_INET6:
		if (connman_inet_add_ipv6_host_route(index, nameserver,
								gw) < 0)
			connman_inet_add_ipv6_host_route(index, nameserver,
							NULL);
		break;
	}
}

static void nameserver_add_routes(int index, char **nameservers,
					const char *gw, int gw_family)
{
	int i, ns_family;

	for (i = 0; nameservers[i]; i++) {
		ns_family = connman_inet_check_ipaddress(nameservers[i]);
		if (ns_family < 0 || ns_family != gw_family)
			continue;

		add_nameserver_route(ns_family, index, nameservers[i], gw);
	}
}

static void nameserver_del_routes(int index, char **nameservers,
				enum connman_ipconfig_type type)
{
	int i, family;

	for (i = 0; nameservers[i]; i++) {
		family = connman_inet_check_ipaddress(nameservers[i]);
		if (family < 0)
			continue;

		switch (family) {
		case AF_INET:
			if (type != CONNMAN_IPCONFIG_TYPE_IPV6)
				connman_inet_del_host_route(index,
							nameservers[i]);
			break;
		case AF_INET6:
			if (type != CONNMAN_IPCONFIG_TYPE_IPV4)
				connman_inet_del_ipv6_host_route(index,
							nameservers[i]);
			break;
		}
	}
}

void __connman_service_nameserver_add_routes(struct connman_service *service,
						const char *gw)
{
	int index;
	int gw_family;
	int refcount;
	int typeint;

	if (!service)
		return;

	gw_family = connman_inet_check_ipaddress(gw);
	switch (gw_family) {
	case AF_INET:
		refcount = __sync_fetch_and_add(
					&service->nameservers_ipv4_refcount, 1);
		typeint = 4;
		break;
	case AF_INET6:
		refcount = __sync_fetch_and_add(
					&service->nameservers_ipv6_refcount, 1);
		typeint = 6;
		break;
	default:
		return;
	}

	if (refcount) {
		DBG("%p IPv%d nameservers already added, refcount %d", service,
							typeint, refcount);
		return;
	}

	DBG("%p IPv%d nameservers refcount %d.", service,
							typeint, refcount);

	index = __connman_service_get_index(service);

	if (service->nameservers_config) {
		/*
		 * Configured nameserver takes preference over the
		 * discoverd nameserver gathered from DHCP, VPN, etc.
		 */
		nameserver_add_routes(index, service->nameservers_config, gw,
								gw_family);
	} else if (service->nameservers) {
		/*
		 * We add nameservers host routes for nameservers that
		 * are not on our subnet. For those who are, the subnet
		 * route will be installed by the time the dns proxy code
		 * tries to reach them. The subnet route is installed
		 * when setting the interface IP address.
		 */
		nameserver_add_routes(index, service->nameservers, gw,
								gw_family);
	}
}

void __connman_service_nameserver_del_routes(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	int index;
	int refcount4 = -1;
	int refcount6 = -1;

	if (!service)
		return;

	DBG("service %p type %s", service,
					__connman_ipconfig_type2string(type));

	if (type != CONNMAN_IPCONFIG_TYPE_IPV6) {
		if (service->nameservers_ipv4_refcount)
			refcount4 = __sync_fetch_and_sub(
					&service->nameservers_ipv4_refcount, 1);
		else
			refcount4 = 0;

		DBG("%p IPv4 nameservers refcount %d", service, refcount4);
	}

	if (type != CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (service->nameservers_ipv6_refcount)
			refcount6 = __sync_fetch_and_sub(
					&service->nameservers_ipv6_refcount, 1);
		else
			refcount6 = 0;

		DBG("%p IPv6 nameservers refcount %d", service, refcount6);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_ALL &&
					(refcount4 != -1 && refcount4 != 1) &&
					(refcount6 != -1 && refcount6 != 1))
		return;

	if (refcount4 != -1 && refcount4 != 1) {
		if (type == CONNMAN_IPCONFIG_TYPE_ALL)
			type = CONNMAN_IPCONFIG_TYPE_IPV6;
		else
			return;
	}

	if (refcount6 != -1 && refcount6 != 1) {
		if (type == CONNMAN_IPCONFIG_TYPE_ALL)
			type = CONNMAN_IPCONFIG_TYPE_IPV4;
		else
			return;
	}

	DBG("%p removing %s nameservers", service,
					__connman_ipconfig_type2string(type));

	index = __connman_service_get_index(service);

	if (service->nameservers_config)
		nameserver_del_routes(index, service->nameservers_config,
					type);
	else if (service->nameservers)
		nameserver_del_routes(index, service->nameservers, type);
}

static bool check_proxy_setup(struct connman_service *service)
{
	/*
	 * We start WPAD if we haven't got a PAC URL from DHCP and
	 * if our proxy manual configuration is either empty or set
	 * to AUTO with an empty URL.
	 */

	if (service->proxy != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return true;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN &&
		(service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_AUTO ||
			service->pac))
		return true;

	if (__connman_wpad_start(service) < 0) {
		service->proxy = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;
		__connman_notifier_proxy_changed(service);
		return true;
	}

	return false;
}

static void cancel_online_check(struct connman_service *service)
{
	if (!service)
		return;

	if (service->online_timeout_ipv4) {
		g_source_remove(service->online_timeout_ipv4);
		service->online_timeout_ipv4 = 0;
		connman_service_unref(service);
	}
	if (service->online_timeout_ipv6) {
		g_source_remove(service->online_timeout_ipv6);
		service->online_timeout_ipv6 = 0;
		connman_service_unref(service);
	}
}

static void start_online_check(struct connman_service *service,
				enum connman_ipconfig_type type)
{
	online_check_initial_interval =
		connman_setting_get_uint("OnlineCheckInitialInterval");
	online_check_max_interval =
		connman_setting_get_uint("OnlineCheckMaxInterval");

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 || check_proxy_setup(service)) {
		cancel_online_check(service);
		__connman_service_wispr_start(service, type);
	}
}

static void address_updated(struct connman_service *service,
			enum connman_ipconfig_type type)
{
	if (is_connected(service->state) &&
			service == connman_service_get_default()) {
		nameserver_remove_all(service, type);
		nameserver_add_all(service, type);
		start_online_check(service, type);

		__connman_timeserver_sync(service);
	}
}

static struct connman_stats *stats_get_roaming(struct connman_service *service,
							gboolean create)
{
	if (!service->stats_roaming) {
		service->stats_roaming = create ?
			__connman_stats_new(service, TRUE) :
			__connman_stats_new_existing(service, TRUE);

		if (service->stats_roaming && !service->stats_timer) {
			service->stats_timer = g_timer_new();
			g_timer_start(service->stats_timer);
		}
	}

	return service->stats_roaming;
}

static struct connman_stats *stats_get(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->roaming ?
		stats_get_roaming(service, TRUE) :
		service->stats;
}

static void reset_stats(struct connman_service *service)
{
	DBG("service %p", service);
	__connman_stats_reset(service->stats);
	__connman_stats_reset(service->stats_roaming);
	g_timer_reset(service->stats_timer);
}

struct connman_service *connman_service_get_default(void)
{
	struct connman_service *service;

	if (!service_list)
		return NULL;

	service = service_list->data;

	if (!is_connected(service->state))
		return NULL;

	return service;
}

bool __connman_service_index_is_default(int index)
{
	struct connman_service *service;
	int index4;
	int index6;

	if (index < 0)
		return false;

	service = connman_service_get_default();
	if (!service)
		return false;

	index4 = __connman_ipconfig_get_index(service->ipconfig_ipv4);
	index6 = __connman_ipconfig_get_index(service->ipconfig_ipv6);

	return index4 == index || index6 == index;
}

static struct connman_service *get_connected_default_service()
{
	GList *iter;

	struct connman_service *service = NULL;

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

		if (!__connman_service_is_split_routing(service) &&
					is_connected(service->state))
			return service;
	}

	return NULL;
}

static bool service_send_default_changed(struct connman_service *service)
{
	const char *path = service ? service->path : "";

	DBG("service %p path %s", service, path);

	return connman_dbus_property_changed_basic(CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE,
				"DefaultService",
				DBUS_TYPE_STRING,
				&path);
}

static void print_service(struct connman_service *service, void *user_data)
{
	if (service)
		DBG("service %p %s %d %s %s",
			service, service->identifier, service->order,
			is_connected(service->state) ? "true" : "false",
			state2string(service->state));
}

static void print_service_list_debug()
{
	static struct connman_debug_desc debug_desc CONNMAN_DEBUG_ATTR = {
		.file = __FILE__,
		.flags = CONNMAN_DEBUG_FLAG_DEFAULT
	};

	if (debug_desc.flags && CONNMAN_DEBUG_FLAG_PRINT) {
		DBG("<start>");
		__connman_service_foreach(print_service, NULL);
		DBG("<end>");
	}
}

static void start_wispr_when_connected(struct connman_service *service)
{
	if (__connman_service_is_connected_state(service,
			CONNMAN_IPCONFIG_TYPE_IPV4))
		__connman_service_wispr_start(service,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	if (__connman_service_is_connected_state(service,
			CONNMAN_IPCONFIG_TYPE_IPV6))
		__connman_service_wispr_start(service,
					CONNMAN_IPCONFIG_TYPE_IPV6);
}

static void default_changed(void)
{
	struct connman_service *service = connman_service_get_default();

	DBG("");
	print_service_list_debug();

	if (service == current_default) {
		DBG("default not changed %p %s",
			service, service ? service->identifier : "NULL");
		return;
	}

	/* If new service is NULL try to get a connected service. */
	if (!service) {
		service = get_connected_default_service();
		DBG("got new connected default %p", service);

		if (service == current_default) {
			DBG("new connected default == current_default");
			return;
		}
	}

	DBG("current default %p %s", current_default,
		current_default ? current_default->identifier : "");
	DBG("new default %p %s", service, service ? service->identifier : "");

	__connman_service_timeserver_changed(current_default, NULL);

	current_default = service;

	if (service) {
		if (service->hostname &&
				connman_setting_get_bool("AllowHostnameUpdates"))
			__connman_utsname_set_hostname(service->hostname);

		if (service->domainname &&
				connman_setting_get_bool("AllowDomainnameUpdates"))
			__connman_utsname_set_domainname(service->domainname);

		nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);

		start_wispr_when_connected(service);

		/*
		 * Connect VPN automatically when new default service
		 * is set and connected, unless new default is VPN
		 */
		if (is_connected(service->state) &&
			service->type != CONNMAN_SERVICE_TYPE_VPN) {
			DBG("running vpn_auto_connect");
			vpn_auto_connect();
		}
	} else {

		/*
		 * Try to autoconnect a service if new default is being
		 * set as NULL - there may be a situation where, e.g., WLAN is
		 * disconnected because of lost signal and mobile data is
		 * enabled but is idle. Mobile data is eventually connected
		 * using a auto connect timeout but calling this here is faster.
		 */
		DBG("Running service auto connect");
		__connman_service_auto_connect(
			CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	__connman_notifier_default_changed(service);
	service_send_default_changed(service);
}

static void state_changed(struct connman_service *service)
{
	const char *str;

	__connman_notifier_service_state_changed(service, service->state);

	str = state2string(service->state);
	if (!str)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "State",
						DBUS_TYPE_STRING, &str);
}

static void strength_changed(struct connman_service *service)
{
	if (service->strength == 0)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Strength",
					DBUS_TYPE_BYTE, &service->strength);
}

static void favorite_changed(struct connman_service *service)
{
	dbus_bool_t favorite;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	favorite = service->favorite;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Favorite",
					DBUS_TYPE_BOOLEAN, &favorite);
}

static void immutable_changed(struct connman_service *service)
{
	dbus_bool_t immutable;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	immutable = service->immutable;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Immutable",
					DBUS_TYPE_BOOLEAN, &immutable);
}

static void roaming_changed(struct connman_service *service)
{
	dbus_bool_t roaming;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	roaming = service->roaming;
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Roaming",
					DBUS_TYPE_BOOLEAN, &roaming);
}

static void service_boolean_changed(struct connman_service *service,
	const struct connman_service_boolean_property *prop)
{
	dbus_bool_t value;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	value = prop->value(service);
	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, prop->name,
				DBUS_TYPE_BOOLEAN, &value);
}

static void service_append_boolean(struct connman_service *service,
			const struct connman_service_boolean_property *prop,
			DBusMessageIter *dict)
{
	dbus_bool_t value = prop->value(service);
	connman_dbus_dict_append_basic(dict, prop->name,
				DBUS_TYPE_BOOLEAN, &value);
}

static gboolean service_autoconnect_value(struct connman_service *service)
{
	return service->autoconnect;
}

static gboolean is_available(struct connman_service *service)
{
	return service->network || service->provider;
}

static gboolean service_saved_value(struct connman_service *service)
{
	return !service->new_service;
}

static const struct connman_service_boolean_property service_autoconnect =
	{ "AutoConnect", service_autoconnect_value };
static const struct connman_service_boolean_property service_available =
	{ PROP_AVAILABLE, is_available };
static const struct connman_service_boolean_property service_saved =
	{ PROP_SAVED, service_saved_value };

#define autoconnect_changed(s) service_boolean_changed(s, &service_autoconnect)

static void service_set_new_service(struct connman_service *service,
							bool new_service)
{
	const bool newval = new_service ? true : false;
	if (service->new_service != newval) {
		service->new_service = newval;
		service_boolean_changed(service, &service_saved);
	}
}

bool connman_service_set_autoconnect(struct connman_service *service,
							bool autoconnect)
{
	if (service->autoconnect == autoconnect)
		return false;

	service->autoconnect = autoconnect;
	service_boolean_changed(service, &service_autoconnect);

	if (service->network)
		connman_network_autoconnect_changed(service->network,
							service->autoconnect);

	return true;
}

static void append_security(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *str;

	str = __connman_service_security2string(service->security);
	if (str)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &str);

	/*
	 * Some access points incorrectly advertise WPS even when they
	 * are configured as open or no security, so filter
	 * appropriately.
	 */
	if (service->wps) {
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			str = "wps";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
			break;
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_8021X:
			break;
		}

		if (service->wps_advertizing) {
			str = "wps_advertising";
			dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &str);
		}
	}
}

static void security_changed(struct connman_service *service)
{
	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Security",
				DBUS_TYPE_STRING, append_security, service);
}

static void append_ethernet(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv4,
									iter);
	else if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ethernet(service->ipconfig_ipv6,
									iter);
}

static void append_ipv4(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv4))
		return;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4(service->ipconfig_ipv4, iter);
}

static void append_ipv6(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state_ipv6))
		return;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6(service->ipconfig_ipv6, iter,
						service->ipconfig_ipv4);
}

static void append_ipv4config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv4)
		__connman_ipconfig_append_ipv4config(service->ipconfig_ipv4,
							iter);
}

static void append_ipv6config(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (service->ipconfig_ipv6)
		__connman_ipconfig_append_ipv6config(service->ipconfig_ipv6,
							iter);
}

static void append_nameservers(DBusMessageIter *iter,
		struct connman_service *service, char **servers)
{
	int i;
	bool available = true;

	for (i = 0; servers[i]; i++) {
		if (service)
			available = nameserver_available(service,
						CONNMAN_IPCONFIG_TYPE_ALL,
						servers[i]);

		if (available)
			dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &servers[i]);
	}
}

static void append_dns(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state))
		return;

	if (service->nameservers_config) {
		append_nameservers(iter, service, service->nameservers_config);
		return;
	} else {
		if (service->nameservers)
			append_nameservers(iter, service,
					service->nameservers);

		if (service->nameservers_auto)
			append_nameservers(iter, service,
					service->nameservers_auto);

		if (!service->nameservers && !service->nameservers_auto) {
			char **ns;

			DBG("append fallback nameservers");

			ns = connman_setting_get_string_list("FallbackNameservers");
			if (ns)
				append_nameservers(iter, service, ns);
		}
	}
}

static void append_dnsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!service->nameservers_config)
		return;

	append_nameservers(iter, NULL, service->nameservers_config);
}

static void append_ts(DBusMessageIter *iter, void *user_data)
{
	GSList *list = user_data;

	while (list) {
		char *timeserver = list->data;

		if (timeserver)
			dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
					&timeserver);

		list = g_slist_next(list);
	}
}

static void append_tsconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->timeservers_config)
		return;

	for (i = 0; service->timeservers_config[i]; i++) {
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING,
				&service->timeservers_config[i]);
	}
}

static void append_domainconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->domains)
		return;

	for (i = 0; service->domains[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domains[i]);
}

static void append_domain(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state) &&
				!is_connecting(service->state))
		return;

	if (service->domains)
		append_domainconfig(iter, user_data);
	else if (service->domainname)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->domainname);
}

static void append_proxies(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->proxies)
		return;

	for (i = 0; service->proxies[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->proxies[i]);
}

static void append_excludes(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	int i;

	if (!service->excludes)
		return;

	for (i = 0; service->excludes[i]; i++)
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &service->excludes[i]);
}

static void append_proxy(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	enum connman_service_proxy_method proxy;
	const char *pac = NULL;
	const char *method = proxymethod2string(
		CONNMAN_SERVICE_PROXY_METHOD_DIRECT);

	if (!is_connected(service->state))
		return;

	proxy = connman_service_get_proxy_method(service);

	switch (proxy) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		goto done;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		connman_dbus_dict_append_array(iter, "Servers",
					DBUS_TYPE_STRING, append_proxies,
					service);

		connman_dbus_dict_append_array(iter, "Excludes",
					DBUS_TYPE_STRING, append_excludes,
					service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		/* Maybe DHCP, or WPAD,  has provided an url for a pac file */
		if (service->ipconfig_ipv4)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv4);
		else if (service->ipconfig_ipv6)
			pac = __connman_ipconfig_get_proxy_autoconfig(
				service->ipconfig_ipv6);

		if (!service->pac && !pac)
			goto done;

		if (service->pac)
			pac = service->pac;

		connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &pac);
		break;
	}

	method = proxymethod2string(proxy);

done:
	connman_dbus_dict_append_basic(iter, "Method",
					DBUS_TYPE_STRING, &method);
}

static void append_proxyconfig(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;
	const char *method;

	if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN)
		return;

	switch (service->proxy_config) {
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		return;
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (service->proxies)
			connman_dbus_dict_append_array(iter, "Servers",
						DBUS_TYPE_STRING,
						append_proxies, service);

		if (service->excludes)
			connman_dbus_dict_append_array(iter, "Excludes",
						DBUS_TYPE_STRING,
						append_excludes, service);
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		if (service->pac)
			connman_dbus_dict_append_basic(iter, "URL",
					DBUS_TYPE_STRING, &service->pac);
		break;
	}

	method = proxymethod2string(service->proxy_config);

	connman_dbus_dict_append_basic(iter, "Method",
				DBUS_TYPE_STRING, &method);
}

static void append_provider(DBusMessageIter *iter, void *user_data)
{
	struct connman_service *service = user_data;

	if (!is_connected(service->state))
		return;

	if (service->provider)
		__connman_provider_append_properties(service->provider, iter);
}


static void settings_changed(struct connman_service *service,
				struct connman_ipconfig *ipconfig)
{
	enum connman_ipconfig_type type;

	type = __connman_ipconfig_get_config_type(ipconfig);

	__connman_notifier_ipconfig_changed(service, ipconfig);

	if (!allow_property_changed(service))
		return;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv4",
					append_ipv4, service);
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "IPv6",
					append_ipv6, service);
}

static void ipv4_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv4.Configuration",
							append_ipv4config,
							service);
}

void __connman_service_notify_ipv4_configuration(
					struct connman_service *service)
{
	if (!service)
		return;

	ipv4_configuration_changed(service);
}

static void ipv6_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE,
							"IPv6.Configuration",
							append_ipv6config,
							service);
}

static void dns_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Nameservers",
					DBUS_TYPE_STRING, append_dns, service);
}

static void dns_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	dns_changed(service);
}

static void domain_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE, "Domains",
				DBUS_TYPE_STRING, append_domain, service);
}

static void domain_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
				CONNMAN_SERVICE_INTERFACE,
				"Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);
}

static void proxy_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Proxy",
							append_proxy, service);
}

static void proxy_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
			CONNMAN_SERVICE_INTERFACE, "Proxy.Configuration",
						append_proxyconfig, service);

	proxy_changed(service);
}

static void mdns_changed(struct connman_service *service)
{
	dbus_bool_t mdns = service->mdns;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS", DBUS_TYPE_BOOLEAN,
			&mdns);
}

static void mdns_configuration_changed(struct connman_service *service)
{
	dbus_bool_t mdns_config = service->mdns_config;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, "mDNS.Configuration",
			DBUS_TYPE_BOOLEAN, &mdns_config);
}

static int set_mdns(struct connman_service *service,
			bool enabled)
{
	int result;

	result = __connman_resolver_set_mdns(
			__connman_service_get_index(service), enabled);

	if (result == 0) {
		if (service->mdns != enabled) {
			service->mdns = enabled;
			mdns_changed(service);
		}
	}

	return result;
}

static void timeservers_configuration_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE,
			"Timeservers.Configuration",
			DBUS_TYPE_STRING,
			append_tsconfig, service);
}

static void link_changed(struct connman_service *service)
{
	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_dict(service->path,
					CONNMAN_SERVICE_INTERFACE, "Ethernet",
						append_ethernet, service);
}

static void stats_append_counters(DBusMessageIter *dict,
			struct connman_stats_data *stats,
			uint64_t stats_time,
			struct connman_stats_counter_data *counters,
			bool append_all)
{
	gboolean skip_time = TRUE;

	if (counters->rx_packets != stats->rx_packets || append_all) {
		counters->rx_packets = stats->rx_packets;
		connman_dbus_dict_append_basic(dict, "RX.Packets",
					DBUS_TYPE_UINT64, &stats->rx_packets);
		skip_time = FALSE;
	}

	if (counters->tx_packets != stats->tx_packets || append_all) {
		counters->tx_packets = stats->tx_packets;
		connman_dbus_dict_append_basic(dict, "TX.Packets",
					DBUS_TYPE_UINT64, &stats->tx_packets);
		skip_time = FALSE;
	}

	if (counters->rx_bytes != stats->rx_bytes || append_all) {
		counters->rx_bytes = stats->rx_bytes;
		connman_dbus_dict_append_basic(dict, "RX.Bytes",
					DBUS_TYPE_UINT64, &stats->rx_bytes);
		skip_time = FALSE;
	}

	if (counters->tx_bytes != stats->tx_bytes || append_all) {
		counters->tx_bytes = stats->tx_bytes;
		connman_dbus_dict_append_basic(dict, "TX.Bytes",
					DBUS_TYPE_UINT64, &stats->tx_bytes);
		skip_time = FALSE;
	}

	if (counters->rx_errors != stats->rx_errors || append_all) {
		counters->rx_errors = stats->rx_errors;
		connman_dbus_dict_append_basic(dict, "RX.Errors",
					DBUS_TYPE_UINT64, &stats->rx_errors);
		skip_time = FALSE;
	}

	if (counters->tx_errors != stats->tx_errors || append_all) {
		counters->tx_errors = stats->tx_errors;
		connman_dbus_dict_append_basic(dict, "TX.Errors",
					DBUS_TYPE_UINT64, &stats->tx_errors);
		skip_time = FALSE;
	}

	if (counters->rx_dropped != stats->rx_dropped || append_all) {
		counters->rx_dropped = stats->rx_dropped;
		connman_dbus_dict_append_basic(dict, "RX.Dropped",
					DBUS_TYPE_UINT64, &stats->rx_dropped);
		skip_time = FALSE;
	}

	if (counters->tx_dropped != stats->tx_dropped || append_all) {
		counters->tx_dropped = stats->tx_dropped;
		connman_dbus_dict_append_basic(dict, "TX.Dropped",
					DBUS_TYPE_UINT64, &stats->tx_dropped);
		skip_time = FALSE;
	}

	if (!skip_time && (counters->time != stats_time || append_all)) {
		counters->time = stats_time;
		connman_dbus_dict_append_basic(dict, "Time",
					DBUS_TYPE_UINT64, &stats_time);
	}
}

static void stats_append(struct connman_service *service,
				const char *counter,
				struct connman_stats_counter *counters,
				bool append_all)
{
	DBusMessageIter array, dict;
	DBusMessage *msg;
	struct connman_stats_data data;

	DBG("service %p counter %s", service, counter);

	msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
	if (!msg)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH,
				&service->path, DBUS_TYPE_INVALID);

	dbus_message_iter_init_append(msg, &array);

	/* home counter */
	connman_dbus_dict_open(&array, &dict);
	__connman_stats_get(service->stats, &data);
	stats_append_counters(&dict, &data,
		service->stats_update_time, &counters->stats,
		append_all);

	connman_dbus_dict_close(&array, &dict);

	/* roaming counter */
	connman_dbus_dict_open(&array, &dict);
	__connman_stats_get(service->stats_roaming, &data);
	stats_append_counters(&dict, &data,
		service->stats_update_time, &counters->stats_roaming,
		append_all);

	connman_dbus_dict_close(&array, &dict);

	__connman_counter_send_usage(counter, msg);
}

void __connman_service_notify(struct connman_service *service,
			const struct connman_stats_data *data)
{
	GHashTableIter iter;
	gpointer key, value;
	struct connman_stats *stats;

	if (!service)
		return;

	if (!is_connected(service->state))
		return;

	stats = stats_get(service);
	service->stats_update_time = g_timer_elapsed(service->stats_timer, 0);
	if (!__connman_stats_update(stats, data))
		return;

	DBG("service %p", service);

	g_hash_table_iter_init(&iter, service->counter_table);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		const char *counter = key;
		struct connman_stats_counter *counters = value;

		stats_append(service, counter, counters, counters->append_all);
		counters->append_all = false;
	}
}

int __connman_service_counter_register(const char *counter)
{
	struct connman_service *service;
	GList *list;
	struct connman_stats_counter *counters;

	DBG("counter %s", counter);

	counter_list = g_slist_prepend(counter_list, (gpointer)counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters)
			return -ENOMEM;

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
					counters);
	}

	service_send_initial_stats(counter);
	return 0;
}

static void service_send_initial_stats(const char *counter)
{
	char **services = connman_storage_get_services();
	char **s;

	if (!services)
		return;

	for (s = services; *s; s++) {
		DBusMessage *msg;
		DBusMessageIter array, dict;
		struct connman_stats_data home, roaming;
		struct connman_stats_counter_data counters;
		struct connman_service *service;
		const char *identifier = *s;
		char *path;
		char *tmp = NULL;

		msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
		if (!msg)
			continue;

		service = g_hash_table_lookup(service_hash, identifier);

		if (service) {
			path = service->path;
			__connman_stats_get(service->stats, &home);
			__connman_stats_get(service->stats_roaming, &roaming);
		} else {
			path = tmp = g_strconcat(CONNMAN_PATH, "/service/",
							identifier, NULL);
			__connman_stats_read(identifier, FALSE, &home);
			__connman_stats_read(identifier, TRUE, &roaming);
		}

		dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);
		dbus_message_iter_init_append(msg, &array);

		/* Home counter */
		connman_dbus_dict_open(&array, &dict);
		bzero(&counters, sizeof(counters));
		stats_append_counters(&dict, &home, 0, &counters, TRUE);
		connman_dbus_dict_close(&array, &dict);

		/* Roaming counter */
		connman_dbus_dict_open(&array, &dict);
		bzero(&counters, sizeof(counters));
		stats_append_counters(&dict, &roaming, 0, &counters, TRUE);
		connman_dbus_dict_close(&array, &dict);

		g_free(tmp);
		__connman_counter_send_usage(counter, msg);
	}

	g_strfreev(services);
}

void __connman_service_counter_reset_all(const char *type)
{
	size_t typelen = strlen(type);
	char **services = connman_storage_get_services();
	char **s;

	if (!services)
		return;

	for (s = services; *s; s++) {
		struct connman_service *service;
		const char *identifier = *s;

		if (strncmp(identifier, type, typelen))
			continue;

		service = g_hash_table_lookup(service_hash, identifier);

		if (service) {
			connman_service_ref(service);
			reset_stats(service);
			connman_service_unref(service);
		} else {
			__connman_stats_clear(identifier, TRUE);
			__connman_stats_clear(identifier, FALSE);
		}
	}

	g_strfreev(services);
}

void __connman_service_set_disabled(struct connman_service *service,
						gboolean disabled)
{
	if (service->disabled != disabled) {
		service->disabled = disabled;
		DBG("%p %s %s", service, service->name,
					disabled ? "disabled" : "enabled");
		if (disabled) {
			__connman_service_disconnect(service);
		} else {
			__connman_service_auto_connect
				(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		}
	}
}

void __connman_service_counter_unregister(const char *counter)
{
	struct connman_service *service;
	GList *list;

	DBG("counter %s", counter);

	for (list = service_list; list; list = list->next) {
		service = list->data;

		g_hash_table_remove(service->counter_table, counter);
	}

	counter_list = g_slist_remove(counter_list, counter);
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	GList *list;
	int ret = 0;

	for (list = service_list; list && ret == 0; list = list->next)
		ret = cb((struct connman_service *)list->data, user_data);

	return ret;
}

static void append_wifi_ext_info(DBusMessageIter *dict,
					struct connman_network *network)
{
	unsigned int maxrate;
	uint16_t frequency;
	const char *enc_mode;
	const char *bssid;

	bssid = connman_network_get_bssid_str(network);
	maxrate = connman_network_get_maxrate(network);
	frequency = connman_network_get_frequency(network);
	enc_mode = connman_network_get_enc_mode(network);

	connman_dbus_dict_append_basic(dict, "BSSID",
					DBUS_TYPE_STRING, &bssid);
	connman_dbus_dict_append_basic(dict, "MaxRate",
					DBUS_TYPE_UINT32, &maxrate);
	connman_dbus_dict_append_basic(dict, "Frequency",
					DBUS_TYPE_UINT16, &frequency);
	connman_dbus_dict_append_basic(dict, "EncryptionMode",
					DBUS_TYPE_STRING, &enc_mode);
}

/*
 * Emits ProperyChanged events for those properties that are stored in
 * struct connman_network (i.e. not copied to struct connman_service).
 */
int __connman_service_network_property_changed(struct connman_service *service,
							const char *name)
{
	int type;
	dbus_int16_t u16;
	dbus_int32_t u32;
	const char *str = NULL;
	void *value = NULL;

	if (!allow_property_changed(service))
		return -EACCES;

	if (!service->network)
		return -ENOLINK;

	if (!g_strcmp0(name, "BSSID")) {
		type = DBUS_TYPE_STRING;
		str = connman_network_get_bssid_str(service->network);
		value = &str;
	} else if (!g_strcmp0(name, "MaxRate")) {
		type = DBUS_TYPE_UINT32;
		u32 = connman_network_get_maxrate(service->network);
		value = &u32;
	} else if (!g_strcmp0(name, "Frequency")) {
		service_save(service); /* Why are we saving the frequency? */
		type = DBUS_TYPE_UINT16;
		u16 = connman_network_get_frequency(service->network);
		value = &u16;
	} else if (!g_strcmp0(name, "EncryptionMode")) {
		type = DBUS_TYPE_STRING;
		str = connman_network_get_enc_mode(service->network);
		value = &str;
	} else {
		DBG("unsupported network property %s", name);
		return -EINVAL;
	}

	if (type == DBUS_TYPE_STRING && !str)
		str = "";

	connman_dbus_property_changed_basic(service->path,
			CONNMAN_SERVICE_INTERFACE, name, type, value);
	return 0;
}

static void string_changed(struct connman_service *service,
				const char *name, const char *value)
{
	if (!allow_property_changed(service))
		return;

	if (!value)
		value = "";

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, name,
				DBUS_TYPE_STRING, &value);
}

static gboolean can_get_property(struct connman_service *service,
				const char *name, const char *sender,
				enum connman_access default_access)
{
	return __connman_access_service_policy_check(service->policy,
			CONNMAN_ACCESS_SERVICE_GET_PROPERTY, name,
			sender, default_access) == CONNMAN_ACCESS_ALLOW;
}

static gboolean check_set_property(struct connman_service *service,
				const char *name, DBusMessage *msg,
				enum connman_access default_access)
{
	return __connman_access_service_policy_check(service->policy,
			CONNMAN_ACCESS_SERVICE_SET_PROPERTY, name,
			dbus_message_get_sender(msg),
			default_access) == CONNMAN_ACCESS_ALLOW;
}

static gboolean can_set_property(struct connman_service *service,
				const char *name, DBusMessage *msg,
				enum connman_access default_access)
{
	if (check_set_property(service, name, msg, default_access)) {
		return TRUE;
	} else {
		connman_warn("%s is not allowed to set %s for %s",
			dbus_message_get_sender(msg), name, service->path);
		return FALSE;
	}
}

static gboolean can_call(struct connman_service *service,
			enum connman_access_service_methods method,
			DBusMessage *msg, enum connman_access default_access)
{
	return __connman_access_service_policy_check(service->policy,
			method, NULL, dbus_message_get_sender(msg),
			default_access) == CONNMAN_ACCESS_ALLOW;
}

static void restricted_string_changed(struct connman_service *service,
				const char *name, const char *value,
				enum connman_access default_get_access)
{
	if (can_get_property(service, name, NULL, default_get_access)) {
		/* Access is wide open, send the value */
		string_changed(service, name, value);
	} else if (allow_property_changed(service)) {
		DBusMessage *signal;
		DBusMessageIter it;

		/* We can only broadcast the name */
		signal = dbus_message_new_signal(service->path,
					CONNMAN_SERVICE_INTERFACE,
					"RestrictedPropertyChanged");
		dbus_message_iter_init_append(signal, &it);
		dbus_message_iter_append_basic(&it, DBUS_TYPE_STRING, &name);
		g_dbus_send_message(connection, signal);
	}
}

static void append_restricted_string(DBusMessageIter *dict,
		struct connman_service *service, const char *name,
		const char *str, enum connman_access default_access)
{
	const char *sender = g_dbus_get_current_sender();

	if (!can_get_property(service, name, sender, default_access))
		return;

	if (!str)
		str = "";

	connman_dbus_dict_append_basic(dict, name, DBUS_TYPE_STRING, &str);
}

static DBusMessage *reply_string(DBusMessage *msg, const char *str)
{
	DBusMessage *reply = dbus_message_new_method_return(msg);
	DBusMessageIter iter, value;

	if (!str)
		str = "";

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &str);
	dbus_message_iter_close_container(&iter, &value);
	return reply;
}

static DBusMessage *check_and_reply_string(DBusMessage *msg,
		struct connman_service *service, const char *name,
		const char *value, enum connman_access default_access)
{
	const char *sender = dbus_message_get_sender(msg);

	if (can_get_property(service, name, sender, default_access)) {
		DBG("sending %s to %s", name, sender);
		return reply_string(msg, value);
	} else {
		DBG("%s has no access to %s", sender, name);
		return __connman_error_permission_denied(msg);
	}
}

static DBusMessage *get_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	const char *name;
	DBusMessageIter iter;

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);

	if (!g_strcmp0(name, PROP_PASSPHRASE)) {
		return check_and_reply_string(msg, service, name,
				service->passphrase, GET_PASSPHRASE_ACCESS);
	} else if (!g_strcmp0(name, PROP_ACCESS)) {
		return check_and_reply_string(msg, service, name,
			service_get_access(service), GET_ACCESS_ACCESS);
	} else if (!g_strcmp0(name, PROP_DEFAULT_ACCESS)) {
		return check_and_reply_string(msg, service, name,
				__connman_access_default_service_policy_str(),
				GET_DEFAULT_ACCESS_ACCESS);
	} else if (!g_strcmp0(name, PROP_IDENTITY)) {
		return check_and_reply_string(msg, service, name,
				service->identity, GET_IDENTITY_ACCESS);
	} else if (!g_strcmp0(name, PROP_EAP)) {
		return check_and_reply_string(msg, service, name,
				service->eap, GET_EAP_ACCESS);
	} else if (!g_strcmp0(name, PROP_PHASE2)) {
		return check_and_reply_string(msg, service, name,
				service->phase2, GET_PHASE2_ACCESS);
	} else if (!g_strcmp0(name, PROP_CA_CERT)) {
		return check_and_reply_string(msg, service, name,
				service->ca_cert, GET_CA_CERT_ACCESS);
	} else if (!g_strcmp0(name, PROP_CA_CERT_FILE)) {
		return check_and_reply_string(msg, service, name,
					service->ca_cert_file,
					GET_CA_CERT_FILE_ACCESS);
	} else if (!g_strcmp0(name, PROP_DOMAIN_SUFFIX_MATCH)) {
		return check_and_reply_string(msg, service, name,
					service->domain_suffix_match,
					GET_DOMAIN_SUFFIX_MATCH_ACCESS);
	} else if (!g_strcmp0(name, PROP_CLIENT_CERT)) {
		return check_and_reply_string(msg, service, name,
				service->client_cert, GET_CLIENT_CERT_ACCESS);
	} else if (!g_strcmp0(name, PROP_CLIENT_CERT_FILE)) {
		return check_and_reply_string(msg, service, name,
					service->client_cert_file,
					GET_CLIENT_CERT_ACCESS);
	} else if (!g_strcmp0(name, PROP_PRIVATE_KEY)) {
		return check_and_reply_string(msg, service, name,
				service->private_key, GET_PRIVATE_KEY_ACCESS);
	} else if (!g_strcmp0(name, PROP_PRIVATE_KEY_FILE)) {
		return check_and_reply_string(msg, service, name,
					service->private_key_file,
					GET_PRIVATE_KEY_ACCESS);
	} else if (!g_strcmp0(name, PROP_PRIVATE_KEY_PASSPHRASE)) {
		return check_and_reply_string(msg, service, name,
					service->private_key_passphrase,
					GET_PRIVATE_KEY_PASSPHRASE_ACCESS);
	} else if (!g_strcmp0(name, PROP_ANONYMOUS_IDENTITY)) {
		return check_and_reply_string(msg, service, name,
					service->anonymous_identity,
					GET_ANONYMOUS_IDENTITY_ACCESS);
	}

	DBG("%s requested %s - why?", dbus_message_get_sender(msg), name);
	return __connman_error_invalid_arguments(msg);
}

static void append_properties(DBusMessageIter *dict, dbus_bool_t limited,
					struct connman_service *service)
{
	dbus_bool_t val;
	const char *str;
	GSList *list;

	str = __connman_service_type2string(service->type);
	if (str)
		connman_dbus_dict_append_basic(dict, "Type",
						DBUS_TYPE_STRING, &str);

	connman_dbus_dict_append_array(dict, "Security",
				DBUS_TYPE_STRING, append_security, service);

	str = state2string(service->state);
	if (str)
		connman_dbus_dict_append_basic(dict, "State",
						DBUS_TYPE_STRING, &str);

	str = error2string(service->error);
	if (str)
		connman_dbus_dict_append_basic(dict, "Error",
						DBUS_TYPE_STRING, &str);

	if (service->strength > 0)
		connman_dbus_dict_append_basic(dict, "Strength",
					DBUS_TYPE_BYTE, &service->strength);

	val = service->favorite;
	connman_dbus_dict_append_basic(dict, "Favorite",
					DBUS_TYPE_BOOLEAN, &val);

	val = service->immutable;
	connman_dbus_dict_append_basic(dict, "Immutable",
					DBUS_TYPE_BOOLEAN, &val);

	val = service->autoconnect;
	connman_dbus_dict_append_basic(dict, "AutoConnect",
				DBUS_TYPE_BOOLEAN, &val);

	if (service->name)
		connman_dbus_dict_append_basic(dict, "Name",
					DBUS_TYPE_STRING, &service->name);

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		val = service->roaming;
		connman_dbus_dict_append_basic(dict, "Roaming",
					DBUS_TYPE_BOOLEAN, &val);

		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->network != NULL)
			append_wifi_ext_info(dict, service->network);

		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);

		val = service->hidden_service;
		connman_dbus_dict_append_basic(dict, "Hidden",
						DBUS_TYPE_BOOLEAN, &val);

		if (service->anonymous_identity)
			connman_dbus_dict_append_basic(dict,
						"AnonymousIdentity",
						DBUS_TYPE_STRING,
						&service->anonymous_identity);

		append_restricted_string(dict, service, PROP_PASSPHRASE,
				service->passphrase, GET_PASSPHRASE_ACCESS);
		append_restricted_string(dict, service, PROP_IDENTITY,
				service->identity, GET_IDENTITY_ACCESS);
		append_restricted_string(dict, service, PROP_EAP,
				service->eap, GET_EAP_ACCESS);
		append_restricted_string(dict, service, PROP_PHASE2,
				service->phase2, GET_PHASE2_ACCESS);
		append_restricted_string(dict, service, PROP_CA_CERT,
				service->ca_cert, GET_CA_CERT_ACCESS);
		append_restricted_string(dict, service, PROP_CA_CERT_FILE,
						service->ca_cert_file,
						GET_CA_CERT_FILE_ACCESS);
		append_restricted_string(dict, service,
					PROP_DOMAIN_SUFFIX_MATCH,
					service->domain_suffix_match,
					GET_DOMAIN_SUFFIX_MATCH_ACCESS);
		append_restricted_string(dict, service, PROP_CLIENT_CERT,
				service->client_cert, GET_CLIENT_CERT_ACCESS);
		append_restricted_string(dict, service, PROP_CLIENT_CERT_FILE,
						service->client_cert_file,
						GET_CLIENT_CERT_ACCESS);
		append_restricted_string(dict, service, PROP_PRIVATE_KEY,
				service->private_key, GET_PRIVATE_KEY_ACCESS);
		append_restricted_string(dict, service, PROP_PRIVATE_KEY_FILE,
						service->private_key_file,
						GET_PRIVATE_KEY_ACCESS);
		append_restricted_string(dict, service,
				PROP_PRIVATE_KEY_PASSPHRASE,
				service->private_key_passphrase,
				GET_PRIVATE_KEY_PASSPHRASE_ACCESS);
		append_restricted_string(dict, service,
				PROP_ANONYMOUS_IDENTITY,
				service->anonymous_identity,
				GET_ANONYMOUS_IDENTITY_ACCESS);
		break;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GADGET:
		connman_dbus_dict_append_dict(dict, "Ethernet",
						append_ethernet, service);
		break;
	}

	connman_dbus_dict_append_dict(dict, "IPv4", append_ipv4, service);

	connman_dbus_dict_append_dict(dict, "IPv4.Configuration",
						append_ipv4config, service);

	connman_dbus_dict_append_dict(dict, "IPv6", append_ipv6, service);

	connman_dbus_dict_append_dict(dict, "IPv6.Configuration",
						append_ipv6config, service);

	connman_dbus_dict_append_array(dict, "Nameservers",
				DBUS_TYPE_STRING, append_dns, service);

	connman_dbus_dict_append_array(dict, "Nameservers.Configuration",
				DBUS_TYPE_STRING, append_dnsconfig, service);

	if (service->state == CONNMAN_SERVICE_STATE_READY ||
			service->state == CONNMAN_SERVICE_STATE_ONLINE)
		list = __connman_timeserver_get_all(service);
	else
		list = NULL;

	connman_dbus_dict_append_array(dict, "Timeservers",
				DBUS_TYPE_STRING, append_ts, list);

	g_slist_free_full(list, g_free);

	connman_dbus_dict_append_array(dict, "Timeservers.Configuration",
				DBUS_TYPE_STRING, append_tsconfig, service);

	connman_dbus_dict_append_array(dict, "Domains",
				DBUS_TYPE_STRING, append_domain, service);

	connman_dbus_dict_append_array(dict, "Domains.Configuration",
				DBUS_TYPE_STRING, append_domainconfig, service);

	connman_dbus_dict_append_dict(dict, "Proxy", append_proxy, service);

	connman_dbus_dict_append_dict(dict, "Proxy.Configuration",
						append_proxyconfig, service);

	val = service->mdns;
	connman_dbus_dict_append_basic(dict, "mDNS", DBUS_TYPE_BOOLEAN,
				&val);

	val = service->mdns_config;
	connman_dbus_dict_append_basic(dict, "mDNS.Configuration",
				DBUS_TYPE_BOOLEAN, &val);

	connman_dbus_dict_append_dict(dict, "Provider",
						append_provider, service);

	if (service->network)
		connman_network_append_acddbus(dict, service->network);

	service_append_boolean(service, &service_available, dict);
	service_append_boolean(service, &service_saved, dict);
	append_restricted_string(dict, service, PROP_ACCESS,
				service_get_access(service),
				GET_ACCESS_ACCESS);
	append_restricted_string(dict, service, PROP_DEFAULT_ACCESS,
				__connman_access_default_service_policy_str(),
				GET_DEFAULT_ACCESS_ACCESS);
}

static void append_properties_updated(DBusMessageIter *dict,
					struct connman_service *service)
{
	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_P2P:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_GADGET:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		if (service->network)
			append_wifi_ext_info(dict, service->network);
		break;
	}
}

static void append_struct_service(DBusMessageIter *iter,
		connman_dbus_append_cb_t function,
		struct connman_service *service)
{
	DBusMessageIter entry, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&service->path);

	connman_dbus_dict_open(&entry, &dict);
	if (function)
		function(&dict, service);
	connman_dbus_dict_close(&entry, &dict);

	dbus_message_iter_close_container(iter, &entry);
}

static void append_dict_properties(DBusMessageIter *dict, void *user_data)
{
	struct connman_service *service = user_data;

	append_properties(dict, TRUE, service);
}

static void append_struct(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	DBusMessageIter *iter = user_data;

	if (!service->path)
		return;

	append_struct_service(iter, append_dict_properties, service);
}

static void append_dict_properties_updated(DBusMessageIter *dict,
							void *user_data)
{
	struct connman_service *service = user_data;

	append_properties_updated(dict, service);
}

void __connman_service_list_struct(DBusMessageIter *iter)
{
	g_list_foreach(service_list, append_struct, iter);
}

bool __connman_service_is_hidden(struct connman_service *service)
{
	return service->hidden;
}

bool
__connman_service_is_split_routing(struct connman_service *service)
{
	return service->do_split_routing;
}

bool __connman_service_index_is_split_routing(int index)
{
	struct connman_service *service;

	if (index < 0)
		return true;

	service = __connman_service_lookup_from_index(index);
	if (!service)
		return false;

	return __connman_service_is_split_routing(service);
}

int __connman_service_get_index(struct connman_service *service)
{
	if (!service)
		return -1;

	if (service->network)
		return connman_network_get_index(service->network);
	else if (service->provider)
		return connman_provider_get_index(service->provider);

	return -1;
}

void __connman_service_set_hidden(struct connman_service *service)
{
	if (!service || service->hidden)
		return;

	service->hidden_service = true;
}

void __connman_service_set_hostname(struct connman_service *service,
						const char *hostname)
{
	if (!service || service->hidden)
		return;

	g_free(service->hostname);
	service->hostname = NULL;

	if (hostname && g_str_is_ascii(hostname))
		service->hostname = g_strdup(hostname);
}

const char *__connman_service_get_hostname(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->hostname;
}

void __connman_service_set_domainname(struct connman_service *service,
						const char *domainname)
{
	if (!service || service->hidden)
		return;

	g_free(service->domainname);
	service->domainname = NULL;

	if (domainname && g_str_is_ascii(domainname))
		service->domainname = g_strdup(domainname);

	domain_changed(service);
}

const char *connman_service_get_domainname(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->domains)
		return service->domains[0];
	else
		return service->domainname;
}

const char *connman_service_get_dbuspath(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->path;
}

char **connman_service_get_nameservers(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->nameservers_config)
		return g_strdupv(service->nameservers_config);
	else if (service->nameservers ||
					service->nameservers_auto) {
		int len = 0, len_auto = 0, i;
		char **nameservers;

		if (service->nameservers)
			len = g_strv_length(service->nameservers);
		if (service->nameservers_auto)
			len_auto = g_strv_length(service->nameservers_auto);

		nameservers = g_try_new0(char *, len + len_auto + 1);
		if (!nameservers)
			return NULL;

		for (i = 0; i < len; i++)
			nameservers[i] = g_strdup(service->nameservers[i]);

		for (i = 0; i < len_auto; i++)
			nameservers[i + len] =
				g_strdup(service->nameservers_auto[i]);

		return nameservers;
	}

	return g_strdupv(connman_setting_get_string_list("FallbackNameservers"));
}

char **connman_service_get_timeservers_config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->timeservers_config;
}

char **connman_service_get_timeservers(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->timeservers;
}

void connman_service_set_proxy_method(struct connman_service *service,
					enum connman_service_proxy_method method)
{
	if (!service || service->hidden)
		return;

	service->proxy = method;

	proxy_changed(service);

	if (method != CONNMAN_SERVICE_PROXY_METHOD_AUTO)
		__connman_notifier_proxy_changed(service);
}

enum connman_service_proxy_method connman_service_get_proxy_method(
					struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	if (service->proxy_config != CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN) {
		if (service->proxy_config == CONNMAN_SERVICE_PROXY_METHOD_AUTO &&
				!service->pac)
			return service->proxy;

		return service->proxy_config;
	}

	return service->proxy;
}

char **connman_service_get_proxy_servers(struct connman_service *service)
{
	if (!service)
		return NULL;

	return g_strdupv(service->proxies);
}

char **connman_service_get_proxy_excludes(struct connman_service *service)
{
	if (!service)
		return NULL;

	return g_strdupv(service->excludes);
}

const char *connman_service_get_proxy_url(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->pac;
}

void __connman_service_set_proxy_autoconfig(struct connman_service *service,
							const char *url)
{
	if (!service || service->hidden)
		return;

	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_AUTO;

	if (service->ipconfig_ipv4) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv4, url) < 0)
			return;
	} else if (service->ipconfig_ipv6) {
		if (__connman_ipconfig_set_proxy_autoconfig(
			    service->ipconfig_ipv6, url) < 0)
			return;
	} else
		return;

	proxy_changed(service);

	__connman_notifier_proxy_changed(service);
}

const char *connman_service_get_proxy_autoconfig(struct connman_service *service)
{
	if (!service)
		return NULL;

	if (service->ipconfig_ipv4)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv4);
	else if (service->ipconfig_ipv6)
		return __connman_ipconfig_get_proxy_autoconfig(
						service->ipconfig_ipv6);
	return NULL;
}

void __connman_service_set_timeservers(struct connman_service *service,
				char **timeservers)
{
	int i;

	if (!service)
		return;

	g_strfreev(service->timeservers);
	service->timeservers = NULL;

	for (i = 0; timeservers && timeservers[i]; i++)
		__connman_service_timeserver_append(service, timeservers[i]);
}

int __connman_service_timeserver_append(struct connman_service *service,
						const char *timeserver)
{
	int len;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (service->timeservers) {
		int i;

		for (i = 0; service->timeservers[i]; i++)
			if (g_strcmp0(service->timeservers[i], timeserver) == 0)
				return -EEXIST;

		len = g_strv_length(service->timeservers);
		service->timeservers = g_try_renew(char *, service->timeservers,
							len + 2);
	} else {
		len = 0;
		service->timeservers = g_try_new0(char *, len + 2);
	}

	if (!service->timeservers)
		return -ENOMEM;

	service->timeservers[len] = g_strdup(timeserver);
	service->timeservers[len + 1] = NULL;

	return 0;
}

int __connman_service_timeserver_remove(struct connman_service *service,
						const char *timeserver)
{
	char **servers;
	int len, i, j, found = 0;

	DBG("service %p timeserver %s", service, timeserver);

	if (!timeserver)
		return -EINVAL;

	if (!service->timeservers)
		return 0;

	for (i = 0; service->timeservers &&
					service->timeservers[i]; i++)
		if (g_strcmp0(service->timeservers[i], timeserver) == 0) {
			found = 1;
			break;
		}

	if (found == 0)
		return 0;

	len = g_strv_length(service->timeservers);

	if (len == 1) {
		g_strfreev(service->timeservers);
		service->timeservers = NULL;

		return 0;
	}

	servers = g_try_new0(char *, len);
	if (!servers)
		return -ENOMEM;

	for (i = 0, j = 0; i < len; i++) {
		if (g_strcmp0(service->timeservers[i], timeserver) != 0) {
			servers[j] = g_strdup(service->timeservers[i]);
			if (!servers[j])
				return -ENOMEM;
			j++;
		}
	}
	servers[len - 1] = NULL;

	g_strfreev(service->timeservers);
	service->timeservers = servers;

	return 0;
}

void __connman_service_timeserver_changed(struct connman_service *service,
		GSList *ts_list)
{
	if (!service)
		return;

	if (!allow_property_changed(service))
		return;

	connman_dbus_property_changed_array(service->path,
			CONNMAN_SERVICE_INTERFACE, "Timeservers",
			DBUS_TYPE_STRING, append_ts, ts_list);
}

void __connman_service_set_pac(struct connman_service *service,
					const char *pac)
{
	if (service->hidden)
		return;
	g_free(service->pac);
	service->pac = g_strdup(pac);

	proxy_changed(service);
}

static gboolean set_identity(struct connman_service *service,
					const char *identity)
{
	if (!g_strcmp0(service->identity, identity))
		return FALSE;

	g_free(service->identity);
	service->identity = g_strdup(identity);

	restricted_string_changed(service, PROP_IDENTITY, service->identity,
							GET_IDENTITY_ACCESS);
	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.Identity",
					service->identity);
	return TRUE;
}

void __connman_service_set_identity(struct connman_service *service,
					const char *identity)
{
	if (service->immutable || service->hidden)
		return;

	set_identity(service, identity);
}

void __connman_service_set_anonymous_identity(struct connman_service *service,
						const char *anonymous_identity)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->anonymous_identity);
	service->anonymous_identity = g_strdup(anonymous_identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AnonymousIdentity",
					service->anonymous_identity);
}

void __connman_service_set_subject_match(struct connman_service *service,
						const char *subject_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->subject_match);
	service->subject_match = g_strdup(subject_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.SubjectMatch",
					service->subject_match);
}

void __connman_service_set_altsubject_match(struct connman_service *service,
						const char *altsubject_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->altsubject_match);
	service->altsubject_match = g_strdup(altsubject_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AltSubjectMatch",
					service->altsubject_match);
}

void __connman_service_set_domain_suffix_match(struct connman_service *service,
						const char *domain_suffix_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->domain_suffix_match);
	service->domain_suffix_match = g_strdup(domain_suffix_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.DomainSuffixMatch",
					service->domain_suffix_match);
}

void __connman_service_set_domain_match(struct connman_service *service,
						const char *domain_match)
{
	if (service->immutable || service->hidden)
		return;

	g_free(service->domain_match);
	service->domain_match = g_strdup(domain_match);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.DomainMatch",
					service->domain_match);
}

void __connman_service_set_agent_identity(struct connman_service *service,
						const char *agent_identity)
{
	if (service->hidden)
		return;
	g_free(service->agent_identity);
	service->agent_identity = g_strdup(agent_identity);

	if (service->network)
		connman_network_set_string(service->network,
					"WiFi.AgentIdentity",
					service->agent_identity);
}

int __connman_service_check_passphrase(enum connman_service_security security,
		const char *passphrase)
{
	guint i;
	gsize length;

	if (!passphrase)
		return 0;

	length = strlen(passphrase);

	switch (security) {
	case CONNMAN_SERVICE_SECURITY_UNKNOWN:
	case CONNMAN_SERVICE_SECURITY_NONE:
	case CONNMAN_SERVICE_SECURITY_WPA:
	case CONNMAN_SERVICE_SECURITY_RSN:

		DBG("service security '%s' (%d) not handled",
			__connman_service_security2string(security), security);

		return -EOPNOTSUPP;

	case CONNMAN_SERVICE_SECURITY_PSK:
		/* A raw key is always 64 bytes length,
		 * its content is in hex representation.
		 * A PSK key must be between [8..63].
		 */
		if (length == 64) {
			for (i = 0; i < 64; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length < 8 || length > 63)
			return -ENOKEY;
		break;
	case CONNMAN_SERVICE_SECURITY_WEP:
		/* length of WEP key is 10 or 26
		 * length of WEP passphrase is 5 or 13
		 */
		if (length == 10 || length == 26) {
			for (i = 0; i < length; i++)
				if (!isxdigit((unsigned char)
					      passphrase[i]))
					return -ENOKEY;
		} else if (length != 5 && length != 13)
			return -ENOKEY;
		break;

	case CONNMAN_SERVICE_SECURITY_8021X:
		break;
	}

	return 0;
}

int __connman_service_set_passphrase(struct connman_service *service,
					const char *passphrase)
{
	int err;

	if (service->hidden)
		return -EINVAL;

	if (service->immutable &&
			service->security != CONNMAN_SERVICE_SECURITY_8021X)
		return -EINVAL;

	if (!g_strcmp0(service->passphrase, passphrase))
		return 0;

	err = __connman_service_check_passphrase(service->security, passphrase);

	if (err < 0)
		return err;

	g_free(service->passphrase);
	service->passphrase = g_strdup(passphrase);

	restricted_string_changed(service, PROP_PASSPHRASE,
				service->passphrase, GET_PASSPHRASE_ACCESS);
	if (service->network)
		connman_network_set_string(service->network, "WiFi.Passphrase",
				service->passphrase);

	return 0;
}

const char *__connman_service_get_passphrase(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->passphrase;
}

/*
 * The default access policy is returned and saved as an empty string.
 * This way we can change the defaults and the services that were using
 * the default policy will automatically pick it up.
 */
static const char *service_get_access(struct connman_service *service)
{
	if (!service || !service->access || !service->policy)
		return NULL;

	if (__connman_access_is_default_service_policy(service->policy))
		return NULL;

	return service->access;
}

/* Takes the ownership of the policy */
static void service_set_access_policy(struct connman_service *service,
	const char *access, struct connman_access_service_policy *policy)
{
	g_free(service->access);
	__connman_access_service_policy_free(service->policy);

	/* NULL or empty access string will initialize the default policy */
	service->policy = policy;
	service->access = g_strdup(access);

	restricted_string_changed(service, PROP_ACCESS,
			service_get_access(service), GET_ACCESS_ACCESS);
}

static void service_set_access(struct connman_service *service,
							const char *access)
{
	if (!service)
		return;

	if (!service->access && (!access || !access[0]))
		return;

	if (!g_strcmp0(service->access, access))
		return;

	service_set_access_policy(service, access,
			__connman_access_service_policy_create(access));
}

/* Only allows valid values */
static gboolean set_eap_method(struct connman_service *service,
							const char *method)
{
	if (method && method[0]) {
		if (!g_strcmp0(service->eap, method)) {
			return FALSE;
		} else if (!g_ascii_strcasecmp(method, "peap") ||
				!g_ascii_strcasecmp(method, "peapv0") ||
				!g_ascii_strcasecmp(method, "peapv1") ||
				!g_ascii_strcasecmp(method, "tls") ||
				!g_ascii_strcasecmp(method, "ttls")) {
			g_free(service->eap);
			service->eap = g_strdup(method);
			restricted_string_changed(service, PROP_EAP,
					service->eap, GET_EAP_ACCESS);
			return TRUE;
		}
		DBG("invalid EAP method %s", method);
	}
	if (service->eap) {
		g_free(service->eap);
		service->eap = NULL;
		restricted_string_changed(service, PROP_EAP,
				service->eap, GET_EAP_ACCESS);
		return TRUE;
	}
	return FALSE;
}

static gboolean set_prop_string(struct connman_service *service,
					const char *name,
					char **stored,
					const char *value,
					enum connman_access get_access)
{
	if (value && !value[0])
		value = NULL;
	if (!g_strcmp0(*stored, value))
		return FALSE;

	g_free(*stored);
	*stored = g_strdup(value);
	restricted_string_changed(service, name, *stored, get_access);

	return TRUE;
}

static gboolean set_phase2(struct connman_service *service,
							const char *phase2)
{
	return set_prop_string(service, PROP_PHASE2, &service->phase2, phase2,
							GET_PHASE2_ACCESS);
}

static gboolean set_ca_cert(struct connman_service *service,
							const char *ca_cert)
{
	return set_prop_string(service, PROP_CA_CERT, &service->ca_cert,
						ca_cert, GET_CA_CERT_ACCESS);
}

static gboolean set_ca_cert_file(struct connman_service *service,
						const char *ca_cert_file)
{
	return set_prop_string(service, PROP_CA_CERT_FILE, &service->ca_cert_file,
				ca_cert_file, GET_CA_CERT_FILE_ACCESS);
}

static gboolean set_domain_suffix_match(struct connman_service *service,
						const char *suffix)
{
	return set_prop_string(service, PROP_DOMAIN_SUFFIX_MATCH,
				&service->domain_suffix_match,
				suffix, GET_DOMAIN_SUFFIX_MATCH_ACCESS);
}

static gboolean set_client_cert(struct connman_service *service,
						const char *client_cert)
{
	return set_prop_string(service, PROP_CLIENT_CERT,
					&service->client_cert, client_cert,
					GET_CLIENT_CERT_ACCESS);
}

static gboolean set_client_cert_file(struct connman_service *service,
						const char *client_cert_file)
{
	return set_prop_string(service, PROP_CLIENT_CERT_FILE,
				&service->client_cert_file, client_cert_file,
				GET_CLIENT_CERT_ACCESS);
}

static gboolean set_private_key(struct connman_service *service,
							const char *private_key)
{
	return set_prop_string(service, PROP_PRIVATE_KEY, &service->private_key,
						private_key, GET_PRIVATE_KEY_ACCESS);
}

static gboolean set_private_key_file(struct connman_service *service,
						const char *private_key_file)
{
	return set_prop_string(service, PROP_PRIVATE_KEY_FILE, &service->private_key_file,
				private_key_file, GET_PRIVATE_KEY_ACCESS);
}

static gboolean set_private_key_passphrase(struct connman_service *service,
						const char *private_key_passphrase)
{
	return set_prop_string(service, PROP_PRIVATE_KEY_PASSPHRASE,
				&service->private_key_passphrase,
				private_key_passphrase,
				GET_PRIVATE_KEY_PASSPHRASE_ACCESS);
}

static gboolean set_anonymous_identity(struct connman_service *service,
						const char *anonymous_identity)
{
	return set_prop_string(service, PROP_ANONYMOUS_IDENTITY,
				&service->anonymous_identity,
				anonymous_identity,
				GET_ANONYMOUS_IDENTITY_ACCESS);
}

static DBusMessage *set_restricted_string(struct connman_service *service,
		const char *name, DBusMessageIter *value, DBusMessage *msg,
		gboolean (*set)(struct connman_service *, const char *),
		enum connman_access default_set_access)
{
	/* Name has already been read from the iterator and checked */
	const char *str = NULL;

	if (dbus_message_iter_get_arg_type(value) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(value, &str);

	if (!can_set_property(service, name, msg, default_set_access))
		return __connman_error_permission_denied(msg);

	if (set(service, str))
		service_save(service);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return __connman_error_failed(msg, ENOMEM);

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);
	append_properties(&dict, FALSE, service);
	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static char **remove_empty_strings(char **strv)
{
	int index = 0;
	char **iter = strv;

	while (*iter) {
		if (**iter)
			strv[index++] = *iter;
		else
			g_free(*iter);
		iter++;
	}

	strv[index] = NULL;
	return strv;
}

static int update_proxy_configuration(struct connman_service *service,
				DBusMessageIter *array)
{
	DBusMessageIter dict;
	enum connman_service_proxy_method method;
	GString *servers_str = NULL;
	GString *excludes_str = NULL;
	const char *url = NULL;

	method = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			goto error;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			goto error;

		dbus_message_iter_recurse(&entry, &variant);

		type = dbus_message_iter_get_arg_type(&variant);

		if (g_str_equal(key, "Method")) {
			const char *val;

			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &val);
			method = string2proxymethod(val);
		} else if (g_str_equal(key, "URL")) {
			if (type != DBUS_TYPE_STRING)
				goto error;

			dbus_message_iter_get_basic(&variant, &url);
		} else if (g_str_equal(key, "Servers")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			servers_str = g_string_new(NULL);
			if (!servers_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (servers_str->len > 0)
					g_string_append_printf(servers_str,
							" %s", val);
				else
					g_string_append(servers_str, val);

				dbus_message_iter_next(&str_array);
			}
		} else if (g_str_equal(key, "Excludes")) {
			DBusMessageIter str_array;

			if (type != DBUS_TYPE_ARRAY)
				goto error;

			excludes_str = g_string_new(NULL);
			if (!excludes_str)
				goto error;

			dbus_message_iter_recurse(&variant, &str_array);

			while (dbus_message_iter_get_arg_type(&str_array) ==
							DBUS_TYPE_STRING) {
				char *val = NULL;

				dbus_message_iter_get_basic(&str_array, &val);

				if (excludes_str->len > 0)
					g_string_append_printf(excludes_str,
							" %s", val);
				else
					g_string_append(excludes_str, val);

				dbus_message_iter_next(&str_array);
			}
		}

		dbus_message_iter_next(&dict);
	}

	switch (method) {
	case CONNMAN_SERVICE_PROXY_METHOD_DIRECT:
		break;
	case CONNMAN_SERVICE_PROXY_METHOD_MANUAL:
		if (!servers_str && !service->proxies)
			goto error;

		if (servers_str) {
			g_strfreev(service->proxies);

			if (servers_str->len > 0) {
				char **proxies = g_strsplit_set(
					servers_str->str, " ", 0);
				proxies = remove_empty_strings(proxies);
				service->proxies = proxies;
			} else
				service->proxies = NULL;
		}

		if (excludes_str) {
			g_strfreev(service->excludes);

			if (excludes_str->len > 0) {
				char **excludes = g_strsplit_set(
					excludes_str->str, " ", 0);
				excludes = remove_empty_strings(excludes);
				service->excludes = excludes;
			} else
				service->excludes = NULL;
		}

		if (!service->proxies)
			method = CONNMAN_SERVICE_PROXY_METHOD_DIRECT;

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_AUTO:
		g_free(service->pac);

		if (url && strlen(url) > 0)
			service->pac = g_strstrip(g_strdup(url));
		else
			service->pac = NULL;

		/* if we are connected:
		   - if service->pac == NULL
		   - if __connman_ipconfig_get_proxy_autoconfig(
		   service->ipconfig) == NULL
		   --> We should start WPAD */

		break;
	case CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN:
		goto error;
	}

	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	service->proxy_config = method;

	return 0;

error:
	if (servers_str)
		g_string_free(servers_str, TRUE);

	if (excludes_str)
		g_string_free(excludes_str, TRUE);

	return -EINVAL;
}

static void do_auto_connect(struct connman_service *service,
	enum connman_service_connect_reason reason)
{
	/*
	 * CONNMAN_SERVICE_CONNECT_REASON_NONE must be ignored for VPNs. VPNs
	 * always have reason CONNMAN_SERVICE_CONNECT_REASON_USER/AUTO.
	 */
	if (!service || (service->type == CONNMAN_SERVICE_TYPE_VPN &&
				reason == CONNMAN_SERVICE_CONNECT_REASON_NONE))
		return;

	/*
	 * Run service auto connect for other than VPN services. Afterwards
	 * start also VPN auto connect process.
	 */
	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		__connman_service_auto_connect(reason);
	/* Only user interaction should get VPN connected in failure state. */
	else if (service->state == CONNMAN_SERVICE_STATE_FAILURE &&
				reason != CONNMAN_SERVICE_CONNECT_REASON_USER)
		return;

	vpn_auto_connect();
}

static int reset_ipconfig(struct connman_service *service,
					struct connman_ipconfig *ipconfig,
					struct connman_ipconfig *new_ipconfig,
					enum connman_ipconfig_type type,
					enum connman_ipconfig_method new_method,
					enum connman_service_state state,
					enum connman_service_state *new_state)
{
	enum connman_ipconfig_method old_method;

	if (!service || !ipconfig || !new_ipconfig)
		return -EINVAL;

	old_method = __connman_ipconfig_get_method(ipconfig);

	if (is_connecting(state) || is_connected(state)) {
		__connman_service_nameserver_del_routes(service,
						CONNMAN_IPCONFIG_TYPE_ALL);
		__connman_network_clear_ipconfig(service->network, ipconfig);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->ipconfig_ipv4 = new_ipconfig;
	else if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		service->ipconfig_ipv6 = new_ipconfig;

	if (is_connecting(state) || is_connected(state))
		__connman_ipconfig_enable(new_ipconfig);

	if (new_state && new_method != old_method) {
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			*new_state = service->state_ipv4;
		else
			*new_state = service->state_ipv6;

		settings_changed(service, new_ipconfig);
		address_updated(service, type);

		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	return 0;
}

int __connman_service_reset_ipconfig(struct connman_service *service,
		enum connman_ipconfig_type type, DBusMessageIter *array,
		enum connman_service_state *new_state)
{
	struct connman_ipconfig *ipconfig, *new_ipconfig;
	enum connman_ipconfig_method new_method;
	enum connman_service_state state;
	int err = 0, index;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		ipconfig = service->ipconfig_ipv4;
		state = service->state_ipv4;
		new_method = CONNMAN_IPCONFIG_METHOD_DHCP;
	} else if (type == CONNMAN_IPCONFIG_TYPE_IPV6) {
		ipconfig = service->ipconfig_ipv6;
		state = service->state_ipv6;
		new_method = CONNMAN_IPCONFIG_METHOD_AUTO;
	} else
		return -EINVAL;

	if (!ipconfig)
		return -ENXIO;

	index = __connman_ipconfig_get_index(ipconfig);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		new_ipconfig = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_UNKNOWN);
	else
		new_ipconfig = create_ip6config(service, index);

	if (array) {
		err = __connman_ipconfig_set_config(new_ipconfig, array);
		if (err < 0) {
			__connman_ipconfig_unref(new_ipconfig);
			return err;
		}

		new_method = __connman_ipconfig_get_method(new_ipconfig);
	}

	err = reset_ipconfig(service, ipconfig, new_ipconfig, type, new_method,
							state, new_state);

	__connman_ipconfig_unref(ipconfig);

	DBG("err %d ipconfig %p type %d method %d state %s", err,
		new_ipconfig, type, new_method,
		!new_state  ? "-" : state2string(*new_state));

	return err;
}

int connman_service_reset_ipconfig_to_address(struct connman_service *service,
					enum connman_service_state *new_state,
					enum connman_ipconfig_type type,
					enum connman_ipconfig_method new_method,
					int index,
					const char *address,
					const char *netmask,
					const char *gateway,
					const unsigned char prefix_length)
{
	struct connman_ipconfig *ipconfig;
	struct connman_ipconfig *new_ipconfig;
	enum connman_service_state state;
	int err = 0;

	if (!service)
		return -EINVAL;

	DBG("service %p new state %p type %d new_method %d", service,
					new_state, type, new_method);
	DBG("index %d address %s netmask %s gateway %s prefix length %u",
					index, address, netmask, gateway,
					prefix_length);

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		ipconfig = service->ipconfig_ipv4;
		state = service->state_ipv4;
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		ipconfig = service->ipconfig_ipv6;
		state = service->state_ipv6;
		break;
	default:
		return -EINVAL;
	}

	if (!ipconfig)
		return -ENXIO;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		new_ipconfig = create_ip4config(service, index, new_method);
	else
		new_ipconfig = create_ip6config(service, index);

	err = __connman_ipconfig_set_config_from_address(new_ipconfig,
					new_method, address, netmask, gateway,
					prefix_length);
	if (err) {
		DBG("Failed to set IPv%d config %s/%s/%s with method %d",
				type == CONNMAN_IPCONFIG_TYPE_IPV4 ? 4 : 6,
				address, netmask, gateway, new_method);
		return err;
	}

	err = reset_ipconfig(service, ipconfig, new_ipconfig, type, new_method,
							state, new_state);

	__connman_ipconfig_unref(ipconfig);

	DBG("err %d ipconfig %p type %d method %d state %s", err,
				new_ipconfig, type, new_method,
				!new_state ? "-" : state2string(*new_state));

	err = __connman_network_enable_ipconfig(service->network, new_ipconfig);
	if (err)
		DBG("cannot enable ipconfig %p for network %p", new_ipconfig,
							service->network);

	return err;
}

// TODO: make this into a configuration option
static bool autoconnect_controls_service(struct connman_service *service)
{
	if (!service)
		return false;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_WIFI:
		break;
	case CONNMAN_SERVICE_TYPE_VPN:
		return true;
	}

	return false;
}

static void disable_autoconnect_for_services(struct connman_service *exclude,
	enum connman_service_type type)
{
	GList* list = NULL;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;

		if (service->type != type)
			continue;

		if (service == exclude)
			continue;

		if (connman_service_set_autoconnect(service, false)) {
			service_save(service);
			DBG("disabled autoconnect for %s", service->name);

			if (autoconnect_controls_service(service))
				__connman_service_disconnect(service);
		}
	}
}

void __connman_service_wispr_start(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p type %s", service, __connman_ipconfig_type2string(type));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->online_check_interval_ipv4 =
					online_check_initial_interval;
	else
		service->online_check_interval_ipv6 =
					online_check_initial_interval;

	__connman_wispr_start(service, type);
}

static void set_error(struct connman_service *service,
					enum connman_service_error error);

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("service %p", service);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "AutoConnect")) {
		dbus_bool_t autoconnect;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &autoconnect);

		if (autoconnect && service->type == CONNMAN_SERVICE_TYPE_VPN) {
			/*
			 * Changing the autoconnect flag on VPN to "on" should
			 * have the same effect as user connecting the VPN =
			 * clear previous error and change state to idle.
			 */
			set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

			if (service->state == CONNMAN_SERVICE_STATE_FAILURE) {
				service->state = CONNMAN_SERVICE_STATE_IDLE;
				state_changed(service);
			}

			/* Disable autoconnect for all other VPN providers
			 * if autoconnect is set true. Only one VPN can have
			 * autoconnect enabled.
			 */
			disable_autoconnect_for_services(service,
							service->type);
		}

		if (connman_service_set_autoconnect(service, autoconnect)) {
			/* AutoConnect explicitly set, ensure service is
			 * saved by clearing the new-service flag.
			 */
			service_set_new_service(service, false);

			service_save(service);
			if (autoconnect)
				do_auto_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_AUTO);
			else if (autoconnect_controls_service(service))
				__connman_service_disconnect(service);
		}
	} else if (g_str_equal(name, "Nameservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;
		int index;
		const char *gw;
		int ipv4_refcount_old = 0;
		int ipv6_refcount_old = 0;

		if (__connman_provider_is_immutable(service->provider) ||
				service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		index = __connman_service_get_index(service);
		gw = __connman_ipconfig_get_gateway_from_index(index,
			CONNMAN_IPCONFIG_TYPE_ALL);

		if (gw && strlen(gw)) {
			DBG("nameservers removing for gw %s", gw);
			/*
			 * Do a forced reset of nameserver routes since user set
			 * nameservers overrule any other nameservers set via
			 * other means. Avoid the forced reset if there isn't
			 * any route set.
			 */
			ipv4_refcount_old = service->nameservers_ipv4_refcount;
			DBG("nameservers ipv4 old refcount %d", ipv4_refcount_old);
			if (service->nameservers_ipv4_refcount > 1)
				service->nameservers_ipv4_refcount = 1;

			ipv6_refcount_old = service->nameservers_ipv6_refcount;
			DBG("nameservers ipv6 old refcount %d", ipv6_refcount_old);
			if (service->nameservers_ipv6_refcount > 1)
				service->nameservers_ipv6_refcount = 1;

			if (ipv4_refcount_old || ipv6_refcount_old) {
				DBG("nameservers del routes");
				__connman_service_nameserver_del_routes(service,
						CONNMAN_IPCONFIG_TYPE_ALL);
			}
		}

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		nameserver_remove_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
		g_strfreev(service->nameservers_config);

		if (str->len > 0) {
			char **nameservers, **ns_iter;

			nameservers = g_strsplit_set(str->str, " ", 0);

			for (ns_iter = nameservers; *ns_iter; ns_iter++)
				if (connman_inet_check_ipaddress(*ns_iter) <= 0)
					*ns_iter[0] = '\0';

			nameservers = remove_empty_strings(nameservers);
			service->nameservers_config = nameservers;
		} else {
			service->nameservers_config = NULL;
		}

		g_string_free(str, TRUE);

		if (gw && strlen(gw)) {
			__connman_service_nameserver_add_routes(service, gw);

			/*
			 * After the user set ns routes have been added restore
			 * old refcounters to avoid situation where online
			 * check might remove the routes if this change happens
			 * during the initial resolving of the online check URL.
			 * Set the old value only for the IP type for which the
			 * routes were added.
			 */
			if (service->nameservers_ipv4_refcount) {
				DBG("nameservers ipv4 refcount %d -> %d ",
					service->nameservers_ipv4_refcount,
					ipv4_refcount_old);
				service->nameservers_ipv4_refcount =
							ipv4_refcount_old;
			}

			if (service->nameservers_ipv6_refcount) {
				DBG("nameservers ipv6 refcount %d -> %d ",
					service->nameservers_ipv6_refcount,
					ipv6_refcount_old);
				service->nameservers_ipv6_refcount =
							ipv6_refcount_old;
			}
		}

		nameserver_add_all(service, CONNMAN_IPCONFIG_TYPE_ALL);
		dns_configuration_changed(service);

		cancel_online_check(service);

		start_wispr_when_connected(service);

		service_save(service);
	} else if (g_str_equal(name, "Timeservers.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		g_strfreev(service->timeservers_config);
		service->timeservers_config = NULL;

		if (str->len > 0) {
			char **timeservers = g_strsplit_set(str->str, " ", 0);
			timeservers = remove_empty_strings(timeservers);
			service->timeservers_config = timeservers;
		}

		g_string_free(str, TRUE);

		service_save(service);
		timeservers_configuration_changed(service);

		if (service == connman_service_get_default())
			__connman_timeserver_sync(service);

	} else if (g_str_equal(name, "Domains.Configuration")) {
		DBusMessageIter entry;
		GString *str;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		str = g_string_new(NULL);
		if (!str)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_recurse(&value, &entry);

		while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
			const char *val;
			dbus_message_iter_get_basic(&entry, &val);
			dbus_message_iter_next(&entry);

			if (!val[0])
				continue;

			if (str->len > 0)
				g_string_append_printf(str, " %s", val);
			else
				g_string_append(str, val);
		}

		searchdomain_remove_all(service);
		g_strfreev(service->domains);

		if (str->len > 0) {
			char **domains = g_strsplit_set(str->str, " ", 0);
			domains = remove_empty_strings(domains);
			service->domains = domains;
		} else
			service->domains = NULL;

		g_string_free(str, TRUE);

		searchdomain_add_all(service);
		domain_configuration_changed(service);
		domain_changed(service);

		service_save(service);
	} else if (g_str_equal(name, "Proxy.Configuration")) {
		int err;

		if (!can_set_property(service, name, msg, SET_PROXYCONFIG_ACCESS))
			return __connman_error_permission_denied(msg);

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_ARRAY)
			return __connman_error_invalid_arguments(msg);

		err = update_proxy_configuration(service, &value);

		if (err < 0)
			return __connman_error_failed(msg, -err);

		proxy_configuration_changed(service);

		__connman_notifier_proxy_changed(service);

		cancel_online_check(service);

		start_wispr_when_connected(service);

		service_save(service);
	} else if (g_str_equal(name, "mDNS.Configuration")) {
		dbus_bool_t val;

		if (service->immutable)
			return __connman_error_not_supported(msg);

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &val);
		service->mdns_config = val;

		mdns_configuration_changed(service);

		set_mdns(service, service->mdns_config);

		service_save(service);
	} else if (g_str_equal(name, "IPv4.Configuration") ||
			g_str_equal(name, "IPv6.Configuration")) {

		enum connman_service_state state =
						CONNMAN_SERVICE_STATE_UNKNOWN;
		enum connman_ipconfig_type ipconfig_type =
			CONNMAN_IPCONFIG_TYPE_UNKNOWN;
		int err = 0;

		if (service->type == CONNMAN_SERVICE_TYPE_VPN ||
				service->immutable)
			return __connman_error_not_supported(msg);

		DBG("%s", name);

		if (!service->ipconfig_ipv4 &&
					!service->ipconfig_ipv6)
			return __connman_error_invalid_property(msg);

		if (g_str_equal(name, "IPv4.Configuration"))
			ipconfig_type = CONNMAN_IPCONFIG_TYPE_IPV4;
		else
			ipconfig_type = CONNMAN_IPCONFIG_TYPE_IPV6;

		err = __connman_service_reset_ipconfig(service, ipconfig_type,
								&value, &state);

		if (err < 0) {
			if (is_connected(state) || is_connecting(state)) {
				if (ipconfig_type == CONNMAN_IPCONFIG_TYPE_IPV4)
					__connman_network_enable_ipconfig(
							service->network,
							service->ipconfig_ipv4);
				else
					__connman_network_enable_ipconfig(
							service->network,
							service->ipconfig_ipv6);
			}

			return __connman_error_failed(msg, -err);
		}

		if (ipconfig_type == CONNMAN_IPCONFIG_TYPE_IPV4)
			ipv4_configuration_changed(service);
		else
			ipv6_configuration_changed(service);

		if (is_connecting(service->state) ||
						is_connected(service->state)) {
			if (ipconfig_type == CONNMAN_IPCONFIG_TYPE_IPV4)
				__connman_network_enable_ipconfig(
							service->network,
							service->ipconfig_ipv4);
			else
				__connman_network_enable_ipconfig(
							service->network,
							service->ipconfig_ipv6);
		}

		service_save(service);
	} else if (g_str_equal(name, PROP_PASSPHRASE)) {
		const char *str = NULL;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &str);

		if (!can_set_property(service, name, msg,
						SET_PASSPHRASE_ACCESS))
			return __connman_error_permission_denied(msg);

		if (g_strcmp0(str, service->passphrase)) {
			int err;

			err = __connman_service_set_passphrase(service, str);
			if (err) {
				/*
				 * InvalidArguments is more appropriate here
				 * than PassphraseRequired
				 */
				if (err == -ENOKEY)
					err = -EINVAL;

				return __connman_error_failed(msg, -err);
			}

			service_save(service);
		}
	} else if (g_str_equal(name, PROP_ACCESS)) {
		const char *str = NULL;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &str);

		if (!can_set_property(service, name, msg, SET_ACCESS_ACCESS))
			return __connman_error_permission_denied(msg);

		if (g_strcmp0(str, service->access)) {
			/* Check the syntax */
			struct connman_access_service_policy *policy =
				__connman_access_service_policy_create(str);

			if (str && !policy)
				return __connman_error_invalid_arguments(msg);

			/* Don't allow the user to shoot self in the foot */
			if (__connman_access_service_policy_check(policy,
					CONNMAN_ACCESS_SERVICE_SET_PROPERTY,
					name, dbus_message_get_sender(msg),
					SET_ACCESS_ACCESS) !=
							CONNMAN_ACCESS_ALLOW) {
				DBG("self-shooting prevented");
				__connman_access_service_policy_free(policy);
				return __connman_error_invalid_arguments(msg);
			}

			DBG("%s access \"%s\"", service->identifier, str);
			service_set_access_policy(service, str, policy);
			service_save(service);
		}
	} else if (g_str_equal(name, PROP_IDENTITY)) {
		return set_restricted_string(service, name, &value, msg,
					set_identity, SET_IDENTITY_ACCESS);
	} else if (g_str_equal(name, PROP_EAP)) {
		return set_restricted_string(service, name, &value, msg,
					set_eap_method, SET_EAP_ACCESS);
	} else if (g_str_equal(name, PROP_PHASE2)) {
		return set_restricted_string(service, name, &value, msg,
					set_phase2, SET_PHASE2_ACCESS);
	} else if (g_str_equal(name, PROP_CA_CERT)) {
		return set_restricted_string(service, name, &value, msg,
					set_ca_cert, SET_CA_CERT_ACCESS);
	} else if (g_str_equal(name, PROP_CA_CERT_FILE)) {
		return set_restricted_string(service, name, &value, msg,
						set_ca_cert_file,
						SET_CA_CERT_FILE_ACCESS);
	} else if (g_str_equal(name, PROP_DOMAIN_SUFFIX_MATCH)) {
		return set_restricted_string(service, name, &value, msg,
					set_domain_suffix_match,
					SET_DOMAIN_SUFFIX_MATCH_ACCESS);
	} else if (g_str_equal(name, PROP_CLIENT_CERT)) {
		return set_restricted_string(service, name, &value, msg,
					set_client_cert, SET_CLIENT_CERT_ACCESS);
	} else if (g_str_equal(name, PROP_CLIENT_CERT_FILE)) {
		return set_restricted_string(service, name, &value, msg,
						set_client_cert_file,
						SET_CLIENT_CERT_ACCESS);
	} else if (g_str_equal(name, PROP_PRIVATE_KEY)) {
		return set_restricted_string(service, name, &value, msg,
					set_private_key, SET_PRIVATE_KEY_ACCESS);
	} else if (g_str_equal(name, PROP_PRIVATE_KEY_FILE)) {
		return set_restricted_string(service, name, &value, msg,
						set_private_key_file,
						SET_PRIVATE_KEY_ACCESS);
	} else if (g_str_equal(name, PROP_PRIVATE_KEY_PASSPHRASE)) {
		return set_restricted_string(service, name, &value, msg,
						set_private_key_passphrase,
						SET_PRIVATE_KEY_PASSPHRASE_ACCESS);
	} else if (g_str_equal(name, PROP_ANONYMOUS_IDENTITY)) {
		return set_restricted_string(service, name, &value, msg,
						set_anonymous_identity,
						SET_ANONYMOUS_IDENTITY_ACCESS);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void set_error(struct connman_service *service,
					enum connman_service_error error)
{
	const char *str;

	if (service->error == error)
		return;

	service->error = error;

	if (!service->path)
		return;

	if (!allow_property_changed(service))
		return;

	str = error2string(service->error);

	if (!str)
		str = "";

	connman_dbus_property_changed_basic(service->path,
				CONNMAN_SERVICE_INTERFACE, "Error",
				DBUS_TYPE_STRING, &str);
}

static void remove_timeout(struct connman_service *service)
{
	if (service->timeout > 0) {
		g_source_remove(service->timeout);
		service->timeout = 0;
	}
}

static void reply_pending(struct connman_service *service, int error)
{
	remove_timeout(service);

	if (service->pending) {
		connman_dbus_reply_pending(service->pending, error, NULL);
		service->pending = NULL;
	}

	if (service->provider_pending) {
		connman_dbus_reply_pending(service->provider_pending,
				error, service->path);
		service->provider_pending = NULL;
	}
}

static void service_complete(struct connman_service *service)
{
	reply_pending(service, EIO);

	gettimeofday(&service->modified, NULL);
	service_save(service);
}

static DBusMessage *clear_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *sender = dbus_message_get_sender(msg);
	struct connman_service *service = user_data;
	const char *name;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (__connman_access_service_policy_check(service->policy,
			CONNMAN_ACCESS_SERVICE_CLEAR_PROPERTY, name, sender,
			CLEAR_PROPERTY_ACCESS) != CONNMAN_ACCESS_ALLOW) {
		connman_warn("%s is not allowed to clear %s for %s", sender,
							name, service->path);
		return __connman_error_permission_denied(msg);
	}

	if (g_str_equal(name, "Error")) {
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		__connman_service_clear_error(service);
		service_complete(service);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool is_ipconfig_usable(struct connman_service *service)
{
	if (!__connman_ipconfig_is_usable(service->ipconfig_ipv4) &&
			!__connman_ipconfig_is_usable(service->ipconfig_ipv6))
		return false;

	return true;
}

static bool is_ignore(struct connman_service *service)
{
	if (!service->autoconnect)
		return true;

	if (service->roaming &&
		!connman_setting_get_bool("AutoConnectRoamingServices"))
		return true;

	if (service->ignore)
		return true;

	if (!is_ipconfig_usable(service))
		return true;

	return false;
}

static void disconnect_on_last_session(enum connman_service_type type)
{
	GList *list;

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;

		if (service->type != type)
			continue;

		if (service->connect_reason != CONNMAN_SERVICE_CONNECT_REASON_SESSION)
			 continue;

		__connman_service_disconnect(service);
		return;
	}
}

static int active_sessions[MAX_CONNMAN_SERVICE_TYPES] = {};
static int always_connect[MAX_CONNMAN_SERVICE_TYPES] = {};
static int active_count = 0;

void __connman_service_set_active_session(bool enable, GSList *list)
{
	if (!list)
		return;

	if (enable)
		active_count++;
	else
		active_count--;

	while (list) {
		enum connman_service_type type = GPOINTER_TO_INT(list->data);

		switch (type) {
		case CONNMAN_SERVICE_TYPE_ETHERNET:
		case CONNMAN_SERVICE_TYPE_WIFI:
		case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		case CONNMAN_SERVICE_TYPE_CELLULAR:
		case CONNMAN_SERVICE_TYPE_GADGET:
			if (enable)
				active_sessions[type]++;
			else
				active_sessions[type]--;
			break;

		case CONNMAN_SERVICE_TYPE_UNKNOWN:
		case CONNMAN_SERVICE_TYPE_SYSTEM:
		case CONNMAN_SERVICE_TYPE_GPS:
		case CONNMAN_SERVICE_TYPE_VPN:
		case CONNMAN_SERVICE_TYPE_P2P:
			break;
		}

		if (active_sessions[type] == 0)
			disconnect_on_last_session(type);

		list = g_slist_next(list);
	}

	DBG("eth %d wifi %d bt %d cellular %d gadget %d sessions %d",
			active_sessions[CONNMAN_SERVICE_TYPE_ETHERNET],
			active_sessions[CONNMAN_SERVICE_TYPE_WIFI],
			active_sessions[CONNMAN_SERVICE_TYPE_BLUETOOTH],
			active_sessions[CONNMAN_SERVICE_TYPE_CELLULAR],
			active_sessions[CONNMAN_SERVICE_TYPE_GADGET],
			active_count);
}

struct preferred_tech_data {
	GList *preferred_list;
	enum connman_service_type type;
};

static void preferred_tech_add_by_type(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	struct preferred_tech_data *tech_data = user_data;

	/* Ignore unavailable services (without the network) */
	if (service->type == tech_data->type && is_available(service)) {
		tech_data->preferred_list =
			g_list_append(tech_data->preferred_list, service);

		DBG("type %d service %p %s", tech_data->type, service,
				service->name);
	}
}

static GList *preferred_tech_list_get(void)
{
	unsigned int *tech_array;
	struct preferred_tech_data tech_data = { 0, };
	int i;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (!tech_array)
		return NULL;

	if (connman_setting_get_bool("SingleConnectedTechnology")) {
		GList *list;
		for (list = service_list; list; list = list->next) {
			struct connman_service *service = list->data;

			if (!is_connected(service->state))
				break;

			if (service->connect_reason ==
					CONNMAN_SERVICE_CONNECT_REASON_USER) {
				DBG("service %p name %s is user connected",
						service, service->name);
				return NULL;
			}
		}
	}

	for (i = 0; tech_array[i] != 0; i += 1) {
		tech_data.type = tech_array[i];
		g_list_foreach(service_list, preferred_tech_add_by_type,
				&tech_data);
	}

	return tech_data.preferred_list;
}

static void set_always_connecting_technologies()
{
	unsigned int *always_connected_techs =
		connman_setting_get_uint_list("AlwaysConnectedTechnologies");
	int i;
	for (i = 0; always_connected_techs && always_connected_techs[i]; i++)
		always_connect[always_connected_techs[i]] = 1;
}

static bool autoconnect_no_session_active(struct connman_service *service)
{
	/*
	 * Test active_count to see if there are no sessions set up and
	 * stop autoconnecting, but continue connecting if the service
	 * belongs to a technology which should always autoconnect.
	 */
	if (!active_count && !always_connect[service->type])
		return true;

	return false;
}

static bool autoconnect_already_connecting(struct connman_service *service,
					   bool autoconnecting)
{
	/*
	 * If another service is already connecting and this service type has
	 * not been marked as always connecting, stop the connecting procedure.
	 */
	if (autoconnecting &&
			!active_sessions[service->type] &&
			!always_connect[service->type])
		return true;

	return false;
}

static int service_indicate_state(struct connman_service *service);

static bool auto_connect_service(GList *services,
				enum connman_service_connect_reason reason,
				bool preferred)
{
	struct connman_service *service = NULL;
	bool ignore[MAX_CONNMAN_SERVICE_TYPES] = { };
	bool busy[MAX_CONNMAN_SERVICE_TYPES] = { };
	bool autoconnecting = false;
	bool preferred_found = false;
	GList *list;

	DBG("preferred %d sessions %d reason %s", preferred, active_count,
		reason2string(reason));

	ignore[CONNMAN_SERVICE_TYPE_VPN] = true;

	/*
	 * Do not try to simultaneously autoconnect more than one service
	 * of each kind.
	 */
	for (list = services; list; list = list->next) {
		service = list->data;

		/*
		 * Once we hit the unavailable service, we know that the
		 * rest of them are unavailable too (see service_compare),
		 * so we can break out early.
		 */
		if (!is_available(service))
			break;

		if (service->disabled)
			continue;

		if (ignore[service->type] || busy[service->type])
			continue;

		if (service->pending ||
				is_connecting(service->state) ||
				is_connected(service->state)) {
			/*
			 * At least one service of this type is busy.
			 * Don't set the autoconnecting flag just yet,
			 * because we may need to ask a service of other
			 * type to get connected, if it happens to have
			 * a higher priority (e.g. to switch from cellular
			 * to wifi).
			 */
			busy[service->type] = true;
			DBG("service %p busy, skipping %s", service,
				__connman_service_type2string(service->type));
			continue;
		}
	}

	for (list = services; list; list = list->next) {
		service = list->data;

		/*
		 * Once we hit the unavailable service, we know that the
		 * rest of them are unavailable too (see service_compare),
		 * so we can break out early.
		 */
		if (!is_available(service))
			break;

		if (ignore[service->type] || !service->autoconnect) {
			DBG("service %p type %s ignore %d autoconnect %d",
				service,
				__connman_service_type2string(service->type),
				ignore[service->type], service->autoconnect);
			continue;
		}

		if (busy[service->type]) {
			if (autoconnect_no_session_active(service))

				return true;

			ignore[service->type] = true;
			autoconnecting = true;

			DBG("service %p type %s busy", service,
				__connman_service_type2string(service->type));

			continue;
		}

		if (service->new_service &&
			service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			reason == CONNMAN_SERVICE_CONNECT_REASON_AUTO) {
			DBG("service %p type %s new (skipping)", service,
				__connman_service_type2string(service->type));
			continue;
		}

		if (!service->favorite) {
			/*
			 * If we are connecting preferred technologies and
			 * this service is autoconnectable, then connect it
			 * regardless of whether it is favorite or not.
			 */
			if (!preferred)
				return autoconnecting;
		}

		if (is_ignore(service) || service->state !=
				CONNMAN_SERVICE_STATE_IDLE) {
			DBG("service %p ignore %d state %d", service,
				is_ignore(service), service->state);
			continue;
		}

		if (autoconnect_already_connecting(service, autoconnecting)) {
			DBG("service %p type %s has no users", service,
				__connman_service_type2string(service->type));
			continue;
		}

		DBG("service %p %s %s", service, service->name,
			(preferred) ? "preferred" : reason2string(reason));

		if (__connman_service_connect(service, reason) == 0)
			service_indicate_state(service);

		/*
		 * Stop autoconnection of services if no service is active only
		 * if not selecting a preferred service or when selecting
		 * preferred service and such service has been found. Otherwise
		 * there will be a long delay in dropping out from range of a
		 * WLAN network and a mobile data connection that is in idle
		 * state  should be connected. 
		 */
		if (autoconnect_no_session_active(service)) {
			if (!preferred || preferred_found) {
				DBG("active_count %d preferred %s found %s",
					active_count,
					preferred ? "true" : "false",
					preferred_found ? "true" : "false");
				return true;
			}
		}

		ignore[service->type] = true;

		preferred_found = true;
	}

	return autoconnecting;
}

static gboolean run_auto_connect(gpointer data)
{
	enum connman_service_connect_reason reason = GPOINTER_TO_UINT(data);
	bool autoconnecting = false;
	GList *preferred_tech;

	autoconnect_id = 0;

	DBG("paused %d", autoconnect_paused);
	if (autoconnect_paused)
		return FALSE;

	preferred_tech = preferred_tech_list_get();
	if (preferred_tech) {
		autoconnecting = auto_connect_service(preferred_tech, reason,
							true);
		g_list_free(preferred_tech);
	}

	if (!autoconnecting || active_count)
		auto_connect_service(service_list, reason, false);

	return FALSE;
}

void __connman_service_auto_connect(enum connman_service_connect_reason reason)
{
	DBG("");

	if (autoconnect_id != 0)
		return;

	if (!__connman_session_policy_autoconnect(reason))
		return;

	autoconnect_id = g_idle_add(run_auto_connect,
						GUINT_TO_POINTER(reason));
}

static gboolean run_vpn_auto_connect(gpointer data) {
	GList *list;
	bool need_split = false;
	bool autoconnectable_vpns = false;
	int attempts = 0;
	int timeout = VPN_AUTOCONNECT_TIMEOUT_DEFAULT;
	struct connman_service *def_service;

	attempts = GPOINTER_TO_INT(data);
	def_service = connman_service_get_default();

	/*
	 * Stop auto connecting VPN if there is no transport service or the
	 * transport service is not connected or if the  current default service
	 * is a connected VPN (in ready state).
	 */
	if (!def_service || !is_connected(def_service->state) ||
			(def_service->type == CONNMAN_SERVICE_TYPE_VPN &&
			is_connected(def_service->state))) {

		DBG("stopped, default service %s connected %d",
			def_service ? def_service->identifier : "NULL",
			def_service ? is_connected(def_service->state) : -1);
		goto out;
	}

	for (list = service_list; list; list = list->next) {
		struct connman_service *service = list->data;
		int res;

		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			continue;

		if (is_connected(service->state) ||
					is_connecting(service->state)) {
			if (!service->do_split_routing)
				need_split = true;

			/*
			 * If the service is connecting it must be accounted
			 * for to keep the autoconnection in main loop.
			 */
			if (is_connecting(service->state))
				autoconnectable_vpns = true;

			continue;
		}

		if (is_ignore(service) || !service->favorite)
			continue;

		if (need_split && !service->do_split_routing) {
			DBG("service %p no split routing", service);
			continue;
		}

		DBG("service %p %s %s", service, service->name,
				service->do_split_routing ?
				"split routing" : "");

		res = __connman_service_connect(service,
				CONNMAN_SERVICE_CONNECT_REASON_AUTO);

		switch (res) {
		case 0:
			service_indicate_state(service);
			/* fall through */
		case -EINPROGRESS:
		case -EALREADY:
			autoconnectable_vpns = true;
			break;
		default:
			continue;
		}

		if (!service->do_split_routing)
			need_split = true;
	}

	/* Stop if there is no VPN to automatically connect.*/
	if (!autoconnectable_vpns) {
		DBG("stopping, no autoconnectable VPNs found");
		goto out;
	}

	/* Increase the attempt count up to the threshold.*/
	if (attempts < VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD)
		attempts++;

	/*
	 * Timeout increases with 1s after VPN_AUTOCONNECT_TIMEOUT_STEP amount
	 * of attempts made. After VPN_AUTOCONNECT_TIMEOUT_ATTEMPTS_THRESHOLD is
	 * reached the delay does not increase.
	 */
	timeout = timeout + (int)(attempts / VPN_AUTOCONNECT_TIMEOUT_STEP);

	/* Re add this to main loop */
	vpn_autoconnect_id =
		g_timeout_add_seconds(timeout, run_vpn_auto_connect,
			GINT_TO_POINTER(attempts));

	DBG("re-added to main loop, next VPN autoconnect in %d seconds (#%d)",
		timeout, attempts);

	return G_SOURCE_REMOVE;

out:
	vpn_autoconnect_id = 0;
	return G_SOURCE_REMOVE;
}

static void vpn_auto_connect(void)
{
	DBG("");

	/*
	 * Remove existing autoconnect from main loop to reset the attempt
	 * counter in order to get VPN connected when there is a network change.
	 */
	if (vpn_autoconnect_id) {
		if (!g_source_remove(vpn_autoconnect_id)) {
			return;
		}
	}

	vpn_autoconnect_id =
		g_idle_add(run_vpn_auto_connect, NULL);
}

bool
__connman_service_is_provider_pending(struct connman_service *service)
{
	if (!service)
		return false;

	if (service->provider_pending)
		return true;

	return false;
}

void __connman_service_set_provider_pending(struct connman_service *service,
							DBusMessage *msg)
{
	if (service->provider_pending) {
		DBG("service %p provider pending msg %p already exists",
			service, service->provider_pending);
		return;
	}

	service->provider_pending = msg;
}

static void check_pending_msg(struct connman_service *service)
{
	if (!service->pending)
		return;

	DBG("service %p pending msg %p already exists", service,
						service->pending);
	dbus_message_unref(service->pending);
}

void __connman_service_set_hidden_data(struct connman_service *service,
							gpointer user_data)
{
	DBusMessage *pending = user_data;

	DBG("service %p pending %p", service, pending);

	if (!pending)
		return;

	check_pending_msg(service);

	service->pending = pending;
}

void __connman_service_return_error(struct connman_service *service,
				int error, gpointer user_data)
{
	DBG("service %p error %d user_data %p", service, error, user_data);

	__connman_service_set_hidden_data(service, user_data);

	reply_pending(service, error);
}

static void service_ipconfig_indicate_states(struct connman_service *service,
					enum connman_service_state new_state)
{
	__connman_service_ipconfig_indicate_state(service, new_state,
					CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service, new_state,
					CONNMAN_IPCONFIG_TYPE_IPV6);
}

static gboolean service_retry_connect(gpointer data)
{
	struct connman_service *service = data;

	DBG("service %p", service);
	service->connect_retry_timer = 0;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE ||
			service->state == CONNMAN_SERVICE_STATE_IDLE) {
		/*
		 * Do not reset VPN state here as doing so leads to reseting of
		 * the VPN autoconnect timer without proper reason.
		 */
		if (service->type != CONNMAN_SERVICE_TYPE_VPN) {
			/* Clear the state */
			service_ipconfig_indicate_states(service,
						CONNMAN_SERVICE_STATE_IDLE);
			set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

			service->state = CONNMAN_SERVICE_STATE_IDLE;
			state_changed(service);
		}

		/* Schedule the next auto-connect round */
		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	return FALSE;
}

static gboolean connect_timeout(gpointer user_data)
{
	struct connman_service *service = user_data;
	bool autoconnect = false;

	DBG("service %p", service);

	service->timeout = 0;

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->provider) {
		/*
		 * Remove timeout when the VPN is waiting for user input in
		 * association state. By default the VPN agent timeout is
		 * 300s whereas default connection timeout is 120s. Provider
		 * will start connect timeout for the service when it enters
		 * configuration state.
		 */
		const char *statestr = connman_provider_get_string(
					service->provider, "State");
		if (!g_strcmp0(statestr, "association")) {
			DBG("VPN provider %p is waiting for VPN agent, "
						"stop connect timeout",
						service->provider);
			return G_SOURCE_REMOVE;
		}

		connman_provider_disconnect(service->provider);
	}



	if (service->pending) {
		DBusMessage *reply;

		reply = __connman_error_operation_timeout(service->pending);
		if (reply)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(service->pending);
		service->pending = NULL;
	} else
		autoconnect = true;

	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_FAILURE,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (autoconnect &&
			service->connect_reason !=
				CONNMAN_SERVICE_CONNECT_REASON_USER)
		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);

	return G_SOURCE_REMOVE;
}

void __connman_service_start_connect_timeout(struct connman_service *service,
								bool restart)
{
	DBG("");

	if (!service)
		return;

	if (!restart && service->timeout)
		return;

	if (restart && service->timeout) {
		DBG("cancel running connect timeout");
		g_source_remove(service->timeout);
	}

	service->timeout = connman_wakeup_timer_add_seconds(CONNECT_TIMEOUT,
				connect_timeout, service);
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int index, err = 0;
	GList *list;

	DBG("service %p", service);

	if (!can_call(service, CONNMAN_ACCESS_SERVICE_CONNECT, msg,
							CONNECT_ACCESS)) {
		connman_warn("%s is not allowed to connect %s",
			dbus_message_get_sender(msg), service->path);
		return __connman_error_permission_denied(msg);
	}

	if (!service->network && !(service->provider &&
				service->type == CONNMAN_SERVICE_TYPE_VPN))
		return __connman_error_no_carrier(msg);

	/* Hidden services do not keep the pending msg, check it from agent */
	if (service->pending || (service->hidden &&
				__connman_agent_is_request_pending(service,
						dbus_message_get_sender(msg))))
		return __connman_error_in_progress(msg);

	index = __connman_service_get_index(service);

	for (list = service_list; list; list = list->next) {
		struct connman_service *temp = list->data;

		if (!is_connecting(temp->state) && !is_connected(temp->state))
			break;

		if (service == temp)
			continue;

		if (service->type != temp->type)
			continue;

		if (__connman_service_get_index(temp) == index &&
				__connman_service_disconnect(temp) == -EINPROGRESS)
			err = -EINPROGRESS;

	}
	if (err == -EINPROGRESS)
		return __connman_error_operation_timeout(msg);

	service->ignore = false;

	service->pending = dbus_message_ref(msg);

	err = __connman_service_connect(service,
			CONNMAN_SERVICE_CONNECT_REASON_USER);

	if (err != -EINPROGRESS)
		reply_pending(service, -err);

	return NULL;
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	int err;

	DBG("service %p", service);

	if (!can_call(service, CONNMAN_ACCESS_SERVICE_DISCONNECT, msg,
							DISCONNECT_ACCESS)) {
		connman_warn("%s is not allowed to disconnect %s",
			dbus_message_get_sender(msg), service->path);
		return __connman_error_permission_denied(msg);
	}

	//service->ignore = true;

	err = __connman_service_disconnect(service);
	if (err < 0 && err != -EINPROGRESS)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

bool __connman_service_remove(struct connman_service *service)
{
	size_t i;
#define SVC_PROP(name, member, access) \
	{ name, G_STRUCT_OFFSET(struct connman_service, member), access }
	const struct {
		const char *name;
		size_t offset;
		enum connman_access default_access;
	} cleared_properties[] = {
		SVC_PROP(PROP_PASSPHRASE, passphrase, GET_PASSPHRASE_ACCESS),
		SVC_PROP(PROP_IDENTITY, identity, GET_IDENTITY_ACCESS),
		SVC_PROP("AnonymousIdentity", anonymous_identity,
				GET_IDENTITY_ACCESS),
		SVC_PROP("SubjectMatch", subject_match, GET_ACCESS_ACCESS),
		SVC_PROP("AltSubjectMatch", altsubject_match,
				GET_ACCESS_ACCESS),
		SVC_PROP("DomainSuffixMatch", domain_suffix_match,
				GET_ACCESS_ACCESS),
		SVC_PROP("DomainMatch", domain_match, GET_ACCESS_ACCESS),
		SVC_PROP("AgentIdentity", agent_identity,
				GET_IDENTITY_ACCESS),
		SVC_PROP("CACert", ca_cert, GET_ACCESS_ACCESS),
		SVC_PROP("CACertFile", ca_cert_file, GET_ACCESS_ACCESS),
		SVC_PROP("ClientCert", client_cert, GET_ACCESS_ACCESS),
		SVC_PROP("ClientCertFile", client_cert_file,
				GET_ACCESS_ACCESS),
		SVC_PROP("PrivateKey", private_key, GET_PASSPHRASE_ACCESS),
		SVC_PROP("PrivateKeyFile", private_key_file,
				GET_PASSPHRASE_ACCESS),
		SVC_PROP("PrivateKeyPassphrase", private_key_passphrase,
				GET_PASSPHRASE_ACCESS),
	};
#undef SVC_PROP

	if (service->type == CONNMAN_SERVICE_TYPE_ETHERNET ||
			service->type == CONNMAN_SERVICE_TYPE_GADGET)
		return false;

	if (service->immutable || service->hidden ||
			__connman_provider_is_immutable(service->provider))
		return false;

	/* Not clear what was the meaning of this restriction: */
//	if (!service->favorite && !is_idle(service->state))
//		return false;

	/*
	 * We don't want the service files to stay around forever unless the
	 * service file belongs to a VPN connection. The VPN connection specific
	 * configuration files contain autoconnect and split routing information
	 * that should be kept between connman restarts. Otherwise autoconnect
	 * for VPNs cannot operate. The VPN connection service file is removed
	 * when vpnd removes the connection. It should not be removed here.
	 */
	if (service->type != CONNMAN_SERVICE_TYPE_VPN)
		__connman_storage_remove_service(service->identifier);

	__connman_service_disconnect(service);

	for (i = 0; i < G_N_ELEMENTS(cleared_properties); i++) {
		char **member = &G_STRUCT_MEMBER(char *, service,
						cleared_properties[i].offset);

		g_free(*member);
		*member = NULL;

		restricted_string_changed(service,
					cleared_properties[i].name, NULL,
					cleared_properties[i].default_access);
	}

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	__connman_service_set_favorite(service, false);
	connman_service_set_autoconnect(service, false);

	__connman_ipconfig_ipv6_reset_privacy(service->ipconfig_ipv6);

	if (service->network) {
		/* The network is still alive (but not saved anymore) */
		service_set_new_service(service, true);
	} else {
		/* No network for this service, it's gone for good */
		service_remove(service);
	}

	return true;
}

static DBusMessage *remove_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	DBG("service %p", service);

	if (!can_call(service, CONNMAN_ACCESS_SERVICE_REMOVE, msg,
							REMOVE_ACCESS)) {
		connman_warn("%s is not allowed to remove %s",
			dbus_message_get_sender(msg), service->path);
		return __connman_error_permission_denied(msg);
	}

	if (!__connman_service_remove(service))
		return __connman_error_not_supported(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static bool check_suitable_state(enum connman_service_state a,
					enum connman_service_state b)
{
	/*
	 * Special check so that "ready" service can be moved before
	 * "online" one.
	 */
	if ((a == CONNMAN_SERVICE_STATE_ONLINE &&
			b == CONNMAN_SERVICE_STATE_READY) ||
		(b == CONNMAN_SERVICE_STATE_ONLINE &&
			a == CONNMAN_SERVICE_STATE_READY))
		return true;

	return a == b;
}

static void downgrade_state(struct connman_service *service)
{
	if (!service)
		return;

	DBG("service %p state4 %d state6 %d", service, service->state_ipv4,
						service->state_ipv6);

	if (service->state_ipv4 == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	if (service->state_ipv6 == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);
}

static void apply_relevant_default_downgrade(struct connman_service *service)
{
	struct connman_service *def_service;

	def_service = connman_service_get_default();
	if (!def_service)
		return;

	if (def_service == service &&
			def_service->state == CONNMAN_SERVICE_STATE_ONLINE) {
		def_service->state = CONNMAN_SERVICE_STATE_READY;
		__connman_notifier_leave_online(def_service->type);
		state_changed(def_service);
	}
}

static void switch_default_service(struct connman_service *default_service,
		struct connman_service *downgrade_service)
{
	struct connman_service *service;
	GList *src, *dst;

	apply_relevant_default_downgrade(default_service);
	src = g_list_find(service_list, downgrade_service);
	dst = g_list_find(service_list, default_service);

	/* Nothing to do */
	if (src == dst || src->next == dst)
		return;

	service = src->data;
	service_list = g_list_delete_link(service_list, src);
	service_list = g_list_insert_before(service_list, dst, service);

	downgrade_state(downgrade_service);
}

static struct _services_notify {
	int id;
	GHashTable *add;
	GHashTable *remove;
	GHashTable *update;
} *services_notify;


static void service_append_added_foreach(gpointer data, gpointer user_data)
{
	struct connman_service *service = data;
	DBusMessageIter *iter = user_data;

	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	if (g_hash_table_lookup(services_notify->add, service->path)) {
		DBG("new %s", service->path);

		append_struct(service, iter);
		g_hash_table_remove(services_notify->add, service->path);
	} else if (g_hash_table_lookup(services_notify->update, service->path)) {
		DBG("updated %s", service->path);

		append_struct_service(iter, append_dict_properties_updated, service);
		g_hash_table_remove(services_notify->update, service->path);
	} else {
		DBG("changed %s", service->path);

		append_struct_service(iter, NULL, service);
	}
}

static void service_append_ordered(DBusMessageIter *iter, void *user_data)
{
	g_list_foreach(service_list, service_append_added_foreach, iter);
}

static void append_removed(gpointer key, gpointer value, gpointer user_data)
{
	char *objpath = key;
	DBusMessageIter *iter = user_data;

	DBG("removed %s", objpath);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &objpath);
}

static void service_append_removed(DBusMessageIter *iter, void *user_data)
{
	g_hash_table_foreach(services_notify->remove, append_removed, iter);
}

static gboolean service_send_changed(gpointer data)
{
	DBusMessage *signal;

	DBG("");

	services_notify->id = 0;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "ServicesChanged");
	if (!signal)
		return FALSE;

	__connman_dbus_append_objpath_dict_array(signal,
					service_append_ordered, NULL);
	__connman_dbus_append_objpath_array(signal,
					service_append_removed, NULL);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);

	g_hash_table_remove_all(services_notify->remove);
	g_hash_table_remove_all(services_notify->add);
	g_hash_table_remove_all(services_notify->update);

	return FALSE;
}

static void service_schedule_changed(void)
{
	if (services_notify->id != 0)
		return;

	services_notify->id = g_timeout_add(100, service_send_changed, NULL);
}

int __connman_service_move(struct connman_service *service,
				struct connman_service *target, bool before)
{
	enum connman_ipconfig_method target4, target6;
	enum connman_ipconfig_method service4, service6;

	DBG("service %p", service);

	if (!service)
		return -EINVAL;

	if (!service->favorite)
		return -EOPNOTSUPP;

	if (!target || !target->favorite || target == service)
		return -EINVAL;

	if (target->type == CONNMAN_SERVICE_TYPE_VPN) {
		/*
		 * We only allow VPN route splitting if there are
		 * routes defined for a given VPN.
		 */
		if (!__connman_provider_check_routes(target->provider)) {
			DBG("Cannot move service. "
				"No routes defined for provider %s",
				__connman_provider_get_ident(target->provider));
			return -EINVAL;
		}

		__connman_service_set_split_routing(target, true);
	} else {
		__connman_service_set_split_routing(target, false);
	}

	__connman_service_set_split_routing(service, false);

	target4 = __connman_ipconfig_get_method(target->ipconfig_ipv4);
	target6 = __connman_ipconfig_get_method(target->ipconfig_ipv6);
	service4 = __connman_ipconfig_get_method(service->ipconfig_ipv4);
	service6 = __connman_ipconfig_get_method(service->ipconfig_ipv6);

	DBG("target %s method %d/%d state %d/%d split %d", target->identifier,
		target4, target6, target->state_ipv4, target->state_ipv6,
		target->do_split_routing);

	DBG("service %s method %d/%d state %d/%d", service->identifier,
				service4, service6,
				service->state_ipv4, service->state_ipv6);

	/*
	 * If method is OFF, then we do not need to check the corresponding
	 * ipconfig state.
	 */
	if (target4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return -EINVAL;
		}
	}

	if (target6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (service4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return -EINVAL;
		}
	}

	if (service4 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target6 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv6,
							service->state_ipv6))
				return -EINVAL;
		}
	}

	if (service6 == CONNMAN_IPCONFIG_METHOD_OFF) {
		if (target4 != CONNMAN_IPCONFIG_METHOD_OFF) {
			if (!check_suitable_state(target->state_ipv4,
							service->state_ipv4))
				return -EINVAL;
		}
	}

	gettimeofday(&service->modified, NULL);
	service_save(service);
	service_save(target);

	/*
	 * If the service which goes down is the default service and is
	 * online, we downgrade directly its state to ready so:
	 * the service which goes up, needs to recompute its state which
	 * is triggered via downgrading it - if relevant - to state ready.
	 */
	if (before)
		switch_default_service(target, service);
	else
		switch_default_service(service, target);

	__connman_connection_update_gateway();

	service_schedule_changed();

	return 0;
}

static DBusMessage *move_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data,
								bool before)
{
	struct connman_service *service = user_data;
	struct connman_service *target;
	const char *path;
	int err;

	DBG("service %p", service);

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	target = find_service(path);

	err = __connman_service_move(service, target, before);
	switch (err) {
	case 0:
		break;
	case -EINVAL:
		return __connman_error_invalid_service(msg);
	case -EOPNOTSUPP:
		return __connman_error_not_supported(msg);
	default:
		connman_warn("unsupported error code %d in move_service()",
									err);
		break;
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *move_before(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, true);
}

static DBusMessage *move_after(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return move_service(conn, msg, user_data, false);
}

static DBusMessage *reset_counters(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;

	if (!can_call(service, CONNMAN_ACCESS_SERVICE_RESET_COUNTERS, msg,
						RESET_COUNTERS_ACCESS)) {
		connman_warn("%s is not allowed to reset counters for %s",
			dbus_message_get_sender(msg), service->path);
		return __connman_error_permission_denied(msg);
	}

	reset_stats(service);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *check_access(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_service *service = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessage *reply = dbus_message_new_method_return(msg);
	DBusMessageIter it;
	dbus_uint32_t get_props = 0;
	dbus_uint32_t set_props = 0;
	dbus_uint32_t calls = ACCESS_METHOD_ALWAYS_ALLOWED;
	guint i;

	for (i=0; i<G_N_ELEMENTS(service_property_access); i++) {
		const struct connman_service_property_access *pa =
			service_property_access + i;

		if (can_get_property(service, pa->name, sender,
						pa->default_get_access)) {
			get_props |= pa->flag;
		} else {
			DBG("%s is not allowed to get %s for %s", sender,
						pa->name, service->path);
		}
		if (check_set_property(service, pa->name, msg,
						pa->default_set_access)) {
			set_props |= pa->flag;
		} else {
			DBG("%s is not allowed to set %s for %s", sender,
						pa->name, service->path);
		}
	}

	for (i=0; i<G_N_ELEMENTS(service_method_access); i++) {
		const struct connman_service_method_access *ma =
			service_method_access + i;

		if (can_call(service, ma->method, msg, ma->default_access)) {
			calls |= ma->flag;
		}
	}

	dbus_message_iter_init_append(reply, &it);
	dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &get_props);
	dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &set_props);
	dbus_message_iter_append_basic(&it, DBUS_TYPE_UINT32, &calls);
	return reply;
}

static void service_schedule_added(struct connman_service *service)
{
	DBG("service %p", service);

	g_hash_table_remove(services_notify->remove, service->path);
	g_hash_table_remove(services_notify->update, service->path);
	g_hash_table_replace(services_notify->add, service->path, service);

	service_schedule_changed();
}

static void service_schedule_removed(struct connman_service *service)
{
	if (!service || !service->path) {
		DBG("service %p or path is NULL", service);
		return;
	}

	DBG("service %p %s", service, service->path);

	g_hash_table_remove(services_notify->add, service->path);
	g_hash_table_remove(services_notify->update, service->path);
	g_hash_table_replace(services_notify->remove, g_strdup(service->path),
			NULL);

	service_schedule_changed();
}

static void service_schedule_updated(struct connman_service *service)
{
	/* Only update if service has path */
	if (!service || !service->path) {
		return;
	}

	DBG("service %p", service);

	g_hash_table_remove(services_notify->remove, service->path);
	g_hash_table_remove(services_notify->add, service->path);
	g_hash_table_replace(services_notify->update, service->path, service);

	service_schedule_changed();
}

static bool allow_property_changed(struct connman_service *service)
{
	if (!service || !service->path)
		return false;

	if (g_hash_table_lookup_extended(services_notify->add, service->path,
					NULL, NULL))
		return false;

	return true;
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("ClearProperty",
			GDBUS_ARGS({ "name", "s" }), NULL,
			clear_property) },
	{ GDBUS_ASYNC_METHOD("Connect", NULL, NULL,
			      connect_service) },
	{ GDBUS_METHOD("Disconnect", NULL, NULL,
			disconnect_service) },
	{ GDBUS_METHOD("Remove", NULL, NULL, remove_service) },
	{ GDBUS_METHOD("MoveBefore",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_before) },
	{ GDBUS_METHOD("MoveAfter",
			GDBUS_ARGS({ "service", "o" }), NULL,
			move_after) },
	{ GDBUS_METHOD("ResetCounters", NULL, NULL, reset_counters) },
	{ GDBUS_METHOD("CheckAccess",
			NULL, GDBUS_ARGS({ "access", "uuu" }),
			check_access) },
	{ GDBUS_METHOD("GetProperty",
			GDBUS_ARGS({ "name", "s" }),
			GDBUS_ARGS({ "value", "v" }), get_property) },
	{ },
};

static const GDBusSignalTable service_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("RestrictedPropertyChanged",
			GDBUS_ARGS({ "name", "s" })) },
	{ },
};

static void stats_destroy(struct connman_service *service)
{
	__connman_stats_free(service->stats);
	__connman_stats_free(service->stats_roaming);
	if (service->stats_timer)
		g_timer_destroy(service->stats_timer);
}

static void service_free(gpointer user_data)
{
	struct connman_service *service = user_data;
	char *path = service->path;

	DBG("service %p", service);

	reply_pending(service, ENOENT);

	if (service->nameservers_timeout) {
		g_source_remove(service->nameservers_timeout);
		dns_changed(service);
	}

	__connman_notifier_service_remove(service);
	/* In our fork, service_schedule_removed() is called by
	 * service_removed() when the service is being removed
	 * from service_hash table. If we are only doing it here,
	 * it may be too late (hash table reference may not be the
	 * last one left), doing it here and there may result in
	 * double D-Bus notifications which is also wrong. */
	//service_schedule_removed(service);

	__connman_wispr_stop(service);

	service->path = NULL;

	if (path) {
		__connman_connection_update_gateway();

		g_dbus_unregister_interface(connection, path,
						CONNMAN_SERVICE_INTERFACE);
		g_free(path);
	}

	g_hash_table_destroy(service->counter_table);

	if (service->network) {
		__connman_network_disconnect(service->network);
		connman_network_unref(service->network);
		service->network = NULL;
	}

	if (service->provider)
		connman_provider_unref(service->provider);

	if (service->ipconfig_ipv4) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv4, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv4);
		service->ipconfig_ipv4 = NULL;
	}

	if (service->ipconfig_ipv6) {
		__connman_ipconfig_set_ops(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_set_data(service->ipconfig_ipv6, NULL);
		__connman_ipconfig_unref(service->ipconfig_ipv6);
		service->ipconfig_ipv6 = NULL;
	}

	g_strfreev(service->timeservers);
	g_strfreev(service->timeservers_config);
	g_strfreev(service->nameservers);
	g_strfreev(service->nameservers_config);
	g_strfreev(service->nameservers_auto);
	g_strfreev(service->domains);
	g_strfreev(service->proxies);
	g_strfreev(service->excludes);

	g_free(service->hostname);
	g_free(service->domainname);
	g_free(service->pac);
	g_free(service->name);
	g_free(service->passphrase);
	g_free(service->identifier);
	g_free(service->eap);
	g_free(service->identity);
	g_free(service->anonymous_identity);
	g_free(service->agent_identity);
	g_free(service->ca_cert_file);
	g_free(service->ca_cert);
	g_free(service->subject_match);
	g_free(service->altsubject_match);
	g_free(service->domain_suffix_match);
	g_free(service->domain_match);
	g_free(service->client_cert_file);
	g_free(service->client_cert);
	g_free(service->private_key_file);
	g_free(service->private_key);
	g_free(service->private_key_passphrase);
	g_free(service->phase2);
	g_free(service->config_file);
	g_free(service->config_entry);

	stats_destroy(service);

	__connman_access_service_policy_free(service->policy);
	g_free(service->access);
	g_free(service->path);

	cancel_online_check(service);
	if (service->connect_retry_timer)
		g_source_remove(service->connect_retry_timer);

	if (service->ssid)
		g_bytes_unref(service->ssid);

	if (current_default == service)
		current_default = NULL;

	g_free(service);
}

static void stats_init(struct connman_service *service)
{
	/* home */
	service->stats = __connman_stats_new(service, FALSE);

	/* Roaming stats will be created later for cellular services */
	if (service->stats) {
		service->stats_timer = g_timer_new();
		g_timer_start(service->stats_timer);
	}
}

static void service_initialize(struct connman_service *service)
{
	DBG("service %p", service);

	service->refcount = 1;

	service->error = CONNMAN_SERVICE_ERROR_UNKNOWN;

	service->type     = CONNMAN_SERVICE_TYPE_UNKNOWN;
	service->security = CONNMAN_SERVICE_SECURITY_UNKNOWN;

	service->state = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv4 = CONNMAN_SERVICE_STATE_UNKNOWN;
	service->state_ipv6 = CONNMAN_SERVICE_STATE_UNKNOWN;

	service->favorite  = false;
	service->immutable = false;
	service->hidden = false;

	service->ignore = false;

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;

	service->order = 0;

	service->online_timeout_ipv4 = 0;
	service->online_timeout_ipv6 = 0;
	service->policy = __connman_access_service_policy_create(NULL);

	service->provider = NULL;

	service->wps = false;
	service->wps_advertizing = false;

	service->nameservers_ipv4_refcount = 0;
	service->nameservers_ipv6_refcount = 0;
}

/**
 * connman_service_create:
 *
 * Allocate a new service.
 *
 * Returns: a newly-allocated #connman_service structure
 */
struct connman_service *connman_service_create(void)
{
	GSList *list;
	struct connman_stats_counter *counters;
	const char *counter;

	struct connman_service *service;

	service = g_try_new0(struct connman_service, 1);
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->counter_table = g_hash_table_new_full(g_str_hash,
						g_str_equal, NULL, g_free);

	for (list = counter_list; list; list = list->next) {
		counter = list->data;

		counters = g_try_new0(struct connman_stats_counter, 1);
		if (!counters) {
			g_hash_table_destroy(service->counter_table);
			g_free(service);
			return NULL;
		}

		counters->append_all = true;

		g_hash_table_replace(service->counter_table, (gpointer)counter,
				counters);
	}

	service_initialize(service);

	return service;
}

/**
 * connman_service_ref:
 * @service: service structure
 *
 * Increase reference counter of service
 */
struct connman_service *
connman_service_ref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount + 1,
		file, line, caller);

	__sync_fetch_and_add(&service->refcount, 1);

	return service;
}

/**
 * connman_service_unref:
 * @service: service structure
 *
 * Decrease reference counter of service and release service if no
 * longer needed.
 */
void connman_service_unref_debug(struct connman_service *service,
			const char *file, int line, const char *caller)
{
	DBG("%p ref %d by %s:%d:%s()", service, service->refcount - 1,
		file, line, caller);

	if (__sync_fetch_and_sub(&service->refcount, 1) != 1)
		return;

	service_free(service);
}

/*
 * Check service preference using the list of preferred technology types
 *
 * Return 1 when b is preferred over a
 * Return 0 when a == b, does not apply to sorting
 * Return -1 when a is preferred over b
 */
static int service_preferred_over(struct connman_service *a,
						struct connman_service *b)
{
	unsigned int *tech_array;
	unsigned int position_a = G_MAXUINT;
	unsigned int position_b = G_MAXUINT;
	unsigned int i;

	/*
	 * If either or both are NULL or the types match preference is not used
	 * in sorting.
	 */
	if (!(a && b) || (a->type == b->type))
		return 0;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (!tech_array)
		return 0;

	/*
	 * VPNs are not in the preferred tech list as they rely on other
	 * services as transport. Prefer connected VPN over any other service.
	 */
	if (a->type == CONNMAN_SERVICE_TYPE_VPN) {
		 /* Prefer a if connected */
		if (is_connected(a->state))
			position_a = 0;
		else if (a->order > b->order)
			position_a = 0;
		else
			position_b = 0;

		goto out;
	}

	if (b->type == CONNMAN_SERVICE_TYPE_VPN) {
		/* Prefer b if connected */
		if (is_connected(b->state))
			position_b = 0;
		else if (b->order > a->order)
			position_b = 0;
		else
			position_a = 0;

		goto out;
	}

	for (i = 0; tech_array[i] != 0; i++) {
		if (tech_array[i] == a->type)
			position_a = i;

		if (tech_array[i] == b->type)
			position_b = i;
	}

out:
	DBG("service a %p %s position %u service b %p %s position %u",
		a, a->identifier, position_a, b, b->identifier, position_b);

	/* Index of a is lower than b's index , prefer a */
	if (position_a < position_b)
		return -1;

	/* Index of b is lower than a's index, prefer b */
	if (position_a > position_b)
		return 1;

	return 0;
}

static gint service_compare(gconstpointer a, gconstpointer b);

static gint service_compare_vpn(struct connman_service *a,
						struct connman_service *b)
{
	struct connman_provider *provider;
	struct connman_service *service;
	struct connman_service *transport;
	const char *ident;
	bool reverse;

	if (a->provider) {
		provider = a->provider;
		service = b;
		reverse = false;
	} else if (b->provider) {
		provider = b->provider;
		service = a;
		reverse = true;
	} else {
		return 0;
	}

	ident = __connman_provider_get_transport_ident(provider);
	transport = connman_service_lookup_from_identifier(ident);
	if (!transport)
		return 0;

	if (reverse)
		return service_compare(service, transport);

	return service_compare(transport, service);
}

static gint service_compare(gconstpointer a, gconstpointer b)
{
	struct connman_service *service_a = (void *) a;
	struct connman_service *service_b = (void *) b;
	enum connman_service_state state_a, state_b;
	bool a_connected, b_connected;
	gint strength;

	/* Compare availability first */
	const gboolean a_available = is_available(service_a);
	const gboolean b_available = is_available(service_b);

	if (a_available && !b_available)
		return -1;
	if (!a_available && b_available)
		return 1;

	state_a = service_a->state;
	state_b = service_b->state;
	a_connected = is_connected(state_a);
	b_connected = is_connected(state_b);

	if (a_connected && b_connected) {
		int rval;

		/* Compare the VPN transport and the service */
		if ((service_a->type == CONNMAN_SERVICE_TYPE_VPN ||
				service_b->type == CONNMAN_SERVICE_TYPE_VPN) &&
				service_b->type != service_a->type) {
			rval = service_compare_vpn(service_a, service_b);
			if (rval)
				return rval;
		}

		if (state_a == state_b) {
			int preference;

			/* Return value only if preferred list is used. */
			preference = service_preferred_over(service_a,
						service_b);
			if (preference)
				return preference;
		}

		if (service_a->order > service_b->order)
			return -1;

		if (service_a->order < service_b->order)
			return 1;
	}

	if (state_a != state_b) {
		if (a_connected && b_connected) {
			/* We prefer online over ready state */
			if (state_a == CONNMAN_SERVICE_STATE_ONLINE)
				return -1;

			if (state_b == CONNMAN_SERVICE_STATE_ONLINE)
				return 1;
		}

		if (a_connected)
			return -1;
		if (b_connected)
			return 1;

		if (is_connecting(state_a)) {
			if (is_connecting(state_b))
				goto statecmp;

			return -1;
		}

		if (is_connecting(state_b)) {
			if (is_connecting(state_a))
				goto statecmp;

			return 1;
		}

statecmp:
		if (state_a > state_b)
			return -1;
		if (state_a < state_b)
			return 1;
	}

	if (service_a->favorite && !service_b->favorite)
		return -1;

	if (!service_a->favorite && service_b->favorite)
		return 1;

	if (service_a->type != service_b->type) {
		if (state_a == state_b) {
			int preference;

			preference = service_preferred_over(service_a,
								service_b);
			if (preference)
				return preference;
		}

		if (service_a->type == CONNMAN_SERVICE_TYPE_VPN)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_VPN)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_WIFI)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_WIFI)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_CELLULAR)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_BLUETOOTH)
			return 1;

		if (service_a->type == CONNMAN_SERVICE_TYPE_GADGET)
			return -1;
		if (service_b->type == CONNMAN_SERVICE_TYPE_GADGET)
			return 1;
	}

	strength = (gint) service_b->strength - (gint) service_a->strength;
	if (strength)
		return strength;

	return g_strcmp0(service_a->name, service_b->name);
}

static void service_list_sort(void)
{
	if (service_list && service_list->next) {
		service_list = g_list_sort(service_list, service_compare);
		service_schedule_changed();
	}
}

int __connman_service_compare(const struct connman_service *a,
					const struct connman_service *b)
{
	return service_compare(a, b);
}

/**
 * connman_service_get_type:
 * @service: service structure
 *
 * Get the type of service
 */
enum connman_service_type connman_service_get_type(struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return service->type;
}

/**
 * connman_service_get_interface:
 * @service: service structure
 *
 * Get network interface of service
 */
char *connman_service_get_interface(struct connman_service *service)
{
	int index;

	if (!service)
		return NULL;

	index = __connman_service_get_index(service);

	return connman_inet_ifname(index);
}

/**
 * connman_service_get_network:
 * @service: service structure
 *
 * Get the service network
 */
struct connman_network *
__connman_service_get_network(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->network;
}

struct connman_ipconfig *
__connman_service_get_ip4config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv4;
}

struct connman_ipconfig *
__connman_service_get_ip6config(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->ipconfig_ipv6;
}

struct connman_ipconfig *
__connman_service_get_ipconfig(struct connman_service *service, int family)
{
	if (family == AF_INET)
		return __connman_service_get_ip4config(service);
	else if (family == AF_INET6)
		return __connman_service_get_ip6config(service);
	else
		return NULL;

}

struct connman_ipconfig *connman_service_get_ipconfig(
				struct connman_service *service, int family)
{
	return __connman_service_get_ipconfig(service, family);
}

enum connman_ipconfig_method connman_service_get_ipconfig_method(
						struct connman_service *service,
						enum connman_ipconfig_type type)
{
	if (!service)
		return CONNMAN_IPCONFIG_METHOD_UNKNOWN;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return __connman_ipconfig_get_method(service->ipconfig_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return __connman_ipconfig_get_method(service->ipconfig_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	}

	return CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

const char *connman_service_get_vpn_transport_identifier(
						struct connman_service *service)
{
	if (!service || service->type != CONNMAN_SERVICE_TYPE_VPN)
		return NULL;

	return __connman_provider_get_transport_ident(service->provider);
}

struct connman_provider *connman_service_get_vpn_provider(
						struct connman_service *service)
{
	if (!service || service->type != CONNMAN_SERVICE_TYPE_VPN)
		return NULL;

	return service->provider;
}

bool __connman_service_is_connected_state(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return false;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		return is_connected(service->state_ipv4);
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		return is_connected(service->state_ipv6);
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return is_connected(service->state_ipv4) &&
			is_connected(service->state_ipv6);
	}

	return false;
}
enum connman_service_security __connman_service_get_security(
				struct connman_service *service)
{
	if (!service)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;

	return service->security;
}

const char *__connman_service_get_phase2(struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->phase2;
}

bool __connman_service_wps_enabled(struct connman_service *service)
{
	if (!service)
		return false;

	return service->wps;
}

void __connman_service_mark_dirty(void)
{
	services_dirty = true;
}

/**
 * __connman_service_set_favorite_delayed:
 * @service: service structure
 * @favorite: favorite value
 * @delay_ordering: do not order service sequence
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite_delayed(struct connman_service *service,
					bool favorite,
					bool delay_ordering)
{
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->favorite == favorite)
		return -EALREADY;

	service->favorite = favorite;

	favorite_changed(service);

	if (!delay_ordering) {

		service_list_sort();

		__connman_connection_update_gateway();
	}

	return 0;
}

/**
 * __connman_service_set_favorite:
 * @service: service structure
 * @favorite: favorite value
 *
 * Change the favorite setting of service
 */
int __connman_service_set_favorite(struct connman_service *service,
						bool favorite)
{
	return __connman_service_set_favorite_delayed(service, favorite,
							false);
}

bool connman_service_get_favorite(struct connman_service *service)
{
	return service->favorite;
}

bool connman_service_get_saved(struct connman_service *service)
{
	return service_saved_value(service);
}

bool connman_service_get_autoconnect(struct connman_service *service)
{
	return service->autoconnect;
}

int __connman_service_set_immutable(struct connman_service *service,
						bool immutable)
{
	if (service->hidden)
		return -EOPNOTSUPP;

	if (service->immutable == immutable)
		return 0;

	service->immutable = immutable;

	immutable_changed(service);

	return 0;
}

int __connman_service_set_ignore(struct connman_service *service,
						bool ignore)
{
	if (!service)
		return -EINVAL;

	service->ignore = ignore;

	return 0;
}

void __connman_service_set_string(struct connman_service *service,
				  const char *key, const char *value)
{
	if (service->hidden)
		return;
	if (g_str_equal(key, PROP_EAP)) {
		set_eap_method(service, value);
	} else if (g_str_equal(key, PROP_IDENTITY)) {
		set_identity(service, value);
	} else if (g_str_equal(key, "AnonymousIdentity")) {
		g_free(service->anonymous_identity);
		service->anonymous_identity = g_strdup(value);
	} else if (g_str_equal(key, "CACertFile")) {
		g_free(service->ca_cert_file);
		service->ca_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "CACert")) {
		g_free(service->ca_cert);
		service->ca_cert = g_strdup(value);
	} else if (g_str_equal(key, "SubjectMatch")) {
		g_free(service->subject_match);
		service->subject_match = g_strdup(value);
	} else if (g_str_equal(key, "AltSubjectMatch")) {
		g_free(service->altsubject_match);
		service->altsubject_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainSuffixMatch")) {
		g_free(service->domain_suffix_match);
		service->domain_suffix_match = g_strdup(value);
	} else if (g_str_equal(key, "DomainMatch")) {
		g_free(service->domain_match);
		service->domain_match = g_strdup(value);
	} else if (g_str_equal(key, "ClientCertFile")) {
		g_free(service->client_cert_file);
		service->client_cert_file = g_strdup(value);
	} else if (g_str_equal(key, "ClientCert")) {
		g_free(service->client_cert);
		service->client_cert = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyFile")) {
		g_free(service->private_key_file);
		service->private_key_file = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKey")) {
		g_free(service->private_key);
		service->private_key = g_strdup(value);
	} else if (g_str_equal(key, "PrivateKeyPassphrase")) {
		g_free(service->private_key_passphrase);
		service->private_key_passphrase = g_strdup(value);
	} else if (g_str_equal(key, PROP_PHASE2)) {
		g_free(service->phase2);
		service->phase2 = g_strdup(value);
	} else if (g_str_equal(key, PROP_PASSPHRASE))
		__connman_service_set_passphrase(service, value);
}

void __connman_service_set_search_domains(struct connman_service *service,
					char **domains)
{
	searchdomain_remove_all(service);

	if (service->domains)
		g_strfreev(service->domains);

	service->domains = g_strdupv(domains);

	searchdomain_add_all(service);
}

int __connman_service_set_mdns(struct connman_service *service,
			bool enabled)
{
	service->mdns_config = enabled;

	return set_mdns(service, enabled);
}

static void report_error_cb(void *user_context, bool retry,
							void *user_data)
{
    DBG("retry %d",retry);
	struct connman_service *service = user_context;

	if (retry)
		__connman_service_connect(service,
			service->connect_reason);
	else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		__connman_service_clear_error(service);

		service_complete(service);
		__connman_connection_update_gateway();
	}
}

static int check_wpspin(struct connman_service *service, const char *wpspin)
{
	int length;
	guint i;

	if (!wpspin)
		return 0;

	length = strlen(wpspin);

	/* If 0, it will mean user wants to use PBC method */
	if (length == 0) {
		connman_network_set_string(service->network,
							"WiFi.PinWPS", NULL);
		return 0;
	}

	/* A WPS PIN is always 8 chars length,
	 * its content is in digit representation.
	 */
	if (length != 8)
		return -ENOKEY;

	for (i = 0; i < 8; i++)
		if (!isdigit((unsigned char) wpspin[i]))
			return -ENOKEY;

	connman_network_set_string(service->network, "WiFi.PinWPS", wpspin);

	return 0;
}

static void request_input_cb(struct connman_service *service,
			bool values_received,
			const char *name, int name_len,
			const char *identity, const char *passphrase,
			bool wps, const char *wpspin,
			const char *error, void *user_data)
{
	struct connman_device *device;
	const char *security;
	int err = 0;

	DBG("RequestInput return, %p", service);
	__connman_device_keep_network(NULL);
	autoconnect_paused = false;

	if (error) {
		DBG("error: %s", error);

		if (g_strcmp0(error,
				"net.connman.Agent.Error.Canceled") == 0) {
			err = -ECONNABORTED;

			if (service->hidden)
				__connman_service_return_error(service,
							ECONNABORTED,
							user_data);
		} else {
			err = -ETIMEDOUT;

			if (service->hidden)
				__connman_service_return_error(service,
							ETIMEDOUT, user_data);
		}

		goto done;
	}

	if (!service->network) {
		if (service->hidden)
			__connman_service_return_error(service,
							ECONNABORTED,
							user_data);
		err = -ECONNABORTED;
		goto done;
	}

	if (service->hidden && name_len > 0 && name_len <= 32) {
		device = connman_network_get_device(service->network);
		security = connman_network_get_string(service->network,
							"WiFi.Security");
		err = __connman_device_request_hidden_scan(device,
						name, name_len,
						identity, passphrase,
						security, user_data);
		if (err < 0)
			__connman_service_return_error(service,	-err,
							user_data);
	}

	if (!values_received || service->hidden) {
		err = -EINVAL;
		goto done;
	}

	if (wps && service->network) {
		err = check_wpspin(service, wpspin);
		if (err < 0)
			goto done;

		connman_network_set_bool(service->network, "WiFi.UseWPS", wps);
	}

	if (identity)
		__connman_service_set_agent_identity(service, identity);

	if (passphrase)
		err = __connman_service_set_passphrase(service, passphrase);

 done:
	if (err >= 0) {
		/* We forget any previous error. */
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		__connman_service_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_USER);

	} else if (err == -ENOKEY) {
		__connman_service_indicate_error(service,
					CONNMAN_SERVICE_ERROR_INVALID_KEY);
	} else {
		/* It is not relevant to stay on Failure state
		 * when failing is due to wrong user input */
		if (service->state != CONNMAN_SERVICE_STATE_IDLE) {
			service->state = CONNMAN_SERVICE_STATE_IDLE;
			state_changed(service);
		}

		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		if (!service->hidden) {
			/*
			 * If there was a real error when requesting
			 * hidden scan, then that error is returned already
			 * to the user somewhere above so do not try to
			 * do this again.
			 */
			__connman_service_return_error(service,	-err,
							user_data);
		}

		service_complete(service);
		__connman_connection_update_gateway();
	}
}

static void downgrade_connected_services(void)
{
	struct connman_service *up_service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		up_service = list->data;

		if (!is_connected(up_service->state))
			continue;

		if (up_service->state == CONNMAN_SERVICE_STATE_ONLINE)
			return;

		downgrade_state(up_service);
	}
}

static int service_update_preferred_order(struct connman_service *default_service,
		struct connman_service *new_service,
		enum connman_service_state new_state)
{
	unsigned int *tech_array;
	int i;

	if (!default_service || default_service == new_service ||
			default_service->state != new_state)
		return 0;

	tech_array = connman_setting_get_uint_list("PreferredTechnologies");
	if (tech_array) {

		for (i = 0; tech_array[i] != 0; i += 1) {
			if (default_service->type == tech_array[i])
				return -EALREADY;

			if (new_service->type == tech_array[i]) {
				switch_default_service(default_service,
						new_service);
				__connman_connection_update_gateway();
				return 0;
			}
		}
	}

	return -EALREADY;
}

static void single_connected_tech(struct connman_service *allowed)
{
	struct connman_service *service;
	GSList *services = NULL, *list;
	GList *iter;

	DBG("keeping %p %s", allowed, allowed->path);

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

		if (!is_connected(service->state))
			break;

		if (service == allowed)
			continue;

		services = g_slist_prepend(services, service);
	}

	for (list = services; list; list = list->next) {
		service = list->data;

		DBG("disconnecting %p %s", service, service->path);
		__connman_service_disconnect(service);
	}

	g_slist_free(services);
}

static const char *get_dbus_sender(struct connman_service *service)
{
	if (!service->pending)
		return NULL;

	return dbus_message_get_sender(service->pending);
}

static int service_indicate_state(struct connman_service *service)
{
	enum connman_service_state old_state, new_state;
	struct connman_service *def_service;
	enum connman_ipconfig_method method;
	int result;

	if (!service)
		return -EINVAL;

	old_state = service->state;
	new_state = combine_state(service->state_ipv4, service->state_ipv6);

	DBG("service %p old %s - new %s/%s => %s",
					service,
					state2string(old_state),
					state2string(service->state_ipv4),
					state2string(service->state_ipv6),
					state2string(new_state));

	if (old_state == new_state)
		return -EALREADY;

	def_service = connman_service_get_default();

	if (new_state == CONNMAN_SERVICE_STATE_ONLINE) {
		service->connect_retry_timeout = 0;
		if (service->connect_retry_timer) {
			g_source_remove(service->connect_retry_timer);
			service->connect_retry_timer = 0;
		}

		result = service_update_preferred_order(def_service,
				service, new_state);
		if (result == -EALREADY)
			return result;
	}

	if (old_state == CONNMAN_SERVICE_STATE_ONLINE)
		__connman_notifier_leave_online(service->type);

	if (is_connected(old_state) && !is_connected(new_state))
		searchdomain_remove_all(service);

	service->state = new_state;
	state_changed(service);

	if (!is_connected(old_state) && is_connected(new_state))
		searchdomain_add_all(service);

	switch(new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
		if (old_state != CONNMAN_SERVICE_STATE_DISCONNECT)
			__connman_service_disconnect(service);
		break;

	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		break;

	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;

	case CONNMAN_SERVICE_STATE_READY:
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		service_set_new_service(service, false);

		default_changed();

		def_service = connman_service_get_default();

		service_update_preferred_order(def_service, service, new_state);

		__connman_service_set_favorite(service, true);

		reply_pending(service, 0);

		if (service->type == CONNMAN_SERVICE_TYPE_WIFI &&
			connman_network_get_bool(service->network,
						"WiFi.UseWPS")) {
			const char *pass;

			pass = connman_network_get_string(service->network,
							"WiFi.Passphrase");

			__connman_service_set_passphrase(service, pass);

			connman_network_set_bool(service->network,
							"WiFi.UseWPS", false);
		}

		gettimeofday(&service->modified, NULL);
		service_save(service);

		domain_changed(service);
		proxy_changed(service);

		if (old_state != CONNMAN_SERVICE_STATE_ONLINE)
			__connman_notifier_connect(service->type);

		method = __connman_ipconfig_get_method(service->ipconfig_ipv6);
		if (method == CONNMAN_IPCONFIG_METHOD_OFF)
			__connman_ipconfig_disable_ipv6(service->ipconfig_ipv6);

		if (connman_setting_get_bool("SingleConnectedTechnology"))
			single_connected_tech(service);
		else if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			vpn_auto_connect();

		break;

	case CONNMAN_SERVICE_STATE_ONLINE:

		break;

	case CONNMAN_SERVICE_STATE_DISCONNECT:
		set_error(service, CONNMAN_SERVICE_ERROR_UNKNOWN);

		reply_pending(service, ECONNABORTED);

		default_changed();

		__connman_wispr_stop(service);

		__connman_wpad_stop(service);

		domain_changed(service);
		proxy_changed(service);


		/*
		 * Previous services which are connected and which states
		 * are set to online should reset relevantly ipconfig_state
		 * to ready so wispr/portal will be rerun on those
		 */
		downgrade_connected_services();

		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
		break;

	case CONNMAN_SERVICE_STATE_FAILURE:
		if (!service->connect_retry_timer) {
			/* Schedule a retry, increasing timeout if necessary */
			if (service->connect_retry_timer <
						CONNECT_RETRY_TIMEOUT_MAX)
				service->connect_retry_timeout +=
					CONNECT_RETRY_TIMEOUT_STEP;

			DBG("service %p retry timeout %d", service,
					service->connect_retry_timeout);
			service->connect_retry_timer =
				connman_wakeup_timer_add_seconds
					(service->connect_retry_timeout,
						service_retry_connect, service);
		}

		if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER) {
			connman_agent_report_error(service, service->path,
						error2string(service->error),
						report_error_cb,
						get_dbus_sender(service),
						NULL);
		}
		service_complete(service);
		break;
	}

	service_list_sort();

	__connman_connection_update_gateway();

	if ((old_state == CONNMAN_SERVICE_STATE_ONLINE &&
			new_state != CONNMAN_SERVICE_STATE_READY) ||
		(old_state == CONNMAN_SERVICE_STATE_READY &&
			new_state != CONNMAN_SERVICE_STATE_ONLINE)) {
		__connman_notifier_disconnect(service->type);
	}

	if (new_state == CONNMAN_SERVICE_STATE_ONLINE) {
		__connman_notifier_enter_online(service->type);
		default_changed();
	}

	if (new_state == CONNMAN_SERVICE_STATE_READY) {
		/*
		 * Start online check always when upgrading to ready state.
		 * This is because sorting is based also on the state and in
		 * case there is an online service as default, e.g., mobile
		 * data then other, a WLAN service, for instance, would not
		 * start online check when becoming ready.
		*/
		if (old_state != CONNMAN_SERVICE_STATE_ONLINE) {
			if (__connman_ipconfig_get_method(
					service->ipconfig_ipv4) !=
						CONNMAN_IPCONFIG_METHOD_OFF)
				__connman_service_wispr_start(service,
						CONNMAN_IPCONFIG_TYPE_IPV4);

			if (__connman_ipconfig_get_method(
					service->ipconfig_ipv6) !=
						CONNMAN_IPCONFIG_METHOD_OFF)
				__connman_service_wispr_start(service,
						CONNMAN_IPCONFIG_TYPE_IPV6);
		}

		if (service->type == CONNMAN_SERVICE_TYPE_VPN)
			default_changed();
	}

	return 0;
}

int __connman_service_indicate_error(struct connman_service *service,
					enum connman_service_error error)
{
	DBG("service %p error %d", service, error);

	if (!service)
		return -EINVAL;

	if (service->state == CONNMAN_SERVICE_STATE_FAILURE)
		return -EALREADY;

	set_error(service, error);

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	return 0;
}

int __connman_service_clear_error(struct connman_service *service)
{
	DBusMessage *pending, *provider_pending;

	DBG("service %p", service);

	if (!service)
		return -EINVAL;

	if (service->state != CONNMAN_SERVICE_STATE_FAILURE)
		return -EINVAL;

	pending = service->pending;
	service->pending = NULL;
	provider_pending = service->provider_pending;
	service->provider_pending = NULL;

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV4);

	service->pending = pending;
	service->provider_pending = provider_pending;

	return 0;
}

int __connman_service_indicate_default(struct connman_service *service)
{
	DBG("service %p state %s", service, state2string(service->state));

	if (!is_connected(service->state)) {
		/*
		 * If service is not yet fully connected, then we must not
		 * change the default yet. The default gw will be changed
		 * after the service state is in ready.
		 */
		return -EINPROGRESS;
	}

	default_changed();

	return 0;
}

enum connman_service_state __connman_service_ipconfig_get_state(
					struct connman_service *service,
					enum connman_ipconfig_type type)
{
	if (!service)
		return CONNMAN_SERVICE_STATE_UNKNOWN;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		return service->state_ipv4;

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6)
		return service->state_ipv6;

	return CONNMAN_SERVICE_STATE_UNKNOWN;
}

/*
 * How many networks are connected at the same time. If more than 1,
 * then set the rp_filter setting properly (loose mode routing) so that network
 * connectivity works ok. This is only done for IPv4 networks as IPv6
 * does not have rp_filter knob.
 */
static int connected_networks_count;
static int original_rp_filter;

static void service_rp_filter(struct connman_service *service,
				bool connected)
{
	enum connman_ipconfig_method method;

	method = __connman_ipconfig_get_method(service->ipconfig_ipv4);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		return;
	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
		break;
	}

	if (connected) {
		if (connected_networks_count == 1) {
			int filter_value;
			filter_value = __connman_ipconfig_set_rp_filter();
			if (filter_value < 0)
				return;

			original_rp_filter = filter_value;
		}
		connected_networks_count++;

	} else {
		if (connected_networks_count == 2)
			__connman_ipconfig_unset_rp_filter(original_rp_filter);

		connected_networks_count--;
		if (connected_networks_count < 0)
			connected_networks_count = 0;
	}

	DBG("%s %s ipconfig %p method %d count %d filter %d",
		connected ? "connected" : "disconnected", service->identifier,
		service->ipconfig_ipv4, method,
		connected_networks_count, original_rp_filter);
}

static void redo_wispr(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	DBG("service %p type %d", service, type);

	int refcount = service->refcount - 1;
	connman_service_unref(service);
	if (refcount == 0) {
		DBG("Service %p already removed", service);
		return;
	}

	DBG("Retrying %s WISPr for %p %s",
		__connman_ipconfig_type2string(type),
		service, service->name);

	__connman_wispr_start(service, type);
}

static gboolean redo_wispr_ipv4(gpointer user_data)
{
	struct connman_service *service = user_data;

	service->online_timeout_ipv4 = 0;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV4);

	return FALSE;
}

static gboolean redo_wispr_ipv6(gpointer user_data)
{
	struct connman_service *service = user_data;

	service->online_timeout_ipv6 = 0;

	redo_wispr(service, CONNMAN_IPCONFIG_TYPE_IPV6);

	return FALSE;
}

static gboolean downgrade_state_ipv4(gpointer user_data)
{
	struct connman_service *service = (struct connman_service *)user_data;
	__connman_service_ipconfig_indicate_state(service, CONNMAN_SERVICE_STATE_READY, CONNMAN_IPCONFIG_TYPE_IPV4);
	return false;
}

static gboolean downgrade_state_ipv6(gpointer user_data)
{
	struct connman_service *service = (struct connman_service *)user_data;
	__connman_service_ipconfig_indicate_state(service, CONNMAN_SERVICE_STATE_READY, CONNMAN_IPCONFIG_TYPE_IPV6);
	return false;
}

int __connman_service_online_check_failed(struct connman_service *service,
					enum connman_ipconfig_type type)
{
	GSourceFunc downgrade_func;
	GSourceFunc redo_func;
	unsigned int *interval;
	guint timeout;

	DBG("service %p type %s\n",
		service, __connman_ipconfig_type2string(type));

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		downgrade_func = downgrade_state_ipv4;
		interval = &service->online_check_interval_ipv4;
		redo_func = redo_wispr_ipv4;
	} else {
		downgrade_func = downgrade_state_ipv6;
		interval = &service->online_check_interval_ipv6;
		redo_func = redo_wispr_ipv6;
	}

	DBG("service %p type %s interval %d", service,
		__connman_ipconfig_type2string(type), *interval);

	if (!__connman_service_is_connected_state(service, type))
		return 0;

	/* Revert back to ready state */
	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_IPV4:
		if (service->state_ipv4 == CONNMAN_SERVICE_STATE_ONLINE)
			g_idle_add(downgrade_func, service);
		break;
	case CONNMAN_IPCONFIG_TYPE_IPV6:
		if (service->state_ipv6 == CONNMAN_SERVICE_STATE_ONLINE)
			g_idle_add(downgrade_func, service);
		break;
	default:
		;
	}

	timeout = connman_wakeup_timer_add_seconds(*interval * *interval,
				redo_func, connman_service_ref(service));
	if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
		if (service->online_timeout_ipv4)
			g_source_remove(service->online_timeout_ipv4);

		service->online_timeout_ipv4 = timeout;
	} else {
		if (service->online_timeout_ipv6)
			g_source_remove(service->online_timeout_ipv6);

		service->online_timeout_ipv6 = timeout;
	}


	/* Increment the interval for the next time, set a maximum timeout of
	 * online_check_max_interval seconds * online_check_max_interval seconds.
	 */
	if (*interval < online_check_max_interval)
		(*interval)++;

	return -EAGAIN;
}

int __connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type)
{
	struct connman_ipconfig *ipconfig = NULL;
	enum connman_service_state old_state;
	enum connman_ipconfig_method method;

	if (!service)
		return -EINVAL;

	switch (type) {
	case CONNMAN_IPCONFIG_TYPE_UNKNOWN:
	case CONNMAN_IPCONFIG_TYPE_ALL:
		return -EINVAL;

	case CONNMAN_IPCONFIG_TYPE_IPV4:
		service->online_check_interval_ipv4 = ONLINE_CHECK_RETRY_COUNT;
		old_state = service->state_ipv4;
		ipconfig = service->ipconfig_ipv4;

		break;

	case CONNMAN_IPCONFIG_TYPE_IPV6:
		service->online_check_interval_ipv6 = ONLINE_CHECK_RETRY_COUNT;
		old_state = service->state_ipv6;
		ipconfig = service->ipconfig_ipv6;

		break;
	}

	if (!ipconfig)
		return -EINVAL;

	method = __connman_ipconfig_get_method(ipconfig);

	switch (method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
		if (new_state != CONNMAN_SERVICE_STATE_IDLE)
			connman_warn("ipconfig state %d ipconfig method %d",
				new_state, method);

		new_state = CONNMAN_SERVICE_STATE_IDLE;
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		break;

	}

	/* Any change? */
	if (old_state == new_state)
		return -EALREADY;

	DBG("service %p (%s) old state %d (%s) new state %d (%s) type %d (%s)",
		service, service ? service->identifier : NULL,
		old_state, state2string(old_state),
		new_state, state2string(new_state),
		type, __connman_ipconfig_type2string(type));

	switch (new_state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		break;
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		break;
	case CONNMAN_SERVICE_STATE_READY:
		if (connman_setting_get_bool("EnableOnlineCheck")) {
			if (type == CONNMAN_IPCONFIG_TYPE_IPV4) {
				check_proxy_setup(service);
			} else {
				service->online_check_interval_ipv6 =
						ONLINE_CHECK_RETRY_COUNT;
				__connman_service_wispr_start(service, type);
			}
		} else
			connman_info("Online check disabled. "
				"Default service remains in READY state.");
		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, true);
		set_mdns(service, service->mdns_config);
		break;
	case CONNMAN_SERVICE_STATE_ONLINE:
		break;
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		if (service->state == CONNMAN_SERVICE_STATE_IDLE)
			return -EINVAL;

		if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
			service_rp_filter(service, false);

		__connman_service_nameserver_del_routes(service, type);

		break;

	case CONNMAN_SERVICE_STATE_IDLE:
	case CONNMAN_SERVICE_STATE_FAILURE:
		__connman_ipconfig_disable(ipconfig);
		if (service->nameservers_ipv4_refcount) {
			DBG("service %p reset IPv4 refcount (%d)", service,
					service->nameservers_ipv4_refcount);
			service->nameservers_ipv4_refcount = 0;
		}

		if (service->nameservers_ipv6_refcount) {
			DBG("service %p reset IPv6 refcount (%d)", service,
					service->nameservers_ipv6_refcount);
			service->nameservers_ipv6_refcount = 0;
		}

		break;
	}

	if (is_connected(old_state) && !is_connected(new_state)) {
		nameserver_remove_all(service, type);
		cancel_online_check(service);
	}

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4)
		service->state_ipv4 = new_state;
	else
		service->state_ipv6 = new_state;

	if (!is_connected(old_state) && is_connected(new_state))
		nameserver_add_all(service, type);

	__connman_timeserver_sync(service);

	return service_indicate_state(service);
}

int connman_service_ipconfig_indicate_state(struct connman_service *service,
					enum connman_service_state new_state,
					enum connman_ipconfig_type type,
					bool notify_settings_change)
{
	int err;

	DBG("service %p new state %d type %d notify %d", service, new_state,
						type, notify_settings_change);

	err = __connman_service_ipconfig_indicate_state(service, new_state,
						type);

	/*
	 * By default ipconfig change does not send IP address settings change.
	 * This allows to enforce the notification when the state is connected.
	 */
	if ((!err || err == -EALREADY) && is_connected(new_state) &&
				notify_settings_change) {
		switch(type) {
		case CONNMAN_IPCONFIG_TYPE_IPV4:
			DBG("IPv4 settings changed");
			settings_changed(service, service->ipconfig_ipv4);
			break;
		case CONNMAN_IPCONFIG_TYPE_IPV6:
			DBG("IPv6 settings changed");
			settings_changed(service, service->ipconfig_ipv6);
			break;
		default:
			DBG("unknown type %d", type);
			break;
		}

		address_updated(service, type);
	} else {
		DBG("err %d", err);
	}

	return err;
}

static bool prepare_network(struct connman_service *service)
{
	enum connman_network_type type;
	unsigned int ssid_len;

	type = connman_network_get_type(service->network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		return false;
	case CONNMAN_NETWORK_TYPE_WIFI:
		if (!connman_network_get_blob(service->network, "WiFi.SSID",
						&ssid_len))
			return false;

		if (service->passphrase)
			connman_network_set_string(service->network,
				"WiFi.Passphrase", service->passphrase);
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
	case CONNMAN_NETWORK_TYPE_GADGET:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		break;
	}

	return true;
}

static void prepare_8021x(struct connman_service *service)
{
	if (service->eap)
		connman_network_set_string(service->network, "WiFi.EAP",
								service->eap);

	if (service->identity)
		connman_network_set_string(service->network, "WiFi.Identity",
							service->identity);

	if (service->anonymous_identity)
		connman_network_set_string(service->network,
						"WiFi.AnonymousIdentity",
						service->anonymous_identity);

	connman_network_set_string(service->network, "WiFi.CACert",
							service->ca_cert);
	connman_network_set_string(service->network, "WiFi.CACertFile",
							service->ca_cert_file);

	connman_network_set_string(service->network, "WiFi.SubjectMatch",
							service->subject_match);

	connman_network_set_string(service->network, "WiFi.AltSubjectMatch",
							service->altsubject_match);

	connman_network_set_string(service->network, "WiFi.DomainSuffixMatch",
							service->domain_suffix_match);

	connman_network_set_string(service->network, "WiFi.DomainMatch",
							service->domain_match);

	connman_network_set_string(service->network,
						"WiFi.ClientCert",
						service->client_cert);
	connman_network_set_string(service->network,
						"WiFi.ClientCertFile",
						service->client_cert_file);

	connman_network_set_string(service->network,
						"WiFi.PrivateKey",
						service->private_key);
	connman_network_set_string(service->network,
						"WiFi.PrivateKeyFile",
						service->private_key_file);

	if (service->private_key_passphrase)
		connman_network_set_string(service->network,
					"WiFi.PrivateKeyPassphrase",
					service->private_key_passphrase);

	connman_network_set_string(service->network, "WiFi.Phase2",
							service->phase2);
}

static int service_connect(struct connman_service *service)
{
	int err;

	if (service->hidden)
		return -EPERM;

	if (service->disabled)
		return -EPERM;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		return -EINVAL;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_WIFI:
		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
			break;
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			if (service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY)
				return -ENOKEY;

			if (!service->passphrase) {
				if (!service->network)
					return -EOPNOTSUPP;

				if (!service->wps ||
					!connman_network_get_bool(service->network, "WiFi.UseWPS"))
					return -ENOKEY;
			}
			break;

		case CONNMAN_SERVICE_SECURITY_8021X:
			if (!service->eap) {
				/* Give WPS a chance */
				if (!service->wps ||
					!connman_network_get_bool(service->network,"WiFi.UseWPS")) {
					connman_warn("EAP type has not been "
						"found. "
						"Most likely ConnMan is not "
						"able to find a configuration "
						"for given 8021X network. "
						"Check SSID or Name match with "
						"the network name.");
					return -EINVAL;
				}

				break;
			}

			/*
			 * never request credentials if using EAP-TLS
			 * (EAP-TLS networks need to be fully provisioned)
			 */
			if (g_str_equal(service->eap, "tls"))
				break;

			/*
			 * Return -ENOKEY if either identity or passphrase is
			 * missing. Agent provided credentials can be used as
			 * fallback if needed.
			 */
			if (((!service->identity &&
					!service->agent_identity) ||
					!service->passphrase) ||
					service->error == CONNMAN_SERVICE_ERROR_INVALID_KEY) {
				/* Give WPS a chance */
				if (!service->wps ||
					!connman_network_get_bool(service->network, "WiFi.UseWPS"))
					return -ENOKEY;

				break;
			}

			break;
		}
		break;
	}

	if (service->network) {
		if (!prepare_network(service))
			return -EINVAL;

		switch (service->security) {
		case CONNMAN_SERVICE_SECURITY_UNKNOWN:
		case CONNMAN_SERVICE_SECURITY_NONE:
		case CONNMAN_SERVICE_SECURITY_WEP:
		case CONNMAN_SERVICE_SECURITY_PSK:
		case CONNMAN_SERVICE_SECURITY_WPA:
		case CONNMAN_SERVICE_SECURITY_RSN:
			break;
		case CONNMAN_SERVICE_SECURITY_8021X:
			prepare_8021x(service);
			break;
		}

		err = __connman_network_connect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = __connman_provider_connect(service->provider,
						get_dbus_sender(service));
	else
		return -EOPNOTSUPP;

	switch (err) {
	case 0:
	case -EALREADY:
	case -EINPROGRESS:
		break;
	default:
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV4);
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_FAILURE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	return err;
}

int __connman_service_connect(struct connman_service *service,
			enum connman_service_connect_reason reason)
{
	int err;

	DBG("service %p state %s connect reason %s -> %s",
		service, state2string(service->state),
		reason2string(service->connect_reason),
		reason2string(reason));

	if (is_connected(service->state))
		return -EISCONN;

	if (is_connecting(service->state))
		return -EALREADY;

	switch (service->type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
		return -EINVAL;

	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_WIFI:
		break;
	}

	if (!is_ipconfig_usable(service))
		return -ENOLINK;

	__connman_service_clear_error(service);

	err = service_connect(service);

	DBG("service %p err %d", service, err);

	service->connect_reason = reason;

	switch (err) {
	case 0:
		return 0;
	case -EALREADY:
		return -EALREADY;
	case -EINPROGRESS:
		/*
		 * VPN will start connect timeout when it enters CONFIGURATION
		 * state.
		 */
		if (service->type != CONNMAN_SERVICE_TYPE_VPN)
			__connman_service_start_connect_timeout(service, false);

		return -EINPROGRESS;
	default:
		break;
	}

	if (service->network)
		__connman_network_disconnect(service->network);
	else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
				service->provider)
			connman_provider_disconnect(service->provider);

	if (service->connect_reason == CONNMAN_SERVICE_CONNECT_REASON_USER) {

		/*
		 * User-initiated connect would release the previously kept
		 * network in case if passphrase request never completes due
		 * to a user agent crash, bug or whatever.
		 */
		__connman_device_keep_network(NULL);
		autoconnect_paused = false;

		if (err == -ENOKEY || err == -EPERM) {
			DBusMessage *pending = NULL;
			const char *dbus_sender = get_dbus_sender(service);

			/*
			 * We steal the reply here. The idea is that the
			 * connecting client will see the connection status
			 * after the real hidden network is connected or
			 * connection failed.
			 */
			if (service->hidden) {
				pending = service->pending;
				service->pending = NULL;
			}

			err = __connman_agent_request_passphrase_input(service,
					request_input_cb,
					dbus_sender,
					pending);

			DBG("passphrase input status %d", err);

			/*
			 * Prevent the network from being removed from the list
			 * while passphrase request is pending.
			 */
			if (err == -EINPROGRESS) {
				__connman_device_keep_network(service->network);
				autoconnect_paused = true;
			}

			if (service->hidden && err != -EINPROGRESS)
				service->pending = pending;

			return err;
		}
	}

	return err;
}

int __connman_service_disconnect(struct connman_service *service)
{
	int err;

	DBG("service %p", service);

	service->connect_reason = CONNMAN_SERVICE_CONNECT_REASON_NONE;
	service->proxy = CONNMAN_SERVICE_PROXY_METHOD_UNKNOWN;

	__connman_wispr_stop(service);
	cancel_online_check(service);

	reply_pending(service, ECONNABORTED);

	if (service->network) {
		err = __connman_network_disconnect(service->network);
	} else if (service->type == CONNMAN_SERVICE_TYPE_VPN &&
					service->provider)
		err = connman_provider_disconnect(service->provider);
	else
		return -EOPNOTSUPP;

	if (err < 0 && err != -EINPROGRESS)
		return err;

	__connman_6to4_remove(service->ipconfig_ipv4);

	if (service->ipconfig_ipv4)
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv4,
							NULL);
	else
		__connman_ipconfig_set_proxy_autoconfig(service->ipconfig_ipv6,
							NULL);

	__connman_ipconfig_address_remove(service->ipconfig_ipv4);
	settings_changed(service, service->ipconfig_ipv4);

	__connman_ipconfig_address_remove(service->ipconfig_ipv6);
	settings_changed(service, service->ipconfig_ipv6);

	__connman_ipconfig_disable(service->ipconfig_ipv4);
	__connman_ipconfig_disable(service->ipconfig_ipv6);

	return err;
}

int __connman_service_disconnect_all(void)
{
	struct connman_service *service;
	GSList *services = NULL, *list;
	GList *iter;

	DBG("");

	for (iter = service_list; iter; iter = iter->next) {
		service = iter->data;

		if (!is_connected(service->state))
			break;

		services = g_slist_prepend(services, service);
	}

	for (list = services; list; list = list->next) {
		struct connman_service *service = list->data;

		service->ignore = true;

		__connman_service_disconnect(service);
	}

	g_slist_free(services);

	return 0;
}

/**
 * lookup_by_identifier:
 * @identifier: service identifier
 *
 * Look up a service by identifier (reference count will not be increased)
 */
static struct connman_service *lookup_by_identifier(const char *identifier)
{
	return g_hash_table_lookup(service_hash, identifier);
}

struct connman_service *connman_service_lookup_from_identifier(const char* identifier)
{
	return identifier ? lookup_by_identifier(identifier) : NULL;
}

struct provision_user_data {
	const char *ident;
	int ret;
};

static void provision_changed(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct provision_user_data *data = user_data;
	const char *path = data->ident;
	int ret;

	ret = __connman_config_provision_service_ident(service, path,
			service->config_file, service->config_entry);
	if (ret > 0)
		data->ret = ret;
}

int __connman_service_provision_changed(const char *ident)
{
	struct provision_user_data data = {
		.ident = ident,
		.ret = 0
	};

	g_list_foreach(service_list, provision_changed, (void *)&data);

	/*
	 * Because the provision_changed() might have set some services
	 * as favorite, we must sort the sequence now.
	 */
	if (services_dirty) {
		services_dirty = false;

		service_list_sort();

		__connman_connection_update_gateway();
	}

	return data.ret;
}

void __connman_service_set_config(struct connman_service *service,
				const char *file_id, const char *entry)
{
	if (!service)
		return;

	g_free(service->config_file);
	service->config_file = g_strdup(file_id);

	g_free(service->config_entry);
	service->config_entry = g_strdup(entry);
}

/**
 * __connman_service_get:
 * @identifier: service identifier
 *
 * Look up a service by identifier or create a new one if not found
 */
static struct connman_service *service_get(const char *identifier)
{
	struct connman_service *service;

	service = g_hash_table_lookup(service_hash, identifier);
	if (service) {
		/*
		 * No, we don't need to add a reference here.
		 * The caller will add one if needed. In our
		 * fork, service_hash keeps the reference which
		 * gets released when the service is removed
		 * from the table.
		 */
//		connman_service_ref(service);
		return service;
	}

	service = connman_service_create();
	if (!service)
		return NULL;

	DBG("service %p", service);

	service->identifier = g_strdup(identifier);
	stats_init(service);
	service_list = g_list_insert_sorted(service_list, service,
						service_compare);

	g_hash_table_insert(service_hash, service->identifier, service);

	return service;
}

static void service_removed(void *data)
{
	struct connman_service *service = data;

	service_schedule_removed(service);
	connman_service_unref(service);
}

/* Deduce the security type from the service identifier */
static enum connman_service_security security_from_ident(const char *ident)
{
	const char *str = NULL;

	if (ident) {
		const char *sep = strrchr(ident, '_');

		if (sep) {
			str = sep + 1;
		}
	}

	return __connman_service_string2security(str);
}

static bool service_default_mdns(enum connman_service_type type)
{
	bool val = false;

	switch (type){
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
		val = connman_setting_get_bool(CONF_DEFAULT_MDNS_CONFIGURATION);
		break;
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_P2P:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	}

	return val;
}

static struct connman_service *service_new(enum connman_service_type type,
							const char *ident)
{
	struct connman_service *service = connman_service_create();

	DBG("%p", service);

	service->identifier = g_strdup(ident);
	service->path = service_path(ident);
	service->type = type;
	service->mdns_config = service_default_mdns(type);
	service->security = security_from_ident(ident);
	stats_init(service);
	return service;
}

static void service_init(struct connman_service *service)
{
	/* Autoconnect is confused by the UNKNONW state */
	service->state = service->state_ipv4 =
	service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;

	/* Stick it into the table. The table holds the reference */
	g_hash_table_replace(service_hash, service->identifier, service);
	service_list = g_list_insert_sorted(service_list,
			connman_service_ref(service), service_compare);
	count_available_service_type(service, true);

	if (!service->ipconfig_ipv4) {
		service->ipconfig_ipv4 = create_ip4config(service, -1,
			CONNMAN_IPCONFIG_METHOD_DHCP);
		__connman_service_read_ip4config(service);
	}

	if (!service->ipconfig_ipv6) {
		service->ipconfig_ipv6 = create_ip6config(service, -1);
		__connman_service_read_ip6config(service);
	}

	g_dbus_register_interface(connection, service->path,
				CONNMAN_SERVICE_INTERFACE, service_methods,
				service_signals, NULL, service, NULL);
}

/* Note: config.c requires "service_ident" group in the keyfile */
const char *__connman_service_create(enum connman_service_type type,
				const char *ident, GKeyFile *settings)
{
	struct connman_service *service = lookup_by_identifier(ident);

	if (service) {
		/* Apply settings to the existing service */
		service_apply(service, settings);
	} else {
		/* Create a new one */
		service = service_new(type, ident);
		service_init(service);
		service_apply(service, settings);
		service_schedule_added(service);
		service_list_sort();
		__connman_notifier_service_add(service, service->name);
		__connman_connection_update_gateway();
		connman_service_unref(service);
	}

	/*
	 * service_apply() function sets service->hidden_service rather
	 * than service->hidden. It's hard to tell the difference between
	 * those two. In any case, here we need to check the hidden_service
	 * flag.
	 */
	if (service->hidden_service) {
		/* We need to throw a scan to detect hidden networks */
		__connman_device_request_scan(type);
	}

	/* Trigger autoconnect */
	if (service->autoconnect) {
		__connman_service_set_favorite(service, true);

		do_auto_connect(service, CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}

	/* Save the service */
	service_set_new_service(service, false);
	service_save(service);
	return service->path;
}

static void load_wifi_service(const char *ident)
{
	struct connman_service *service =
		service_new(CONNMAN_SERVICE_TYPE_WIFI, ident);

	if (service_load(service) == 0) {
		DBG("service %p path %s", service, service->path);
		service_init(service);
		connman_service_unref(service);
	} else {
		service_free(service);
	}
}

static gboolean load_wifi_services(gpointer unused)
{
	char **services = connman_storage_get_services();

	load_wifi_services_id = 0;

	if (services) {
		int i;

		for (i = 0; services[i]; i++) {
			const char *ident = services[i];
			const enum connman_service_type type =
				__connman_service_string2type(ident);

			DBG("service %d:%s", i, services[i]);

			if (type == CONNMAN_SERVICE_TYPE_WIFI &&
				!g_hash_table_contains(service_hash, ident))
				load_wifi_service(ident);
			else if (g_hash_table_contains(service_hash, ident))
				DBG("is in hash table, not loaded");
		}

		g_strfreev(services);
		service_list_sort();
	}

	return G_SOURCE_REMOVE;
}

static int service_register(struct connman_service *service)
{
	DBG("service %p", service);

	if (service->path)
		return -EALREADY;

	service->path = g_strdup_printf("%s/service/%s", CONNMAN_PATH,
						service->identifier);

	DBG("path %s", service->path);

	g_dbus_register_interface(connection, service->path,
					CONNMAN_SERVICE_INTERFACE,
					service_methods, service_signals,
							NULL, service, NULL);

	if (__connman_config_provision_service(service) < 0)
		service_load(service);

	service_list_sort();

	__connman_connection_update_gateway();

	return 0;
}

static void service_up(struct connman_ipconfig *ipconfig,
		const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s up", ifname);

	link_changed(service);
}

static void service_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	DBG("%s down", ifname);
}

static void service_lower_up(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	struct connman_stats *stats = stats_get(service);
	struct connman_stats_data data;

	DBG("%s lower up", ifname);
	if (__connman_ipconfig_get_stats(ipconfig, &data))
		__connman_stats_rebase(stats, &data);

	__connman_stats_set_index(stats,
				 __connman_ipconfig_get_index(ipconfig));
}

static void service_lower_down(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s lower down", ifname);

	service_save(service);
}

static void service_ip_bound(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	DBG("%s ip bound", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p ipconfig %p type %d method %d", service, ipconfig,
							type, method);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_AUTO)
		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_READY,
						CONNMAN_IPCONFIG_TYPE_IPV6);

	settings_changed(service, ipconfig);
	address_updated(service, type);
}

static void service_ip_release(struct connman_ipconfig *ipconfig,
			const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);
	enum connman_ipconfig_method method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
	enum connman_ipconfig_type type = CONNMAN_IPCONFIG_TYPE_UNKNOWN;

	DBG("%s ip release", ifname);

	type = __connman_ipconfig_get_config_type(ipconfig);
	method = __connman_ipconfig_get_method(ipconfig);

	DBG("service %p ipconfig %p type %d method %d", service, ipconfig,
							type, method);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV6 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);

	if (type == CONNMAN_IPCONFIG_TYPE_IPV4 &&
			method == CONNMAN_IPCONFIG_METHOD_OFF)
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV4);

	settings_changed(service, ipconfig);
}

static void service_route_changed(struct connman_ipconfig *ipconfig,
				const char *ifname)
{
	struct connman_service *service = __connman_ipconfig_get_data(ipconfig);

	DBG("%s route changed", ifname);

	settings_changed(service, ipconfig);
}

static const struct connman_ipconfig_ops service_ops = {
	.up		= service_up,
	.down		= service_down,
	.lower_up	= service_lower_up,
	.lower_down	= service_lower_down,
	.ip_bound	= service_ip_bound,
	.ip_release	= service_ip_release,
	.route_set	= service_route_changed,
	.route_unset	= service_route_changed,
};

static struct connman_ipconfig *create_ip4config(struct connman_service *service,
		int index, enum connman_ipconfig_method method)
{
	struct connman_ipconfig *ipconfig_ipv4;

	ipconfig_ipv4 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV4);
	if (!ipconfig_ipv4)
		return NULL;

	__connman_ipconfig_set_method(ipconfig_ipv4, method);

	__connman_ipconfig_set_data(ipconfig_ipv4, service);

	__connman_ipconfig_set_ops(ipconfig_ipv4, &service_ops);

	return ipconfig_ipv4;
}

static struct connman_ipconfig *create_ip6config(struct connman_service *service,
		int index)
{
	struct connman_ipconfig *ipconfig_ipv6;

	ipconfig_ipv6 = __connman_ipconfig_create(index,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	if (!ipconfig_ipv6)
		return NULL;

	__connman_ipconfig_set_data(ipconfig_ipv6, service);

	__connman_ipconfig_set_ops(ipconfig_ipv6, &service_ops);

	return ipconfig_ipv6;
}

void __connman_service_read_ip4config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv4)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv4, keyfile,
				service->identifier, "IPv4.");

	g_key_file_unref(keyfile);
}

void connman_service_create_ip4config(struct connman_service *service,
					int index)
{
	DBG("ipv4 %p", service->ipconfig_ipv4);

	if (service->ipconfig_ipv4) {
		__connman_ipconfig_set_index(service->ipconfig_ipv4, index);
		return;
	}

	service->ipconfig_ipv4 = create_ip4config(service, index,
			CONNMAN_IPCONFIG_METHOD_DHCP);
	__connman_service_read_ip4config(service);
}

void __connman_service_read_ip6config(struct connman_service *service)
{
	GKeyFile *keyfile;

	if (!service->ipconfig_ipv6)
		return;

	keyfile = connman_storage_load_service(service->identifier);
	if (!keyfile)
		return;

	__connman_ipconfig_load(service->ipconfig_ipv6, keyfile,
				service->identifier, "IPv6.");

	g_key_file_unref(keyfile);
}

void connman_service_create_ip6config(struct connman_service *service,
								int index)
{
	DBG("ipv6 %p", service->ipconfig_ipv6);

	if (service->ipconfig_ipv6) {
		__connman_ipconfig_set_index(service->ipconfig_ipv6, index);
		return;
	}

	service->ipconfig_ipv6 = create_ip6config(service, index);

	__connman_service_read_ip6config(service);
}

/**
 * connman_service_get_network:
 * @service: service structure
 *
 * Get network of the service
 */
struct connman_network *connman_service_get_network(
						struct connman_service *service)
{
	if (!service)
		return NULL;

	return service->network;
}

/**
 * connman_service_lookup_from_network:
 * @network: network structure
 *
 * Look up a service by network (reference count will not be increased)
 */
struct connman_service *connman_service_lookup_from_network(struct connman_network *network)
{
	struct connman_service *service;
	const char *ident, *group;
	char *name;

	if (!network)
		return NULL;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return NULL;

	group = connman_network_get_group(network);
	if (!group)
		return NULL;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = lookup_by_identifier(name);
	g_free(name);

	return service;
}

struct connman_service *__connman_service_lookup_from_index(int index)
{
	struct connman_service *service;
	GList *list;

	for (list = service_list; list; list = list->next) {
		service = list->data;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv4)
							== index)
			return service;

		if (__connman_ipconfig_get_index(service->ipconfig_ipv6)
							== index)
			return service;
	}

	return NULL;
}

struct connman_service *connman_service_lookup_from_index(int index)
{
	return __connman_service_lookup_from_index(index);
}

struct set_ipv6_data {
	struct connman_service *vpn;
	struct connman_service *transport;
	bool enable;
};

static void set_ipv6_for_service(gpointer value, gpointer user_data)
{
	struct connman_service *service = value;
	struct connman_ipconfig *ipconfig;
	struct connman_network *network;
	struct set_ipv6_data *data = user_data;
	int err;

	/*
	 * Ignore the vpn and not connected unless it is the transport. It is
	 * imperative to set the IPv6 parameters on the transport even though
	 * it is being disconnected. This ensures that the interface it is/was
	 * using is set to the previous state.
	 */
	if ((!is_connected(service->state || service == data->vpn) &&
						service != data->transport))
		return;

	DBG("%s service %p/%s", data->enable ? "enable" : "disable", service,
							service->identifier);

	network = service->network;
	if (!network)
		return;

	ipconfig = service->ipconfig_ipv6;
	if (!ipconfig)
		return;

	if (data->enable == __connman_ipconfig_ipv6_is_enabled(ipconfig)) {
		DBG("Ignore service, IPv6 already %s",
					data->enable ? "enabled" : "disabled");
		return;
	}

	if (data->enable) {
		/* Restore the original method before enabling. */
		__connman_ipconfig_ipv6_method_restore(ipconfig);

		/* To allow enabling remove force disabled. */
		__connman_ipconfig_ipv6_set_force_disabled(ipconfig, false);

		/*
		 * When changing to use another service the current service
		 * used as transport is disconnected first and in that case
		 * simply enable IPv6 via ipconfig instead of network to avoid
		 * state changes.
		 */
		if (service == data->transport && !is_connected(service->state))
			err = __connman_ipconfig_enable_ipv6(ipconfig);
		else
			err = __connman_network_enable_ipconfig(network,
								ipconfig);

		if (err)
			connman_warn("cannot re-enable IPv6 on %s",
						service->identifier);
	} else {
		/* Save the IPv6 method for enabling and clear network conf */
		__connman_ipconfig_ipv6_method_save(ipconfig);
		__connman_network_clear_ipconfig(network, ipconfig);
		__connman_ipconfig_gateway_remove(ipconfig);

		/* Disconnect and clear address */
		__connman_service_ipconfig_indicate_state(service,
					CONNMAN_SERVICE_STATE_DISCONNECT,
					CONNMAN_IPCONFIG_TYPE_IPV6);
		__connman_ipconfig_address_remove(ipconfig);

		/*
		 * Disables IPv6 on ipconfig and sets the force_disabled
		 * as true.
		 */
		__connman_ipconfig_set_method(ipconfig,
						CONNMAN_IPCONFIG_METHOD_OFF);
		err = __connman_network_enable_ipconfig(network, ipconfig);
		if (err)
			connman_warn("cannot disable IPv6 on %s",
							service->identifier);

		/* Set force disabled on after disabling. */
		__connman_ipconfig_ipv6_set_force_disabled(ipconfig, true);

		__connman_service_ipconfig_indicate_state(service,
						CONNMAN_SERVICE_STATE_IDLE,
						CONNMAN_IPCONFIG_TYPE_IPV6);
	}

	ipv6_configuration_changed(service);
	__connman_notifier_ipconfig_changed(service, ipconfig);
}

void __connman_service_set_ipv6_for_connected(struct connman_service *vpn,
				struct connman_service *transport, bool enable)
{
	struct set_ipv6_data data = {
		.vpn = vpn,
		.transport = transport,
		.enable = enable
	};

	DBG("%s vpn %p transport %p", enable ? "enable" : "disable", vpn,
								transport);

	g_list_foreach(service_list, set_ipv6_for_service, &data);
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return service ? service->identifier : NULL;
}

const char *__connman_service_get_path(struct connman_service *service)
{
	return service->path;
}

const char *__connman_service_get_name(struct connman_service *service)
{
	return service->name;
}

int connman_service_get_available_count(enum connman_service_type type)
{
	if (!service_type_hash[type])
		return 0;

	return g_hash_table_size(service_type_hash[type]);
}

enum connman_service_state connman_service_get_state(struct connman_service *service)
{
	return service ? service->state : CONNMAN_SERVICE_STATE_UNKNOWN;
}

static enum connman_service_type convert_network_type(struct connman_network *network)
{
	enum connman_network_type type = connman_network_get_type(network);

	switch (type) {
	case CONNMAN_NETWORK_TYPE_UNKNOWN:
	case CONNMAN_NETWORK_TYPE_VENDOR:
		break;
	case CONNMAN_NETWORK_TYPE_ETHERNET:
		return CONNMAN_SERVICE_TYPE_ETHERNET;
	case CONNMAN_NETWORK_TYPE_WIFI:
		return CONNMAN_SERVICE_TYPE_WIFI;
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_PAN:
	case CONNMAN_NETWORK_TYPE_BLUETOOTH_DUN:
		return CONNMAN_SERVICE_TYPE_BLUETOOTH;
	case CONNMAN_NETWORK_TYPE_CELLULAR:
		return CONNMAN_SERVICE_TYPE_CELLULAR;
	case CONNMAN_NETWORK_TYPE_GADGET:
		return CONNMAN_SERVICE_TYPE_GADGET;
	}

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

static enum connman_service_security convert_wifi_security(const char *security)
{
	if (!security)
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
	else if (g_str_equal(security, "none"))
		return CONNMAN_SERVICE_SECURITY_NONE;
	else if (g_str_equal(security, "wep"))
		return CONNMAN_SERVICE_SECURITY_WEP;
	else if (g_str_equal(security, "psk"))
		return CONNMAN_SERVICE_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x"))
		return CONNMAN_SERVICE_SECURITY_8021X;
	else if (g_str_equal(security, "wpa"))
		return CONNMAN_SERVICE_SECURITY_WPA;
	else if (g_str_equal(security, "rsn"))
		return CONNMAN_SERVICE_SECURITY_RSN;
	else
		return CONNMAN_SERVICE_SECURITY_UNKNOWN;
}

static void update_wps_values(struct connman_service *service,
				struct connman_network *network)
{
	bool wps = connman_network_get_bool(network, "WiFi.WPS");
	bool wps_advertising = connman_network_get_bool(network,
							"WiFi.WPSAdvertising");

	if (service->wps != wps ||
			service->wps_advertizing != wps_advertising) {
		service->wps = wps;
		service->wps_advertizing = wps_advertising;
		security_changed(service);
	}
}

/* Return true if service has been updated */
gboolean __connman_service_update_value_from_network(
			struct connman_service *service,
			struct connman_network *network, const char *key)
{
	if (!service || !network || !key) {
		return FALSE;
	} else if (!g_strcmp0(key, "WiFi.EAP")) {
		const char *value = connman_network_get_string(network, key);

		if (!g_strcmp0(value, "default")) {
			/* Substitute default value with "peap" */
			value = service->eap ? service->eap : "peap";
			connman_network_set_string(network, key, value);
		}
		return set_eap_method(service, value);
	} else if (!g_strcmp0(key, "WiFi.Identity")) {
		return set_identity(service,
				connman_network_get_string(network, key));
	} else if (!g_strcmp0(key, "WiFi.SSID")) {
		unsigned int n = 0;
		const void *ssid = connman_network_get_blob(network, key, &n);
		if (ssid) {
			if (!service->ssid ||
				g_bytes_get_size(service->ssid) != n ||
				memcmp(g_bytes_get_data(service->ssid, NULL),
								ssid, n)) {
				if (service->ssid)
					g_bytes_unref(service->ssid);
				service->ssid = g_bytes_new(ssid, n);
				return TRUE;
			}
		}
		return FALSE;
	} else {
		return TRUE;
	}
}

void connman_service_update_strength_from_network(struct connman_network *network)
{
	struct connman_service *service;

	service = connman_service_lookup_from_network(network);
	if (service && service->network) {
		uint8_t strength;

		strength = connman_network_get_strength(service->network);
		if (service->strength != strength) {
			service->strength = strength;
			strength_changed(service);
		}
	}
}

static void update_from_network(struct connman_service *service,
					struct connman_network *network)
{
	const gboolean was_available = service_available.value(service);
	uint8_t strength = service->strength;
	const char *str;
	bool network_update = false;

	DBG("service %p network %p", service, network);

	if (is_connected(service->state))
		return;

	if (is_connecting(service->state))
		return;

	str = connman_network_get_string(network, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = connman_network_get_strength(network);
	service->roaming = connman_network_get_bool(network, "Roaming");

	if (service->strength == 0) {
		/*
		 * Filter out 0-values; it's unclear what they mean
		 * and they cause anomalous sorting of the priority list.
		 */
		service->strength = strength;
	}

	str = connman_network_get_string(network, "WiFi.Security");
	service->security = convert_wifi_security(str);

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI) {
		__connman_service_update_value_from_network(service, network,
								"WiFi.SSID");
		__connman_service_update_value_from_network(service, network,
								"WiFi.EAP");
		update_wps_values(service, network);
	}

	/*
	 * Reset the ignore flag if there was no network associated
	 * with this service. The service isn't necessarily freed
	 * after it's been removed from the network and can be later
	 * re-associated with a new network that has the same name.
	 * In that case service->ignore would be true (because it
	 * was set by __connman_service_remove_from_network) so we
	 * need to reset it back to false.
	 */
	if (!service->network)
		service->ignore = false;

	/* Roaming only makes sense for cellular */
	if (service->type == CONNMAN_SERVICE_TYPE_CELLULAR) {
		stats_get_roaming(service, TRUE);
	} else if (service->stats_roaming) {
		__connman_stats_free(service->stats_roaming);
		service->stats_roaming = NULL;
	}

	if (service->strength > strength && service->network) {
		connman_network_unref(service->network);
		service->network = connman_network_ref(network);
		connman_network_autoconnect_changed(service->network,
							service->autoconnect);
		strength_changed(service);
	}

	if (!service->network) {
		service->network = connman_network_ref(network);
		network_update = service->network ? true : false;
		connman_network_autoconnect_changed(service->network,
							service->autoconnect);
		service_schedule_updated(service);
	}

	if (was_available != service_available.value(service)) {
		service_boolean_changed(service, &service_available);

		if (network_update)
			count_available_service_type(service, true);
	}

	service_list_sort();
}

/**
 * __connman_service_create_from_network:
 * @network: network structure
 *
 * Look up service by network and if not found, create one
 */
bool __connman_service_create_from_network(struct connman_network *network)
{
	struct connman_service *service;
	struct connman_device *device;
	const char *ident, *group;
	char *name;
	unsigned int *auto_connect_types, *favorite_types;
	int i, index;

	DBG("network %p", network);

	if (!network)
		return false;

	ident = __connman_network_get_ident(network);
	if (!ident)
		return false;

	group = connman_network_get_group(network);
	if (!group)
		return false;

	name = g_strdup_printf("%s_%s_%s",
			__connman_network_get_type(network), ident, group);
	service = service_get(name);
	g_free(name);

	if (!service)
		return false;

	if (__connman_network_get_weakness(network))
		return true;

	index = connman_network_get_index(network);

	if (service->path) {
		DBG("old (%s) service with path %s",
					service->new_service ? "new" : "old",
					service->path);
		update_from_network(service, network);

		if (service->ipconfig_ipv4)
			__connman_ipconfig_set_index(service->ipconfig_ipv4,
									index);

		if (service->ipconfig_ipv6)
			__connman_ipconfig_set_index(service->ipconfig_ipv6,
									index);

		__connman_connection_update_gateway();

		if (service->autoconnect)
			do_auto_connect(service,
				CONNMAN_SERVICE_CONNECT_REASON_AUTO);

		return true;
	}

	service->type = convert_network_type(network);
	service->mdns_config = service_default_mdns(service->type);

	auto_connect_types = connman_setting_get_uint_list("DefaultAutoConnectTechnologies");
	service->autoconnect = false;
	for (i = 0; auto_connect_types &&
		     auto_connect_types[i] != 0; i++) {
		if (service->type == auto_connect_types[i]) {
			service->autoconnect = true;
			break;
		}
	}

	favorite_types = connman_setting_get_uint_list("DefaultFavoriteTechnologies");
	service->favorite = false;
	for (i = 0; favorite_types && favorite_types[i] != 0; i++) {
		if (service->type == favorite_types[i]) {
			service->favorite = true;
			break;
		}
	}

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	update_from_network(service, network);

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_DHCP);
	else
		__connman_ipconfig_set_index(service->ipconfig_ipv4, index);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);
	else
		__connman_ipconfig_set_index(service->ipconfig_ipv6, index);

	service_register(service);
	service_schedule_added(service);

	if (service->favorite || service->autoconnect) {
		device = connman_network_get_device(service->network);
		if (device && !connman_device_get_scanning(device,
						CONNMAN_SERVICE_TYPE_UNKNOWN)) {

			switch (service->type) {
			case CONNMAN_SERVICE_TYPE_UNKNOWN:
			case CONNMAN_SERVICE_TYPE_SYSTEM:
			case CONNMAN_SERVICE_TYPE_P2P:
				break;

			case CONNMAN_SERVICE_TYPE_GADGET:
			case CONNMAN_SERVICE_TYPE_ETHERNET:
				if (service->autoconnect) {
					__connman_service_connect(service,
						CONNMAN_SERVICE_CONNECT_REASON_AUTO);
					break;
				}

				/* fall through */
			case CONNMAN_SERVICE_TYPE_BLUETOOTH:
			case CONNMAN_SERVICE_TYPE_GPS:
			case CONNMAN_SERVICE_TYPE_VPN:
			case CONNMAN_SERVICE_TYPE_WIFI:
			case CONNMAN_SERVICE_TYPE_CELLULAR:
				do_auto_connect(service,
					CONNMAN_SERVICE_CONNECT_REASON_AUTO);
				break;
			}
		}
	}

	__connman_notifier_service_add(service, service->name);

	return true;
}

void __connman_service_update_from_network(struct connman_network *network)
{
	bool need_sort = false;
	struct connman_service *service;
	uint8_t strength;
	bool roaming;
	const char *name;

	service = connman_service_lookup_from_network(network);
	if (!service)
		return;

	if (!service->network)
		return;

	name = connman_network_get_string(service->network, "Name");
	if (g_strcmp0(service->name, name) != 0) {
		g_free(service->name);
		service->name = g_strdup(name);
		string_changed(service, PROP_NAME, name);
	}

	if (service->type == CONNMAN_SERVICE_TYPE_WIFI)
		update_wps_values(service, network);

	strength = connman_network_get_strength(service->network);
	if (strength == service->strength)
		goto roaming;

	service->strength = strength;
	need_sort = true;

	strength_changed(service);

roaming:
	roaming = connman_network_get_bool(service->network, "Roaming");
	if (roaming == service->roaming)
		goto sorting;

	service->roaming = roaming;
	need_sort = true;

	roaming_changed(service);

sorting:
	if (need_sort) {
		service_list_sort();
	}
}

void __connman_service_remove_from_network(struct connman_network *network)
{
	struct connman_service *service;

	service = connman_service_lookup_from_network(network);

	DBG("network %p service %p", network, service);

	if (!service)
		return;

	service->ignore = true;

	__connman_connection_gateway_remove(service,
					CONNMAN_IPCONFIG_TYPE_ALL);

	cancel_online_check(service);
	if (service->connect_retry_timer) {
		g_source_remove(service->connect_retry_timer);
		service->connect_retry_timer = 0;
	}

	service_ipconfig_indicate_states(service, CONNMAN_SERVICE_STATE_IDLE);

	/* No network is associated with this service any more */
	if (service->network) {
		connman_network_unref(service->network);
		service->network = NULL;
		count_available_service_type(service, false);
	}

	/*
	 * service->new_service flags is set for the service that have not
	 * been saved yet. If the config file exists for this service, we
	 * keep it around. Nots that g_hash_table_remove drops the reference
	 * to the service and may actually deallocate it (meaning that it has
	 * to be done last).
	 */
	if (service->new_service) {
		service_remove(service);
	} else {
		/* We keep it around but it has become unavailable */
		service_boolean_changed(service, &service_available);
		/* Availability affects the order */
		service_list_sort();
	}
}

/**
 * __connman_service_create_from_provider:
 * @provider: provider structure
 *
 * Look up service by provider and if not found, create one
 */
struct connman_service *
__connman_service_create_from_provider(struct connman_provider *provider)
{
	struct connman_service *service;
	const char *ident, *str;
	char *name;
	int index = connman_provider_get_index(provider);

	DBG("provider %p", provider);

	ident = __connman_provider_get_ident(provider);
	if (!ident)
		return NULL;

	name = g_strdup_printf("vpn_%s", ident);
	service = service_get(name);
	g_free(name);

	if (!service)
		return NULL;

	if (service->provider != provider) {
		if (service->provider)
			connman_provider_unref(service->provider);

		service->provider = connman_provider_ref(provider);
	}

	service->type = CONNMAN_SERVICE_TYPE_VPN;

	/* Try to load modifiable values from storage. If config does not
	 * exist set current time as modify time if service is saved as is.
	 */
	if (__connman_service_load_modifiable(service) != 0)
		gettimeofday(&service->modified, NULL);

	service->order = service->do_split_routing ? 0 : 10;
	service->favorite = true;

	service->state_ipv4 = service->state_ipv6 = CONNMAN_SERVICE_STATE_IDLE;
	service->state = combine_state(service->state_ipv4, service->state_ipv6);

	str = connman_provider_get_string(provider, "Name");
	if (str) {
		g_free(service->name);
		service->name = g_strdup(str);
		service->hidden = false;
	} else {
		g_free(service->name);
		service->name = NULL;
		service->hidden = true;
	}

	service->strength = 0;

	if (!service->ipconfig_ipv4)
		service->ipconfig_ipv4 = create_ip4config(service, index,
				CONNMAN_IPCONFIG_METHOD_MANUAL);

	if (!service->ipconfig_ipv6)
		service->ipconfig_ipv6 = create_ip6config(service, index);

	service_register(service);

	__connman_notifier_service_add(service, service->name);
	service_schedule_added(service);

	/* provider will release the reference */
	return connman_service_ref(service);
}

static void remove_unprovisioned_services(void)
{
	gchar **services;
	GKeyFile *keyfile, *configkeyfile;
	char *file, *section;
	int i = 0;

	services = connman_storage_get_services();
	if (!services)
		return;

	for (; services[i]; i++) {
		file = section = NULL;
		keyfile = configkeyfile = NULL;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		file = g_key_file_get_string(keyfile, services[i],
					"Config.file", NULL);
		if (!file)
			goto next;

		section = g_key_file_get_string(keyfile, services[i],
					"Config.ident", NULL);
		if (!section)
			goto next;

		configkeyfile = __connman_storage_load_config(file);
		if (!configkeyfile) {
			/*
			 * Config file is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);
			goto next;
		}

		if (!g_key_file_has_group(configkeyfile, section))
			/*
			 * Config section is missing, remove the provisioned
			 * service.
			 */
			__connman_storage_remove_service(services[i]);

	next:
		if (keyfile)
			g_key_file_unref(keyfile);

		if (configkeyfile)
			g_key_file_unref(configkeyfile);

		g_free(section);
		g_free(file);
	}

	g_strfreev(services);
}

static int agent_probe(struct connman_agent *agent)
{
	DBG("agent %p", agent);
	return 0;
}

static void agent_remove(struct connman_agent *agent)
{
	DBG("agent %p", agent);
}

static void *agent_context_ref(void *context)
{
	struct connman_service *service = context;

	return (void *)connman_service_ref(service);
}

static void agent_context_unref(void *context)
{
	struct connman_service *service = context;

	connman_service_unref(service);
}

static struct connman_agent_driver agent_driver = {
	.name		= "service",
	.interface      = CONNMAN_AGENT_INTERFACE,
	.probe		= agent_probe,
	.remove		= agent_remove,
	.context_ref	= agent_context_ref,
	.context_unref	= agent_context_unref,
};

/* This is used as a callback for user change unload services. */
void __connman_service_unload_services(gchar **services, int len)
{
	struct connman_service *service;
	int i;

	DBG("services %d/%p", len, services);

	if (!services)
		return;

	for (i = 0; i < len && services[i]; i++) {
		DBG("service %d:%s", i, services[i]);

		service = connman_service_lookup_from_identifier(services[i]);
		if (!service) {
			DBG("no service for %s", services[i]);
			continue;
		}

		switch (connman_service_get_type(service)) {
		case CONNMAN_SERVICE_TYPE_WIFI:
			/*
			 * Stop all DHCPs before removing the service. This is
			 * to ensure that in cases where two users have the
			 * same network saved and DHCP is still pending for
			 * reply it is not left in that state. This may be
			 * possible in scenario where user change happens
			 * rapidly before the network is connected -> stopping
			 * of the DHCPs may not have been executed.
			 */
			if (service->ipconfig_ipv4)
				__connman_dhcp_stop(service->ipconfig_ipv4);

			if (service->network) {
				__connman_dhcpv6_stop(service->network);
				__connman_service_remove_from_network(
							service->network);
			}

			break;
		case CONNMAN_SERVICE_TYPE_VPN:
			break;
		default:
			DBG("skip non WiFi/VPN %p/%s", service,
						service->identifier);
			continue;
		}

		if (!__connman_service_remove(service))
			connman_warn("cannot unload service %s", services[i]);
	}

	/*
	 * Immediately inform about the service changes. If there were
	 * services removed the services_notify->id is set.
	 */
	if (services_notify->id != 0) {
		g_source_remove(services_notify->id);
		services_notify->id = 0;
		service_send_changed(NULL);
	}
}

void __connman_service_load_services(void)
{
	/* Remove previous loading function from main loop if it exists */
	if (load_wifi_services_id) {
		g_source_remove(load_wifi_services_id);
		load_wifi_services_id = 0;
	}

	load_wifi_services(NULL);
}

int __connman_service_init(void)
{
	int err;

	DBG("");

	err = connman_agent_driver_register(&agent_driver);
	if (err < 0) {
		connman_error("Cannot register agent driver for %s",
						agent_driver.name);
		return err;
	}

	set_always_connecting_technologies();

	connection = connman_dbus_get_connection();

	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, service_removed);
	service_type_hash = g_new0(GHashTable*, MAX_CONNMAN_SERVICE_TYPES);

	services_notify = g_new0(struct _services_notify, 1);
	services_notify->remove = g_hash_table_new_full(g_str_hash,
			g_str_equal, g_free, NULL);
	services_notify->add = g_hash_table_new(g_str_hash, g_str_equal);
	services_notify->update = g_hash_table_new(g_str_hash, g_str_equal);

	remove_unprovisioned_services();

	/*
	 * wifi services have to be loaded after plugins are initialized
	 * (e.g. access control plugin). This function is called too early.
	 */
	load_wifi_services_id = g_idle_add(load_wifi_services, NULL);

	return 0;
}

void __connman_service_cleanup(void)
{
	int i;

	DBG("");

	if (load_wifi_services_id) {
		g_source_remove(load_wifi_services_id);
		load_wifi_services_id = 0;
	}

	if (vpn_autoconnect_id) {
		g_source_remove(vpn_autoconnect_id);
		vpn_autoconnect_id = 0;
	}

	if (autoconnect_id != 0) {
		g_source_remove(autoconnect_id);
		autoconnect_id = 0;
	}

	connman_agent_driver_unregister(&agent_driver);

	g_list_free(service_list);
	service_list = NULL;

	g_hash_table_destroy(service_hash);
	service_hash = NULL;

	for (i = 0; i < MAX_CONNMAN_SERVICE_TYPES; i++) {
		if (!service_type_hash[i])
			continue;

		g_hash_table_destroy(service_type_hash[i]);
		service_type_hash[i] = NULL;
	}

	g_free(service_type_hash);
	service_type_hash = NULL;

	g_slist_free(counter_list);
	counter_list = NULL;

	if (services_notify->id != 0) {
		g_source_remove(services_notify->id);
		service_send_changed(NULL);
	}

	g_hash_table_destroy(services_notify->remove);
	g_hash_table_destroy(services_notify->add);
	g_hash_table_destroy(services_notify->update);
	g_free(services_notify);

	dbus_connection_unref(connection);
}
