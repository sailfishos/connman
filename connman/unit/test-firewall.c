/*
 *  ConnMan firewall unit tests
 *
 *  Copyright (C) 2018 Jolla Ltd. All rights reserved.
 *  Contact: jussi.laakkonen@jolla.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

/* TODO list:
 * 1) check rule ordering, the order of the rules is defined by the files they
 *    are loaded from. All dynamic rules are put on top, their order is
 *    following the same file ordering but the last enabled dynamic rules are
 *    always first. Some rules are included only with the specific IP family.
 * 2) add general rules to the dynamically loaded file and check that they are
 *    added and removed accordingly, and put after the general rules in the
 *    firewall.conf (the main file).
 * 3) Add changing policies to additional dynamically loaded files. Remove and
 *    add them and check for policy changes.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <errno.h>
#include <gdbus.h>
#include <stdio.h>
#include <unistd.h>

#include "src/connman.h"

struct connman_service {
	char *dummy;
	char *name;
	char *identifier;
	char *ifname;
	enum connman_service_type type;
	enum connman_service_state state;
};

struct connman_service test_service = {
	.dummy = "dummy",
	.name = "Ethernet1",
	.identifier = "eth_123",
	.ifname = "eth0",
	.type = CONNMAN_SERVICE_TYPE_ETHERNET,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

struct connman_service test_service2 = {
	.dummy = "dummy2",
	.name = "cellular1",
	.identifier = "rmnet_123",
	.ifname = "rmnet0",
	.type = CONNMAN_SERVICE_TYPE_CELLULAR,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

struct connman_service test_service3 = {
	.dummy = "dummy3",
	.name = "Ethernet2",
	.identifier = "eth_456",
	.ifname = "eth1",
	.type = CONNMAN_SERVICE_TYPE_ETHERNET,
	.state = CONNMAN_SERVICE_STATE_IDLE,
};

enum configtype {
	GLOBAL_NOT_SET = 	0x0000,
	CONFIG_OK = 		0x0002,
	CONFIG_INVALID =	0x0004,
	CONFIG_MIXED = 		0x0008,
	CONFIG_DUPLICATES = 	0x0010,
	CONFIG_ALL = 		0x0020,
	CONFIG_MAIN_INVALID = 	0x0040,
	CONFIG_TETHERING = 	0x0080,
	CONFIG_USE_POLICY = 	0x0100,
	ACCESS_FAILURE = 	0x0200,
	DIR_ACCESS_FAILURE =	0x0800,
};

static enum configtype global_config_type = GLOBAL_NOT_SET;

static const gchar *testfiles[] = {
				"10-firewall.conf",
				"30-firewall.conf",
				"20-firewall.conf",
				"04-firewall.conf",
				"69.conf",
				NULL
};

#define TESTFILES_MAX 5

static gboolean config_files_enabled[TESTFILES_MAX];

static void toggle_config(int index, gboolean enable)
{
	if (index >= TESTFILES_MAX)
		return;

	config_files_enabled[index] = enable;
}

#define FILE_CEL0 0
#define FILE_ETH1 1
#define FILE_CEL2 2
#define FILE_ETH3 3

static gboolean config_enabled(int index)
{
	if (index >= TESTFILES_MAX)
		return FALSE;

	return config_files_enabled[index];
}

static void reset_services() {
	test_service.state = test_service2.state = test_service3.state =
				CONNMAN_SERVICE_STATE_IDLE;
}

static void setup_test_params(enum configtype type)
{
	int i;

	if (type & CONFIG_OK)
		DBG("CONFIG_OK");

	if (type & CONFIG_INVALID)
		DBG("CONFIG_INVALID");

	if (type & CONFIG_MIXED)
		DBG("CONFIG_MIXED");

	if (type & CONFIG_MAIN_INVALID)
		DBG("CONFIG_MAIN_INVALID");

	if (type & CONFIG_TETHERING)
		DBG("CONFIG_TETHERING");

	if (type & CONFIG_USE_POLICY)
		DBG("CONFIG_USE_POLICY");
	
	if (type & ACCESS_FAILURE)
		DBG("ACCESS_FAILURE");
	
	if (type & DIR_ACCESS_FAILURE)
		DBG("DIR_ACCESS_FAILURE");

	global_config_type = type;

	DBG("type %d duplicates %d all_configs %d", type,
				type & CONFIG_DUPLICATES ? 1 : 0,
				type & CONFIG_ALL ? 1 : 0);

	for (i = 0; i < TESTFILES_MAX; i++)
		toggle_config(i, TRUE);

	reset_services();
}

// Dummies

// Config dummies

char *__connman_config_get_string(GKeyFile *key_file,
	const char *group_name, const char *key, GError **error)
{
	char *str = g_key_file_get_string(key_file, group_name, key, error);
	if (!str)
		return NULL;

	return g_strchomp(str);
}

char **__connman_config_get_string_list(GKeyFile *key_file,
	const char *group_name, const char *key, gsize *length, GError **error)
{
	char **p;
	char **strlist = g_key_file_get_string_list(key_file, group_name, key,
		length, error);
	if (!strlist)
		return NULL;

	p = strlist;
	while (*p) {
		*p = g_strstrip(*p);
		p++;
	}

	return strlist;
}

// Service dummies 

enum connman_service_type connman_service_get_type(
						struct connman_service *service)
{
	return service->type;
}

const char *__connman_service_get_name(struct connman_service *service)
{
	return service->name;
}

const char *connman_service_get_identifier(struct connman_service *service)
{
	return service->identifier;
}

const char *__connman_service_type2string(enum connman_service_type type)
{
	if (type == CONNMAN_SERVICE_TYPE_ETHERNET)
		return "ethernet";

	if (type == CONNMAN_SERVICE_TYPE_CELLULAR)
		return "cellular";

	if (type == CONNMAN_SERVICE_TYPE_WIFI)
		return "wifi";

	if (type == CONNMAN_SERVICE_TYPE_VPN)
		return "vpn";

	return NULL;
}

enum connman_service_type __connman_service_string2type(const char *str)
{
	if (!g_strcmp0(str, "ethernet"))
		return CONNMAN_SERVICE_TYPE_ETHERNET;

	if (!g_strcmp0(str, "cellular"))
		return CONNMAN_SERVICE_TYPE_CELLULAR;

	if (!g_strcmp0(str, "wifi"))
		return CONNMAN_SERVICE_TYPE_WIFI;

	if (!g_strcmp0(str, "vpn"))
		return CONNMAN_SERVICE_TYPE_VPN;

	return CONNMAN_SERVICE_TYPE_UNKNOWN;
}

struct connman_service *connman_service_lookup_from_identifier(
						const char* identifier)
{
	if (!g_strcmp0(identifier, "eth_123"))
		return &test_service;

	if (!g_strcmp0(identifier, "rmnet_123"))
		return &test_service2;

	if (!g_strcmp0(identifier, "eth_456"))
		return &test_service3;

	return NULL;
}

int connman_service_iterate_services(connman_service_iterate_cb cb,
							void *user_data)
{
	cb(&test_service, user_data);
	cb(&test_service2, user_data);
	cb(&test_service3, user_data);

	return 0;
}

enum connman_service_state connman_service_get_state(
						struct connman_service *service)
{
	return service->state;
}

char *connman_service_get_interface(struct connman_service *service)
{
	if (service->ifname)
		return g_strdup(service->ifname);

	return g_strdup("unknown0");
}

// Tech / tethering dummies

struct connman_technology {
	char *ident;
	char *bridge;
	enum connman_service_type type;
	bool enabled;
	bool default_rules;
};

struct connman_technology test_technology = {
	.ident = "wifi_123",
	.bridge = "tether",
	.type = CONNMAN_SERVICE_TYPE_WIFI,
	.enabled = false,
	.default_rules = true,
};

const char *__connman_technology_get_tethering_ident(
				struct connman_technology *tech)
{
	if (!tech)
		return NULL;

	return tech->ident;
}

const char *__connman_tethering_get_bridge(void)
{
	if (test_technology.enabled)
		return test_technology.bridge;
	return NULL;
}

enum connman_service_type __connman_technology_get_type(
					struct connman_technology *tech)
{
	if (!tech)
		return 0;

	return tech->type;
}

void connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	return;
}

// Access dummies

struct connman_access_firewall_policy *__connman_access_firewall_policy_create
		(const char *spec)
{
	return NULL;
}

void __connman_access_firewall_policy_free
		(struct connman_access_firewall_policy *policy)
{
	return;
}

enum connman_access __connman_access_firewall_manage
		(const struct connman_access_firewall_policy *policy,
			const char *name, const char *sender,
			enum connman_access default_access)
{
	if (global_config_type & ACCESS_FAILURE)
		return CONNMAN_ACCESS_DENY;

	return CONNMAN_ACCESS_ALLOW;
}

// DBus dummies

DBusMessage *test_message = NULL;
GDBusMethodFunction reload_call = NULL;

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy)
{
	int i;

	g_assert(methods);

	for (i = 0; methods[i].name; i++) {
		if (!g_strcmp0(methods[i].name, "Reload"))
			reload_call = methods[i].function;
	}

	g_assert(reload_call);

	return TRUE;
}

gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name)
{
	return TRUE;
}

// Original version from gdbus/object.c
gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message)
{
	g_assert_true(connection == NULL);
	g_assert_true(message != NULL);

	test_message = message;
	return TRUE;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, format);

	reply = g_dbus_create_error_valist(message, name, format, args);

	va_end(args);

	return reply;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args)
{
	char str[1024];

	if (format)
		vsnprintf(str, sizeof(str), format, args);
	else
		str[0] = '\0';

	return dbus_message_new_error(message, name, str);
}

// Copied from gdbus/object.c
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...)
{
	va_list args;
	gboolean result;

	va_start(args, type);

	result = g_dbus_send_reply_valist(connection, message, type, args);

	va_end(args);

	return result;
}

// Copied from gdbus/object.c
gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return FALSE;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return FALSE;
	}

	return g_dbus_send_message(connection, reply);
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (reply == NULL)
		return NULL;

	if (dbus_message_append_args_valist(reply, type, args) == FALSE) {
		dbus_message_unref(reply);
		return NULL;
	}

	return reply;
}

// Copied from gdbus/object.c
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...)
{
	va_list args;
	DBusMessage *reply;

	va_start(args, type);

	reply = g_dbus_create_reply_valist(message, type, args);

	va_end(args);

	return reply;
}

// Notifier dummies

static struct connman_notifier *firewall_notifier;
static bool notifier_fail = false;

int connman_notifier_register(struct connman_notifier *notifier)
{
	if (notifier_fail)
		return -EINVAL;

	if (!g_strcmp0(notifier->name, "firewall"))
		firewall_notifier = notifier;

	return 0;
}

void connman_notifier_unregister(struct connman_notifier *notifier)
{
	firewall_notifier = NULL;
}

// Iptables dummies

struct iptables_rule {
	int type;
	gchar *table;
	gchar *chain;
	gchar *rule_spec;
};

static GSList *rules_ipv4 = NULL;
static GSList *chains_ipv4 = NULL;
static gchar *policies_ipv4[3] = { 0 };
static const gchar *tables_ipv4[] = { "nat", "mangle", "filter", "raw",
						"security", NULL};

static GSList *rules_ipv6 = NULL;
static GSList *chains_ipv6 = NULL;
static gchar *policies_ipv6[3] = { 0 };
static const gchar *tables_ipv6[] = { "raw", "mangle", "filter", NULL};

enum iptablestype {
	IPTABLES_NORMAL = 	0x0000,
	IPTABLES_CHAIN_FAIL = 	0x0002,
	IPTABLES_ADD_FAIL =	0x0004,
	IPTABLES_INS_FAIL = 	0x0008,
	IPTABLES_DEL_FAIL = 	0x0010,
	IPTABLES_POLICY_FAIL =	0x0020,
	IPTABLES_COMMIT_FAIL = 	0x0040,
	IPTABLES_ALL_CHAINS  = 	0x0080,
};

static enum iptablestype global_iptables_type = IPTABLES_NORMAL;

static void setup_iptables_params(enum iptablestype type)
{
	if (type & IPTABLES_NORMAL) {
		global_config_type = IPTABLES_NORMAL;
		DBG("IPTABLES_NORMAL");
	}

	if (type & IPTABLES_CHAIN_FAIL)
		DBG("IPTABLES_CHAIN_FAIL");

	if (type & IPTABLES_ADD_FAIL)
		DBG("IPTABLES_ADD_FAIL");

	if (type & IPTABLES_INS_FAIL)
		DBG("IPTABLES_INS_FAIL");

	if (type & IPTABLES_DEL_FAIL)
		DBG("IPTABLES_DEL_FAIL");

	if (type & IPTABLES_POLICY_FAIL)
		DBG("IPTABLES_POLICY_FAIL");

	if (type & IPTABLES_COMMIT_FAIL)
		DBG("IPTABLES_COMMIT_FAIL");
	
	if (type & IPTABLES_ALL_CHAINS)
		DBG("IPTABLES_ALL_CHAINS");

	global_iptables_type = type;
}

static struct iptables_rule *new_rule(int type, const char *table,
			const char *chain, const char *rule_spec)
{
	struct iptables_rule *rule;

	if (!table || !chain || !rule_spec)
		return NULL;

	rule = g_try_new0(struct iptables_rule, 1);

	if (!rule)
		return NULL;

	rule->type = type;
	rule->table = g_strdup(table);
	rule->chain = g_strdup(chain);
	rule->rule_spec = g_strdup(rule_spec);

	return rule;
}

static void delete_rule(struct iptables_rule *rule)
{
	if (!rule)
		return;

	g_free(rule->table);
	g_free(rule->chain);
	g_free(rule->rule_spec);

	g_free(rule);
}

static gboolean table_exists(int type, const char *table_name)
{
	int i;

	switch (type) {
	case AF_INET:
		for (i = 0; tables_ipv4[i]; i++) {
			if (!g_strcmp0(tables_ipv4[i], table_name))
				return true;
		}
		break;
	case AF_INET6:
		for (i = 0; tables_ipv6[i]; i++) {
			if (!g_strcmp0(tables_ipv6[i], table_name))
				return true;
		}
	}

	return false;
}

static gboolean is_builtin(const char *chain)
{
	int i;
	const char *builtin[] = {"INPUT", "FORWARD", "OUTPUT", NULL};

	for (i = 0; builtin[i]; i++) {
		if (!g_strcmp0(chain, builtin[i]))
			return TRUE;
	}
	return FALSE;
}

static gboolean chain_exists(int type, const char *chain)
{
	GSList *list = NULL;
	switch (type) {
	case AF_INET:
		list = chains_ipv4;
		break;
	case AF_INET6:
		list = chains_ipv6;
	}
	
	if (is_builtin(chain))
		return true;

	if (g_slist_find_custom(list, chain, (GCompareFunc)g_strcmp0))
		return true;

	return false;
}

int __connman_iptables_new_chain(int type, 
				const char *table_name,
				const char *chain)
{
	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (chain_exists(type, chain))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EEXIST;

	switch (type) {
	case AF_INET:
		chains_ipv4 = g_slist_prepend(chains_ipv4, g_strdup(chain));
		break;
	case AF_INET6:
		chains_ipv6 = g_slist_prepend(chains_ipv6, g_strdup(chain));
	}

	return 0;
}

int __connman_iptables_delete_chain(int type,
				const char *table_name,
				const char *chain)
{
	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (is_builtin(chain)) // Builtin chains are not to be deleted
		return -EINVAL;

	if (!chain_exists(type, chain))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EEXIST;

	switch (type) {
	case AF_INET:
		chains_ipv4 = g_slist_remove(chains_ipv4, chain);
		break;
	case AF_INET6:
		chains_ipv6 = g_slist_remove(chains_ipv6, chain);
	}

	return 0;
}

int __connman_iptables_flush_chain(int type,
				const char *table_name,
				const char *chain)
{
	GSList *rules = NULL, *iter, *current, *remove;
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (!chain_exists(type, chain))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_CHAIN_FAIL)
		return -EINVAL;

	switch (type) {
	case AF_INET:
		rules = rules_ipv4;
		break;
	case AF_INET6:
		rules = rules_ipv6;
	}

	iter = rules;

	while (iter) {
		rule = iter->data;
		current = iter; // backup current
		iter = iter->next;
		
		if (rule->type == type &&
					g_str_equal(rule->table, table_name) &&
					g_str_equal(rule->chain, chain))
		{
			remove = g_slist_remove_link(rules, current);
			
			g_assert(remove);
			
			delete_rule(remove->data);
			g_slist_free1(remove);
		}
	}

	return 0;
}

static int chain_to_index(const char *chain)
{
	if (g_str_equal("INPUT", chain))
		return 0;

	if (g_str_equal("FORWARD", chain))
		return 1;

	if (g_str_equal("OUTPUT", chain))
		return 2;

	return -EINVAL;
}

static gboolean is_valid_policy(const char *policy)
{
	if (g_str_equal("ACCEPT", policy))
		return true;

	if (g_str_equal("DROP", policy))
		return true;

	return false;
}

int __connman_iptables_change_policy(int type,
				const char *table_name,
				const char *chain,
				const char *policy)
{
	int index;

	DBG("");

	if (!table_name || !chain || !policy)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (!is_valid_policy(policy))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_POLICY_FAIL)
		return -EINVAL;

	DBG("table %s chain %s policy %s", table_name, chain, policy);

	index = chain_to_index(chain);

	if (index < 0)
		return index;

	switch (type) {
	case AF_INET:
		if (policies_ipv4[index])
			g_free(policies_ipv4[index]);

		policies_ipv4[index] = g_strdup(policy);
		break;
	case AF_INET6:
		if (policies_ipv6[index])
			g_free(policies_ipv6[index]);

		policies_ipv6[index] = g_strdup(policy);
	}

	return 0;
}

int __connman_iptables_append(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_ADD_FAIL)
		return -EINVAL;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	rule = new_rule(type, table_name, chain, rule_spec);

	switch (type) {
	case AF_INET:
		rules_ipv4 = g_slist_append(rules_ipv4, rule);
		break;
	case AF_INET6:
		rules_ipv6 = g_slist_append(rules_ipv6, rule);
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_insert(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;

	if (global_iptables_type & IPTABLES_INS_FAIL)
		return -EINVAL;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	rule = new_rule(type, table_name, chain, rule_spec);

	switch (type) {
	case AF_INET:
		rules_ipv4 = g_slist_prepend(rules_ipv4, rule);
		break;
	case AF_INET6:
		rules_ipv6 = g_slist_prepend(rules_ipv6, rule);
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_delete(int type,
				const char *table_name,
				const char *chain,
				const char *rule_spec)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;

	DBG("");

	if (!table_name || !chain || !rule_spec)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_DEL_FAIL)
		return -EINVAL;

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	while (iter) {
		rule = iter->data;
		
		if (rule->type == type &&
					!g_strcmp0(rule->table, table_name) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_spec)) {
			switch (type) {
				case AF_INET:
					rules_ipv4 = g_slist_remove_link(
								rules_ipv4,
								iter);
					break;
				case AF_INET6:
					rules_ipv6 = g_slist_remove_link(
								rules_ipv6,
								iter);
			}

			delete_rule(rule);
			g_slist_free1(iter);

			break;
		}

		iter = iter->next;
	}

	DBG("list sizes IPv4: %d IPv6: %d", g_slist_length(rules_ipv4),
				g_slist_length(rules_ipv6));

	return 0;
}

int __connman_iptables_commit(int type, const char *table_name)
{
	DBG("");

	if (!table_name)
		return -EINVAL;

	if (!table_exists(type, table_name))
		return -EINVAL;
	
	if (global_iptables_type & IPTABLES_COMMIT_FAIL)
		return -EINVAL;

	return 0;
}

static const char *connman_chains[] = { "connman-INPUT",
					"connman-FORWARD",
					"connman-OUTPUT"
};

int __connman_iptables_iterate_chains(int type, const char *table_name,
				connman_iptables_iterate_chains_cb_t cb,
				void *user_data)
{
	const char *chains[] = {
				"INPUT",
				"OUTPUT",
				"FORWARD",
				connman_chains[0],
				connman_chains[1],
				connman_chains[2],
				NULL
	};
	int i, limit = 3;

	DBG("");
	
	if (global_iptables_type & IPTABLES_ALL_CHAINS)
		limit = 6;
	
	for (i = 0; i < limit; i++)
		cb(chains[i], user_data);

	return 0;
}

int __connman_iptables_init(void)
{
	int i = 0;

	DBG("");

	rules_ipv4 = NULL;
	rules_ipv6 = NULL;
	chains_ipv4 = NULL;
	chains_ipv6 = NULL;

	for (i = 0; i < 3; i++)
		policies_ipv4[i] = policies_ipv6[i] = NULL;

	return 0;
}

static void rule_cleanup(gpointer data)
{
	struct iptables_rule *rule = data;

	delete_rule(rule);
}

void __connman_iptables_cleanup(void)
{
	int i = 0;

	DBG("");

	g_slist_free_full(rules_ipv4, rule_cleanup);
	g_slist_free_full(rules_ipv6, rule_cleanup);
	g_slist_free_full(chains_ipv4, g_free);
	g_slist_free_full(chains_ipv6, g_free);

	for (i = 0; i < 3; i++) {
		g_free(policies_ipv4[i]);
		g_free(policies_ipv6[i]);
		
		policies_ipv4[i] = policies_ipv6[i] = NULL;
	}
}

// GDir dummies 

int file_index = 0;

typedef struct _GDir {
	gboolean value;
} GDir;

GDir *g_dir_open (const gchar *path, guint flags, GError **error)
{
	if (global_config_type & DIR_ACCESS_FAILURE)
		return NULL;

	GDir *dir = g_try_new(GDir, 1);

	g_assert(dir);

	file_index = 0;

	return dir;
}

const gchar *g_dir_read_name (GDir *dir)
{
	g_assert(dir);

	DBG("%d:%s = %s", file_index, testfiles[file_index],
				config_enabled(file_index) ? "on" : "off");

	if (file_index < 5) {
		// Recurse
		if (!config_enabled(file_index)) {
			file_index++;
			return g_dir_read_name(dir);
		}

		return testfiles[file_index++];
	}
	return NULL;
}

void g_dir_close (GDir *dir)
{
	g_assert(dir);

	file_index = 0;

	g_free(dir);
}

gboolean g_file_test(const gchar *filename, GFileTest test)
{
	if (g_str_has_suffix(filename, "firewall.d/")) {

		if (global_config_type & CONFIG_ALL) {
			DBG("dir %s", filename);
			return TRUE;
		} else {
			return FALSE;
		}
	}

	if (g_strstr_len(filename, -1, "firewall.d")) {
		DBG("file in firewall.d/ (%s)", filename);
		return TRUE;
	}

	if (g_str_has_suffix(filename, "/firewall.conf")) {
		DBG("main config");
		return TRUE;
	}
	
	if (g_str_has_suffix(filename, "_tables_names")) {
		DBG("iptables names file");
		return TRUE;
	}

	DBG("invalid");

	return FALSE;
}

gboolean g_file_get_contents(const gchar *filename, gchar **contents,
			gsize *length, GError **error)
{
	if (g_str_has_suffix(filename, "ip_tables_names")) {
		*contents = g_strjoinv("\n", (gchar**)tables_ipv4);
	}
	
	if (g_str_has_suffix(filename, "ip6_tables_names")) {
		*contents = g_strjoinv("\n", (gchar**)tables_ipv6);
	}

	return TRUE;
}

#define RULES_GEN4 48
#define RULES_GEN6 50
#define RULES_ETH 14
#define RULES_CEL 4
#define RULES_TETH 7

/* Main config ok */
static const char *general_input[] = {
		/* All protocols with targets that are supported */
		"-p tcp -j ACCEPT",
		"-p udp -j DROP",
		"-p sctp -j LOG",
		"-p icmp -j QUEUE", /* IPv4 only */
		"-p icmpv6 -j REJECT", /* IPv6 only */
		"-p ipv6-icmp -j ACCEPT", /* IPv6 only */
		"-p esp -j DROP",
		"-p ah -j LOG",
		"-p mh -j QUEUE", /* IPv6 only */
		"-p dccp -j REJECT",
		"-p all -j ACCEPT",
		"-p udplite -j DROP",
		/* Port switches with protocols */
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"-p sctp -m sctp --destination-port 8088 -j LOG",
		"-p dccp -m dccp --source-port 8188 -j QUEUE",
		"-p tcp -m tcp --destination-port 993 --source-port 992 -j LOG",
		"-p udp -m udp --destination-port 997 --sport 996 -j ACCEPT",
		"-p udplite -m udplite --dport 999 --sport 998 -j REJECT",
		"-p sctp -m sctp --dport 995 --source-port 994 -j DROP",
		/* Conntrack */
		"-p all -m conntrack --ctstate RELATED -j ACCEPT",
		"-m conntrack --ctstate NEW,ESTABLISHED,RELATED -j LOG",
		/* ICMP, using also negation */
		"-p icmp -m icmp --icmp-type 8/0 -j DROP",
		"-p ipv6-icmp -m ipv6-icmp --icmp-type 128/0 -j DROP",
		/* Protocols with number and text match are allowed */
		"-p 6 -m tcp --dport 9898 -j ACCEPT",
		"-p 6 -m 6 --dport https -j LOG", /* TODO should not pass */
		"-p udp -m udp --sport telnet -j QUEUE",
		/* Negations */
		"-p tcp -m multiport --dports ! 67,68,69 -j ACCEPT",
		"-p icmpv6 -m icmpv6 ! --icmp-type 128/0 -j DROP",
		"-p ! udp -j ACCEPT",
		 /* Treated as whitespace */
		"#-p sctp --dport 69 -j REJECT",
		NULL
};
static const char *general_output[] = {
		/* Identical rules in different chains are allowed */
		"-p tcp -m tcp --dport 80 -j ACCEPT",
		"-p udp -m udp --sport 81 -j DROP",
		"-p sctp -m sctp --destination-port 8088 -j LOG",
		"-p dccp -m dccp --source-port 8188 -j QUEUE",
		"-p tcp -m tcp --destination-port 993 --source-port 992 -j LOG",
		"-p udp -m udp --destination-port 997 --sport 996 -j ACCEPT",
		"-p udplite -m udplite --dport 999 --sport 998 -j REJECT",
		"-p sctp -m sctp --dport 995 --source-port 994 -j DROP",
		"-p icmp -m icmp --icmp-type 8/0 -j DROP", // +1 IPv4
		"-p esp -j DROP",
		"-p ah -j LOG",
		"-p mh -j QUEUE", /* IPv6 only */
		"#-p sctp --sport 123 -j REJECT",
		NULL
};
static const char *general_forward[] = {
		"-p tcp -m tcp -j ACCEPT",
		"-p udp -m udp -j DROP",
		"-p all -m conntrack --ctstate RELATED,ESTABLISHED,NEW -j DROP",
		"-m ttl --ttl-eq 60 -j LOG", // +1 IPv4
		/* Basic targets */
		"-j ACCEPT",
		"-j DROP",
		"-j QUEUE",
		"-j LOG",
		"-j REJECT",
		NULL
};
static const char *policies_default[] = {"ACCEPT", "ACCEPT", "ACCEPT"};
static const char *general_policies_ok[] = { "DROP", "ACCEPT", "DROP"};
static const char *general_policies_fail[] = {"DENY", "REJECT", "ALLOW"};
static const char *eth_input[] = {
		/* Multiport with switches */
		"-p tcp -m tcp --dport 8080 -j ACCEPT",
		"-p udp -m udp --destination-port 8081 -j DROP",
		"-p tcp -m multiport --dports 22,23 --sports 10:1000 -j ACCEPT",
		"-p tcp -m multiport --dports 8080:10000 -j ACCEPT",
		"-p udp -m multiport --dports 808,100,123,555,12345 -j DROP",
		"-p sctp -m multiport --dports 6999 --sports 200:300 -j LOG",
		"-p sctp -m multiport --destination-ports 69:100 "
					"--sports 100,200 -j REJECT",
		"-p tcp -m multiport --dports 6060:50000 "
					"--source-ports 23,24,45,65 -j LOG",
		"-p udp -m multiport --destination-ports 1000:3000 "
					"--source-ports 2000:4000 -j DROP",
		"-p tcp -m multiport --port 9999 -j LOG",
		"-p tcp -m multiport --ports 9999,10000 -j QUEUE",
		NULL
};
static const char *eth_output[] = {
		"-p tcp -m tcp --sport 8080 -j ACCEPT",
		"-p udp -m udp --source-port 8081 -j DROP",
		"-p sctp -m sctp --sport 123 -j REJECT",
		NULL
};
static const char *cellular_input[] = {
		"-p tcp -m tcp --dport 8082 -j ACCEPT",
		"-p udp -m udp --dport 8083 -j DROP",
		NULL
};
static const char *cellular_output[] = {
		"-p tcp -m tcp --sport 8082 -j ACCEPT",
		"-p udp -m udp --sport 8083 -j DROP",
		NULL
};

/* Tethering for main */
static const char *tethering_input[] = {
		"-p udp -m multiport --dports 53,67 -j ACCEPT",
		"-p tcp -m tcp --dport 53 -j ACCEPT",
		NULL
};

static const char *tethering_forward[] = {
		"-p udp -m multiport --dports 53,67 -j ACCEPT",
		"-p tcp -m multiport --dports 1024:65535 -j ACCEPT",
		"-p tcp -m tcp --dport 22 -j DROP",
		NULL
};

static const char *tethering_output[] = {
		"-p udp -m udp --dport 68 -j ACCEPT",
		"-p tcp -m tcp --dport 53 -j ACCEPT",
		NULL
};

/* Main config with invalid rules */
static const char *invalid_general_input[] = {
		/* Only one target */
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		/* Protocol omitted */
		"udp -m udp --dport 81 -j DROP",
		/* One protocol only */
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		/* State is disabled */
		"-p tcp -m state --state NEW -j ACCEPT",
		/* Comment is disabled, TODO lone --comment must be disabled */
		"-p tcp -m tcp --dport 22 -j ACCEPT -m comment --comment test",
		/* Source or destination modifiers are disabled */
		"-p tcp -m tcp --dport 99 --source 192.168.1.1 -j DROP",
		"-p tcp -m tcp --dport 99 --src 192.168.1.2 -j DROP",
		"-p tcp -m tcp --dport 99 -s 192.168.1.3 -j DROP",
		"-p tcp -m tcp --dport 98 --destination 192.168.1.3 -j DROP",
		"-p tcp -m tcp --dport 98 --dst 192.168.1.4 -j DROP",
		"-p tcp -m tcp --dport 98 -d 192.168.1.5 -j DROP",
		"--source 1.2.3.4 --destination 4.3.2.1 -j ACCEPT",
		"--src 1.2.3.4 --dst 4.3.2.1 -j ACCEPT",
		"-d 1.2.3.4 -d 4.3.2.1 -j ACCEPT",
		NULL
};
static const char *invalid_general_output[] = {
		/* One target only, max 2 port speficiers */
		/* TODO two same port specifiers should be disabled */
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		/* No target modifier */
		"DROP",
		/* Disabled matches */
		"-m recent --name example --check --seconds 60",
		"-m owner --uid-owner 0",
		"-m iprange --src-range 192.168.10.1-192.168.10.5 -j DROP",
		/* Multiport cannot be used in conjunction of -m protocol */
		/* TODO this is iptables.c limitation, fix it */
		"-p tcp -m tcp -m multiport 45:8000 -j ACCEPT",
		/* Clearly invalid */
		"-p tcp -m",
		/* Invalid port specifiers for multiport*/
		"-p tcp -m multiport --dport 6789 -j ACCEPT"
		"-p tcp -m multiport --sport 6789 -j DROP",
		"-p tcp -m multiport --dports -j ACCEPT",
		/* TODO FIX these in firewall.c */
		/*"-p tcp -m multiport --destination-port 6789 -j LOG",
		"-p tcp -m multiport --source-port 6789 -j QUEUE",
		"-p tcp -m multiport --dport 6789 --sport 6788 -j REJECT",*/
		NULL
};
static const char *invalid_general_forward[] = {
		/* Double target */
		"-j ACCEPT -j DROP",
		/* Invalid multiport range */
		"-p udp -m multiport --dports 11-4000 -j ACCEPT",
		/* No protocol and double match */
		"-m multiport -m tcp --dports 70:111 -j ACCEPT",
		/* Double match */
		"-p tcp -m multiport -m tcp --dports 555:666 -j ACCEPT",
		/* No protocol */
		"-p -j DROP",
		NULL
};
static const char *invalid_eth_input[] = {
		"-p tcp -m tcp --dport 80 -j ACCEPT -j DROP",
		"udp -m udp --dport 81 -j DROP",
		"-p tcp -p all -m conntrack --ctstate RELATED -j ACCEPT",
		"-i eth0 -j LOG",
		"--in-interface eth0 -j LOG",
		NULL
};
static const char *invalid_eth_output[] = {
		"-p tcp -m tcp --sport 80 -j ACCEPT -j ACCEPT -j DROP",
		"-p udp -m udp --sport 81 --dport 50 --dport 40 -j DROP",
		"DROP",
		"-o eth1 -j QUEUE",
		"--out-interface eth1 -j QUEUE",
		"-m tcp --dport 8888 -j DROP",
		NULL
};

static gboolean setup_main_config(GKeyFile *config)
{
	g_assert(config);

	if (global_config_type & GLOBAL_NOT_SET){
		DBG("invalid global_config_type");
		return FALSE;
	}

	if (global_config_type & CONFIG_MAIN_INVALID) {
		DBG("invalid main config");
		
		g_key_file_set_string_list(config, "invalid",
					"IPv4.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULE", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv8.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTGOING.RULES", general_output,
					g_strv_length((char**)general_output));
		return TRUE;
	}

	if (global_config_type & CONFIG_OK ||
				global_config_type & CONFIG_MIXED) {
		DBG("ok or mixed");
		g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULES", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv4.FORWARD.RULES", general_forward,
					g_strv_length((char**)general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.INPUT.RULES", eth_input,
					g_strv_length((char**)eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.OUTPUT.RULES", eth_output,
					g_strv_length((char**)eth_output));

		g_key_file_set_string_list(config, "cellular",
					"IPv4.INPUT.RULES", cellular_input,
					g_strv_length((char**)cellular_input));

		g_key_file_set_string_list(config, "cellular",
					"IPv4.OUTPUT.RULES", cellular_output,
					g_strv_length((char**)cellular_output));

		// IPv6
		g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES", general_input,
					g_strv_length((char**)general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTPUT.RULES", general_output,
					g_strv_length((char**)general_output));

		g_key_file_set_string_list(config, "General",
					"IPv6.FORWARD.RULES", general_forward,
					g_strv_length((char**)general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.INPUT.RULES", eth_input,
					g_strv_length((char**)eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.OUTPUT.RULES", eth_output,
					g_strv_length((char**)eth_output));

		g_key_file_set_string_list(config, "cellular",
					"IPv6.INPUT.RULES", cellular_input,
					g_strv_length((char**)cellular_input));

		g_key_file_set_string_list(config, "cellular",
					"IPv6.OUTPUT.RULES", cellular_output,
					g_strv_length((char**)cellular_output));
	}

	if (global_config_type & CONFIG_INVALID) {
		DBG("invalid");
		g_key_file_set_string_list(config, "General",
					"IPv4.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "General",
					"IPv4.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "General",
					"IPv4.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv4.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
		
		// IPv6
		g_key_file_set_string_list(config, "General",
					"IPv6.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "General",
					"IPv6.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "General",
					"IPv6.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "ethernet",
					"IPv6.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
	}

	/*
	 * Group change is required because otherwise groups would be
	 * overwritten
	 */
	if (global_config_type & CONFIG_MIXED) {
		DBG("mixed");
		g_key_file_set_string_list(config, "wifi",
					"IPv4.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "wifi",
					"IPv4.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "wifi",
					"IPv4.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "vpn",
					"IPv4.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "vpn",
					"IPv4.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
		
		// IPv6
		g_key_file_set_string_list(config, "wifi",
					"IPv6.INPUT.RULES",
					invalid_general_input,
					g_strv_length(
					(char**)invalid_general_input));

		g_key_file_set_string_list(config, "wifi",
					"IPv6.OUTPUT.RULES",
					invalid_general_output,
					g_strv_length(
					(char**)invalid_general_output));

		g_key_file_set_string_list(config, "wifi",
					"IPv6.FORWARD.RULES",
					invalid_general_forward,
					g_strv_length(
					(char**)invalid_general_forward));

		g_key_file_set_string_list(config, "vpn",
					"IPv6.INPUT.RULES",
					invalid_eth_input,
					g_strv_length(
					(char**)invalid_eth_input));

		g_key_file_set_string_list(config, "vpn",
					"IPv6.OUTPUT.RULES",
					invalid_eth_output,
					g_strv_length(
					(char**)invalid_eth_output));
	}

	if (global_config_type & CONFIG_TETHERING) {
		g_key_file_set_string_list(config, "tethering",
					"IPv4.INPUT.RULES",
					tethering_input,
					g_strv_length((char**)tethering_input));
		g_key_file_set_string_list(config, "tethering",
					"IPv4.FORWARD.RULES",
					tethering_forward,
					g_strv_length(
					(char**)tethering_forward));
		g_key_file_set_string_list(config, "tethering",
					"IPv4.OUTPUT.RULES",
					tethering_output,
					g_strv_length(
					(char**)tethering_output));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.INPUT.RULES",
					tethering_input,
					g_strv_length((char**)tethering_input));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.FORWARD.RULES",
					tethering_forward,
					g_strv_length(
					(char**)tethering_forward));
		g_key_file_set_string_list(config, "tethering",
					"IPv6.OUTPUT.RULES",
					tethering_output,
					g_strv_length(
					(char**)tethering_output));
	}

	if (global_config_type & CONFIG_OK &&
				global_config_type & CONFIG_USE_POLICY) {
		g_key_file_set_string(config, "General", "IPv4.INPUT.POLICY",
					general_policies_ok[0]);
		g_key_file_set_string(config, "General", "IPv4.FORWARD.POLICY",
					general_policies_ok[1]);
		g_key_file_set_string(config, "General", "IPv4.OUTPUT.POLICY",
					general_policies_ok[2]);
		g_key_file_set_string(config, "General", "IPv6.INPUT.POLICY",
					general_policies_ok[0]);
		g_key_file_set_string(config, "General", "IPv6.FORWARD.POLICY",
					general_policies_ok[1]);
		g_key_file_set_string(config, "General", "IPv6.OUTPUT.POLICY",
					general_policies_ok[2]);
	}

	if (global_config_type & CONFIG_INVALID &&
				global_config_type & CONFIG_USE_POLICY) {
		g_key_file_set_string(config, "General", "IPv4.INPUT.POLICY",
					general_policies_fail[0]);
		g_key_file_set_string(config, "General", "IPv4.FORWARD.POLICY",
					general_policies_fail[1]);
		g_key_file_set_string(config, "General", "IPv4.OUTPUT.POLICY",
					general_policies_fail[2]);
		g_key_file_set_string(config, "General", "IPv6.INPUT.POLICY",
					general_policies_fail[0]);
		g_key_file_set_string(config, "General", "IPv6.FORWARD.POLICY",
					general_policies_fail[1]);
		g_key_file_set_string(config, "General", "IPv6.OUTPUT.POLICY",
					general_policies_fail[2]);
	}

	return TRUE;
}

#define RULES_CEL_ADD0 3
#define RULES_ETH_ADD1 2
#define RULES_CEL_ADD2 2
#define RULES_ETH_ADD3 3

// Cellular
static const char *cel_input_add0[] = {
			"-p udp -m udp --dport 12000 -j LOG",
			"-p tcp -m tcp --dport 12001 -j QUEUE",
			"-p dccp -m dccp --dport 12002 -j REJECT",
			NULL,
};

static const char *input_fail0[] = {
			"-p sctp -m tcp -j ACCEPT",
			"-p udplite -m udp -j DROP",
			"-m state -j DROP",
			NULL,
};

// Ethernet
static const char *eth_input_add1[] = {
			"-m mark --mark 1 -j DROP",
			"-p ah -j ACCEPT",
			NULL,
};

static const char *input_fail1[] = {
			"-o eth1 -p tcp -m tcp --dport -j DROP",
			"-i eth1 -o eth2 -j ACCEPT",
			NULL,
};

// Cellular
static const char *cel_input_add2[] = {
			"-j ACCEPT",
			"-p sctp -j DROP",
			NULL,
};

static const char *input_fail2[] = {
			"-p udp -j",
			"-m -j DROP",
			NULL,
};

// Ethernet
static const char *eth_input_add3[] = {
			"-p dccp -m dccp --sport 34 --dport 55 -j ACCEPT",
			"-p dccp -m multiport --ports 56:67 -j DROP",
			"-p all -m conntrack --ctstate NEW -j ACCEPT",
			NULL,
};

static const char *input_fail3[] = {
			"-m DROP",
			NULL,
};

static const char **input_ok_rules[4] = {
			cel_input_add0,
			eth_input_add1,
			cel_input_add2,
			eth_input_add3,
};

static const char **input_fail_rules[4] = {
			input_fail0,
			input_fail1,
			input_fail2,
			input_fail3,
};

gboolean setup_config(GKeyFile *config, int config_index)
{
	g_assert(config);
	gchar *config_group;

	DBG("%d", config_index);

	switch (config_index) {
	case 0: // "10-firewall.conf"
		config_group = g_strdup("cellular");
		break;
	case 1: // "30-firewall.conf"
		config_group = g_strdup("ethernet");
		break;
	case 2: // "20-firewall.conf"
		config_group = g_strdup("cellular");
		break;
	case 3: // "01-firewall.conf"
		config_group = g_strdup("ethernet");
		break;
	case 4: // NULL, nothing to add
		return TRUE;
	default:
		return FALSE;
	}

	if (global_config_type & CONFIG_OK ||
				global_config_type & CONFIG_MIXED) {
		DBG("ok or mixed");
		g_key_file_set_string_list(config, config_group,
					"IPv4.INPUT.RULES",
					input_ok_rules[config_index],
					g_strv_length(
					(char**)input_ok_rules[config_index]));
		g_key_file_set_string_list(config, config_group,
					"IPv6.INPUT.RULES",
					input_ok_rules[config_index],
					g_strv_length(
					(char**)input_ok_rules[config_index]));
	}

	if (global_config_type & CONFIG_INVALID ||
				global_config_type & CONFIG_MIXED) {
		DBG("invalid or mixed");
		g_key_file_set_string_list(config, config_group,
					"IPv4.OUTPUT.RULES",
					input_fail_rules[config_index],
					g_strv_length(
					(char**)input_fail_rules[config_index]));
		g_key_file_set_string_list(config, config_group,
					"IPv6.OUTPUT.RULES",
					input_fail_rules[config_index],
					g_strv_length(
					(char**)input_fail_rules[config_index]));
	}

	g_free(config_group);

	return TRUE;
}

gboolean g_key_file_load_from_file(GKeyFile *key_file, const gchar *file,
			GKeyFileFlags flags, GError **error)
{
	int i;

	DBG("load %s\n", file);

	if (g_strstr_len(file, -1, "firewall.d")) {
		for (i = 0; testfiles[i]; i++) {
			if (g_str_has_suffix(file, testfiles[i])) {
				DBG("file %s", testfiles[i]);
				
				// Use main config to detect duplicates
				if (global_config_type & CONFIG_DUPLICATES) {
					DBG("return duplicate of main");
					return setup_main_config(key_file);
				} else {
					return setup_config(key_file, i);
				}
			}
		}
		return FALSE;
	} else {
		return setup_main_config(key_file);
	}
}

// End of dummies

static DBusMessage *construct_message_reload()
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CONNMAN_SERVICE ".Firewall",
				"/", CONNMAN_SERVICE ".Firewall", "Reload");

	// Close everything off
	dbus_message_set_serial (msg, 1);

	return msg;
}

static void service_state_change(struct connman_service *service,
			enum connman_service_state state)
{
	if (firewall_notifier)
		firewall_notifier->service_state_changed(service, state);

	service->state = state;
}

static void service_remove(struct connman_service *service)
{
	if (firewall_notifier)
		firewall_notifier->service_remove(service);
	
	service->state = CONNMAN_SERVICE_STATE_IDLE;
}

static gboolean is_supported_by_type(int type, const char *rule_spec)
{
	int i = 0;
	const char *not_with_ipv4[] = { "-p icmpv6",
					"-p ipv6-icmp",
					"-p mh",
					NULL
	};
	const char *not_with_ipv6[] = { "-p icmp", "-m ttl", NULL};

	switch (type) {
	case AF_INET:
		for (i = 0; not_with_ipv4[i]; i++) {
			if (g_strstr_len(rule_spec, -1, not_with_ipv4[i]))
				return false;
		}
		return true;
	case AF_INET6:
		for (i = 0; not_with_ipv6[i]; i++) {
			if (g_strstr_len(rule_spec, -1, not_with_ipv6[i]))
				return false;
		}
		return true;
	default:
		return false;
	}
}

static void assert_rule_exists(int type, const char *table, const char *chain,
			const char *rule_spec, const char *device)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;
	char *rule_str;
	char device_type;

	// Rules starting with # are interpreted as empty (commented) rules
	if (rule_spec[0] == '#' || !is_supported_by_type(type, rule_spec))
		return;

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	if (device) {
		if (!g_strcmp0(chain, connman_chains[0]))
			device_type = 'i';
		else if (!g_strcmp0(chain, connman_chains[1]))
			device_type = 'o';
		else if (!g_strcmp0(chain, connman_chains[2]))
			device_type = 'o';
		else
			device_type = '?';
		
		g_assert(device_type != '?');
		
		rule_str = g_strdup_printf("-%c %s %s", device_type, device,
					rule_spec);
	} else {
		rule_str = g_strdup(rule_spec);
	}

	while (iter) {
		rule = iter->data;
		
		if (rule->type == type && !g_strcmp0(rule->table, table) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_str))
			goto out;

		iter = iter->next;
	}

	g_assert(FALSE);

out:
	g_free(rule_str);
}

static void assert_rule_not_exists(int type, const char *table,
			const char *chain, const char *rule_spec,
			const char *device)
{
	GSList *iter = NULL;
	struct iptables_rule *rule;
	char *rule_str;
	char device_type;

	// Rules starting with # are interpreted as empty (commented) rules
	if (rule_spec[0] == '#')
		return;

	switch (type) {
	case AF_INET:
		iter = rules_ipv4;
		break;
	case AF_INET6:
		iter = rules_ipv6;
	}

	if (device) {
		if (!g_strcmp0(chain, connman_chains[0]))
			device_type = 'i';
		else if (!g_strcmp0(chain, connman_chains[1]))
			device_type = 'o';
		else if (!g_strcmp0(chain, connman_chains[2]))
			device_type = 'o';
		else
			device_type = '?';
		
		g_assert(device_type != '?');
		
		rule_str = g_strdup_printf("-%c %s %s", device_type, device,
					rule_spec);
	} else {
		rule_str = g_strdup(rule_spec);
	}

	while (iter) {
		rule = iter->data;

		g_assert_false(rule->type == type &&
					!g_strcmp0(rule->table, table) &&
					!g_strcmp0(rule->chain, chain) &&
					!g_strcmp0(rule->rule_spec, rule_str));

		iter = iter->next;
	}

	g_free(rule_str);
}

typedef  void (*assert_cb_t)(int type, const char *table, const char *chain,
			const char *rule_spec, const char *device);

static void check_rules(assert_cb_t cb, const char **rules[],
			const char *ifname)
{
	int i, j;

	for (j = 0; j < 3; j++) {
		if (!rules[j])
			continue;

		for (i = 0; rules[j][i]; i++) {
			cb(AF_INET, "filter", connman_chains[j], rules[j][i],
						ifname);
			cb(AF_INET6, "filter", connman_chains[j], rules[j][i],
						ifname);
		}
	}
}

static void check_main_config_rules()
{
	const char **general_rules_all[] = {
				general_input,
				general_forward,
				general_output
	};
	const char **eth_rules_all[] = {eth_input, NULL, eth_output};
	const char **cel_rules_all[] = {cellular_input, NULL, cellular_output};

	check_rules(assert_rule_exists, general_rules_all, NULL);
	check_rules(assert_rule_not_exists, eth_rules_all, NULL);
	check_rules(assert_rule_not_exists, cel_rules_all, NULL);
}

static void check_default_policies(const char *policies[])
{
	int i;

	for (i = 0; i < 3; i++) {
		DBG("IPv4 %s - %s", policies_ipv4[i], policies[i]);
		if (policies_ipv4[i] && policies[i])
			g_assert(!g_strcmp0(policies_ipv4[i], policies[i]));

		DBG("IPv6 %s - %s", policies_ipv6[i], policies[i]);
		if (policies_ipv6[i] && policies[i])
			g_assert(!g_strcmp0(policies_ipv6[i], policies[i]));
	}
}

static void firewall_test_basic0()
{
	struct firewall_context *ctx;

	__connman_iptables_init();
	
	g_assert(!__connman_firewall_is_up());
	
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert(__connman_firewall_enable(ctx) == -ENOENT);
	
	g_assert(__connman_firewall_is_up());

	g_assert(__connman_firewall_disable(ctx) == -ENOENT);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static const char *basic_rules[] = { "-o eth1 -j ACCEPT",
					"-p tcp -m tcp -j DROP",
					"-m conntrack --ctstate NEW -j ACCEPT",
					"-i wlan0 -j REJECT",
					"-m mark --mark 0x01 -j QUEUE",
					NULL
};

static void firewall_test_basic1()
{
	struct firewall_context *ctx;
	int id[5], id6[5], i;
	const char *table = "filter";
	const char *chain = "INPUT";

	__connman_iptables_init();
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert(__connman_firewall_is_up());
	
	for (i = 0; i < 5; i++) {
		id[i] = __connman_firewall_add_rule(ctx, NULL, NULL, table,
					chain, basic_rules[i]);
		
		g_assert(id[i] >= 0);
		
		id6[i] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL,
					table, chain, basic_rules[i]);
		
		g_assert(id6[i] >= 0);
	}

	g_assert(__connman_firewall_enable(ctx) == 0);
	
	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 6);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 6);

	g_assert(__connman_firewall_disable(ctx) == 0);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void firewall_test_basic2()
{
	struct firewall_context *ctx;
	int id[5], id6[5], i = 0, res;
	const char *table = "filter";
	const char *chains[] = {"INPUT", "connman-INPUT", "OUTPUT",
				"connman-OUTPUT", "FORWARD" };

	__connman_iptables_init();
	__connman_firewall_init();

	ctx = __connman_firewall_create();

	g_assert(ctx);

	g_assert(__connman_firewall_is_up());
	
	id[0] = __connman_firewall_add_rule(ctx, NULL, NULL, table, chains[0],
				basic_rules[0]);
	g_assert(id[0]);
		
	id6[0] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL, table,
				chains[0], basic_rules[0]);
	g_assert(id6[0]);
	
	g_assert(__connman_firewall_enable(ctx) == 0);

	for (i = 1; i < 5; i++) {
		id[i] = __connman_firewall_add_rule(ctx, NULL, NULL, table,
					chains[i], basic_rules[i]);

		g_assert(id[i]);
		
		id6[i] = __connman_firewall_add_ipv6_rule(ctx, NULL, NULL,
					table, chains[i], basic_rules[i]);

		g_assert(id6[i]);
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 2); // +1 managed chain
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 2); // +1 managed chain

	g_assert(__connman_firewall_remove_rule(ctx, id[3]) == 0);
	id[3] = 0;

	g_assert(__connman_firewall_remove_ipv6_rule(ctx, id6[2]) == 0);
	id6[2] = 0;

	for (i = 0; i < 5; i++) {
		res = __connman_firewall_enable_rule(ctx, id[i]);

		if (id[i] && i > 0)
			g_assert(res == 0);
		else
			g_assert(res != 0);

		res = __connman_firewall_enable_rule(ctx, id6[i]);

		if (id6[i] && i > 0)
			g_assert(res == 0);
		else
			g_assert(res != 0);
		
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 7); // +3 managed chains
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 6); // +2 managed chains
	
	for (i = 0; i < 5; i++) {
		res = __connman_firewall_disable_rule(ctx, id[i]);

		if (id[i])
			g_assert(res == 0);
		else
			g_assert(res != 0);

		res = __connman_firewall_disable_rule(ctx, id6[i]);

		if (id6[i])
			g_assert(res == 0);
		else
			g_assert(res != 0);
		
	}

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	g_assert(__connman_firewall_disable(ctx) == 0);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok0()
{
	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok1()
{
	setup_test_params(CONFIG_MIXED);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_ok2()
{
	setup_test_params(CONFIG_OK|CONFIG_USE_POLICY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();
	check_default_policies(general_policies_ok);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_ok0()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_ok1()
{
	setup_test_params(CONFIG_MIXED|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_duplicates0()
{
	setup_test_params(CONFIG_OK|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_duplicates1()
{
	setup_test_params(CONFIG_MIXED|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail0()
{
	setup_test_params(CONFIG_INVALID); // Rules that are invalid

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail1()
{
	setup_test_params(CONFIG_INVALID|CONFIG_USE_POLICY);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_default_policies(policies_default);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_main_config_fail2()
{
	setup_test_params(CONFIG_MAIN_INVALID); // Invalid groups, keys

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_all_config_fail0()
{
	setup_test_params(CONFIG_INVALID|CONFIG_DUPLICATES|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* One service to ready, online and off */
static void firewall_test_dynamic_ok0()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);
	// Double on
	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Two services on and off and both running at the same time*/
static void firewall_test_dynamic_ok1()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert(g_slist_length(rules_ipv4) ==
				RULES_GEN4 + RULES_ETH + RULES_CEL);
	g_assert(g_slist_length(rules_ipv6) ==
				RULES_GEN6 + RULES_ETH + RULES_CEL);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, cel_rules, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state =
				CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL);

	check_rules(assert_rule_not_exists, eth_rules, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, cel_rules, ifname2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static const char *tethering_default_input[] = {"-j ACCEPT", NULL};

/* Tethering on twice, off, re-enable and off with default rules */
static void firewall_test_dynamic_ok2()
{
	const char *ifname;
	const char **device_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Tethering without defined rules
	test_technology.default_rules = true;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);
	// Double notify
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 1);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 1 );

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, device_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	// Re-enable
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + 1);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + 1 );

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, device_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Tethering with custom rules */
static void firewall_test_dynamic_ok3()
{
	const char *ifname;

	const char **tethering_rules[] = { tethering_input, 
					tethering_forward,
					tethering_output,
	};
	const char **not_exist_rules[] = { tethering_default_input, NULL, NULL};

	setup_test_params(CONFIG_OK|CONFIG_TETHERING);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Tethering with custom rules
	test_technology.default_rules = false;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH);

	ifname = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, tethering_rules, ifname);
	check_rules(assert_rule_not_exists, not_exist_rules, ifname);

	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, tethering_rules, ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Two services and tethering with custom rules on and off and running
 * simultaneously
 */
static void firewall_test_dynamic_ok4()
{
	const char *iftether;
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};
	const char **tethering_rules[] = { tethering_input, 
					tethering_forward,
					tethering_output,
	};
	const char **not_exist_rules[] = { tethering_default_input, NULL, NULL};
	const char **eth_add_rules1[] = { eth_input_add1, NULL, NULL };
	const char **eth_add_rules3[] = { eth_input_add3, NULL, NULL };
	const char **cel_add_rules0[] = { cel_input_add0, NULL, NULL };
	const char **cel_add_rules2[] = { cel_input_add2, NULL, NULL };

	setup_test_params(CONFIG_MIXED|CONFIG_TETHERING|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);
	check_rules(assert_rule_exists, eth_add_rules1, ifname);
	check_rules(assert_rule_exists, eth_add_rules3, ifname);

	// Tethering on
	test_technology.default_rules = false;
	test_technology.enabled = true;
	firewall_notifier->tethering_changed(&test_technology, true);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH);

	iftether = __connman_tethering_get_bridge();
	check_rules(assert_rule_exists, tethering_rules, iftether);
	check_rules(assert_rule_not_exists, not_exist_rules, iftether);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH  +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH  +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, cel_rules, ifname2);
	check_rules(assert_rule_exists, cel_add_rules0, ifname2);
	check_rules(assert_rule_exists, cel_add_rules2, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH +
				RULES_CEL + RULES_CEL_ADD0 + RULES_CEL_ADD2);

	check_rules(assert_rule_not_exists, eth_rules, ifname);
	check_rules(assert_rule_not_exists, eth_add_rules1, ifname);
	check_rules(assert_rule_not_exists, eth_add_rules3, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_TETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_TETH);

	check_rules(assert_rule_not_exists, cel_rules, ifname2);
	check_rules(assert_rule_not_exists, eth_add_rules1, ifname2);
	check_rules(assert_rule_not_exists, eth_add_rules3, ifname2);

	// Disable tethering
	firewall_notifier->tethering_changed(&test_technology, false);
	test_technology.enabled = false;

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, tethering_rules, iftether);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* One service on and off with changing interface */
static void firewall_test_dynamic_ok5()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service3.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service3);
	check_rules(assert_rule_exists, device_rules, ifname);

	test_service3.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);

	test_service3.ifname = g_strdup("eth2");

	test_service3.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service3);
	check_rules(assert_rule_exists, device_rules, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service3, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);
	g_free(test_service3.ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Two services on and off and both running at the same time with additional
 * files
 */
static void firewall_test_dynamic_ok6()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output };
	const char **eth_add_rules1[] = { eth_input_add1, NULL, NULL };
	const char **eth_add_rules3[] = { eth_input_add3, NULL, NULL };
	const char **cel_add_rules0[] = { cel_input_add0, NULL, NULL };
	const char **cel_add_rules2[] = { cel_input_add2, NULL, NULL };

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);
	check_rules(assert_rule_exists, eth_add_rules1, ifname);
	check_rules(assert_rule_exists, eth_add_rules3, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, cel_rules, ifname2);
	check_rules(assert_rule_exists, cel_add_rules0, ifname2);
	check_rules(assert_rule_exists, cel_add_rules2, ifname2);

	// Disable ethernet test service
	test_service.state = test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL +
				RULES_CEL_ADD0 + RULES_CEL_ADD2);

	check_rules(assert_rule_not_exists, eth_rules, ifname);
	check_rules(assert_rule_not_exists, eth_add_rules1, ifname);
	check_rules(assert_rule_not_exists, eth_add_rules3, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, cel_rules, ifname2);
	check_rules(assert_rule_not_exists, cel_add_rules0, ifname2);
	check_rules(assert_rule_not_exists, cel_add_rules2, ifname2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/* Two services on and off and both running at the same time and other removed*/
static void firewall_test_dynamic_ok7()
{
	char *ifname, *ifname2;

	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **cel_rules[] = { cellular_input, NULL, cellular_output};

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);

	// Enable cellular test service
	test_service2.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_READY);

	g_assert(g_slist_length(rules_ipv4) ==
				RULES_GEN4 + RULES_ETH + RULES_CEL);
	g_assert(g_slist_length(rules_ipv6) ==
				RULES_GEN6 + RULES_ETH + RULES_CEL);

	ifname2 = connman_service_get_interface(&test_service2);
	check_rules(assert_rule_exists, cel_rules, ifname2);

	test_service2.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Remove ethernet test service twice
	service_remove(&test_service);
	service_remove(&test_service);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_CEL);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_CEL);

	check_rules(assert_rule_not_exists, eth_rules, ifname);

	// Disable cellular test service
	service_state_change(&test_service2, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, cel_rules, ifname2);

	// Remove disconnected
	service_remove(&test_service2);

	g_free(ifname);
	g_free(ifname2);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload0()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload1()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload2()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, eth_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload3()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **add_rules1[] = { eth_input_add1, NULL, NULL};
	const char **add_rules3[] = { eth_input_add3, NULL, NULL};
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	toggle_config(FILE_ETH1, FALSE);
	toggle_config(FILE_ETH3, FALSE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Load new configs
	toggle_config(FILE_ETH1, TRUE);
	toggle_config(FILE_ETH3, TRUE);

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD1 + RULES_ETH_ADD3);

	check_rules(assert_rule_exists, eth_rules, ifname);
	check_rules(assert_rule_exists, add_rules1, ifname);
	check_rules(assert_rule_exists, add_rules3, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, eth_rules, ifname);
	check_rules(assert_rule_not_exists, add_rules1, ifname);
	check_rules(assert_rule_not_exists, add_rules3, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

/*
 * Remove configs before service is enabled, start service and remove another
 * config.
 */
static void firewall_test_config_reload4()
{
	char *ifname;
	const char **eth_rules[] = { eth_input, NULL, eth_output };
	const char **add_rules1[] = { eth_input_add1, NULL, NULL};
	const char **add_rules3[] = { eth_input_add3, NULL, NULL};
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	msg = construct_message_reload();

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	// Disable first and reload
	toggle_config(FILE_ETH1, FALSE);

	reply = reload_call(NULL, msg, NULL);
	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);

	// Enable ethernet test_service
	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;
	test_service.state = CONNMAN_SERVICE_STATE_READY;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH +
				RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH +
				RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, eth_rules, ifname);
	check_rules(assert_rule_exists, add_rules3, ifname);
	check_rules(assert_rule_not_exists, add_rules1, ifname);

	test_service.state = CONNMAN_SERVICE_STATE_ONLINE;

	// Remove config 3
	toggle_config(FILE_ETH3, FALSE);

	reply = reload_call(NULL, msg, NULL);
	g_assert(dbus_message_get_type(reply) != DBUS_MESSAGE_TYPE_ERROR);

	/* TODO enable more fine grained error checking, currently only
	 * permission denied would be returned as error, so only error type is
	 * required to be checked.
	 */
	/*g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));*/

	dbus_message_unref(reply);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4 + RULES_ETH);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6 + RULES_ETH);

	check_rules(assert_rule_exists, eth_rules, ifname);
	check_rules(assert_rule_not_exists, add_rules1, ifname);
	check_rules(assert_rule_not_exists, add_rules3, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	check_rules(assert_rule_not_exists, eth_rules, ifname);

	g_free(ifname);
	dbus_message_unref(msg);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload_fail0()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|ACCESS_FAILURE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_config_reload_fail1()
{
	DBusMessage *msg;
	DBusMessage *reply;

	setup_test_params(CONFIG_OK|DIR_ACCESS_FAILURE);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	msg = construct_message_reload();
	reply = reload_call(NULL, msg, NULL);

	g_assert(!dbus_message_is_error(reply,
				CONNMAN_ERROR_INTERFACE ".PermissionDenied"));

	dbus_message_unref(reply);
	dbus_message_unref(msg);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
}

static void firewall_test_notifier_fail0()
{
	char *ifname;

	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	notifier_fail = true; // No dynamic rules

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_main_config_rules();

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_not_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_ONLINE);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_not_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();
	
	notifier_fail = false;
}

static void firewall_test_iptables_fail0()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_COMMIT_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail1()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL|CONFIG_USE_POLICY);
	setup_iptables_params(IPTABLES_POLICY_FAIL);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	check_default_policies(policies_default);

	__connman_firewall_pre_cleanup();

	__connman_firewall_cleanup();
	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail2()
{
	char *ifname;
	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_ADD_FAIL); // General rules are not added

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_ETH + RULES_ETH_ADD1 +
				RULES_ETH_ADD3);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_ETH + RULES_ETH_ADD1 +
				RULES_ETH_ADD3);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail3()
{
	char *ifname;
	const char **device_rules[] = { eth_input, NULL, eth_output };

	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_INS_FAIL); // Managed chain fails

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	test_service.state = CONNMAN_SERVICE_STATE_CONFIGURATION;

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_READY);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	ifname = connman_service_get_interface(&test_service);
	check_rules(assert_rule_not_exists, device_rules, ifname);

	service_state_change(&test_service, CONNMAN_SERVICE_STATE_DISCONNECT);

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	check_rules(assert_rule_not_exists, device_rules, ifname);

	g_free(ifname);

	__connman_firewall_pre_cleanup();

	check_default_policies(policies_default);

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, 0);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, 0);

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static void firewall_test_iptables_fail4()
{
	setup_test_params(CONFIG_OK|CONFIG_ALL);
	setup_iptables_params(IPTABLES_NORMAL|IPTABLES_ALL_CHAINS);

	__connman_iptables_init();
	__connman_firewall_init();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);
	
	setup_iptables_params(IPTABLES_DEL_FAIL|IPTABLES_POLICY_FAIL);

	__connman_firewall_pre_cleanup();

	__connman_firewall_cleanup();

	g_assert_cmpint(g_slist_length(rules_ipv4), ==, RULES_GEN4);
	g_assert_cmpint(g_slist_length(rules_ipv6), ==, RULES_GEN6);

	__connman_iptables_cleanup();

	setup_iptables_params(IPTABLES_NORMAL);
}

static gchar *option_debug = NULL;

static bool parse_debug(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	if (value)
		option_debug = g_strdup(value);
	else
		option_debug = g_strdup("*");

	return true;
}

static GOptionEntry options[] = {
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, parse_debug,
				"Specify debug options to enable", "DEBUG" },
	{ NULL },
};

int main (int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;

	g_test_init(&argc, &argv, NULL);

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		return 1;
	}

	g_option_context_free(context);

	__connman_log_init(argv[0], option_debug, false, false,
			"Unit Tests Connection Manager", VERSION);

	g_test_add_func("/firewall/test_basic0", firewall_test_basic0);
	g_test_add_func("/firewall/test_basic1", firewall_test_basic1);
	g_test_add_func("/firewall/test_basic2", firewall_test_basic2);
	g_test_add_func("/firewall/test_main_config_ok0",
				firewall_test_main_config_ok0);
	g_test_add_func("/firewall/test_main_config_ok1",
				firewall_test_main_config_ok1);
	g_test_add_func("/firewall/test_main_config_ok2",
				firewall_test_main_config_ok2);
	g_test_add_func("/firewall/test_all_config_ok0",
				firewall_test_all_config_ok0);
	g_test_add_func("/firewall/test_all_config_ok1",
				firewall_test_all_config_ok1);
	g_test_add_func("/firewall/test_all_config_duplicates0",
				firewall_test_all_config_duplicates0);
	g_test_add_func("/firewall/test_all_config_duplicates1",
				firewall_test_all_config_duplicates1);
	g_test_add_func("/firewall/test_main_config_fail0",
				firewall_test_main_config_fail0);
	g_test_add_func("/firewall/test_main_config_fail1",
				firewall_test_main_config_fail1);
	g_test_add_func("/firewall/test_main_config_fail2",
				firewall_test_main_config_fail2);
	g_test_add_func("/firewall/test_all_config_fail0",
				firewall_test_all_config_fail0);
	g_test_add_func("/firewall/test_dynamic_ok0",
				firewall_test_dynamic_ok0);
	g_test_add_func("/firewall/test_dynamic_ok1",
				firewall_test_dynamic_ok1);
	g_test_add_func("/firewall/test_dynamic_ok2",
				firewall_test_dynamic_ok2);
	g_test_add_func("/firewall/test_dynamic_ok3",
				firewall_test_dynamic_ok3);
	g_test_add_func("/firewall/test_dynamic_ok4",
				firewall_test_dynamic_ok4);
	g_test_add_func("/firewall/test_dynamic_ok5",
				firewall_test_dynamic_ok5);
	g_test_add_func("/firewall/test_dynamic_ok6",
				firewall_test_dynamic_ok6);
	g_test_add_func("/firewall/test_dynamic_ok7",
				firewall_test_dynamic_ok7);
	g_test_add_func("/firewall/config_reload0",
				firewall_test_config_reload0);
	g_test_add_func("/firewall/config_reload1",
				firewall_test_config_reload1);
	g_test_add_func("/firewall/config_reload2",
				firewall_test_config_reload2);
	g_test_add_func("/firewall/config_reload3",
				firewall_test_config_reload3);
	g_test_add_func("/firewall/config_reload4",
				firewall_test_config_reload4);
	g_test_add_func("/firewall/config_reload_fail0",
				firewall_test_config_reload_fail0);
	g_test_add_func("/firewall/config_reload_fail1",
				firewall_test_config_reload_fail1);
	g_test_add_func("/firewall/iptables_notifier0",
				firewall_test_notifier_fail0);
	g_test_add_func("/firewall/iptables_fail0",
				firewall_test_iptables_fail0);
	g_test_add_func("/firewall/iptables_fail1",
				firewall_test_iptables_fail1);
	g_test_add_func("/firewall/iptables_fail2",
				firewall_test_iptables_fail2);
	g_test_add_func("/firewall/iptables_fail3",
				firewall_test_iptables_fail3);
	g_test_add_func("/firewall/iptables_fail4",
				firewall_test_iptables_fail4);

	return g_test_run();
}

/*
 * Local Variables:
 * mode: C
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * End:
 */