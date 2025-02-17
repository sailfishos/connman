/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2020  Jolla Ltd.
 *  Copyright (C) 2020  Open Mobile Platform LLC.
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <gdbus.h>
#include <gweb/gweb.h>
#include <gweb/gresolv.h>
#include <gdhcp/gdhcp.h>

#include "connman.h"
#include "iptables_ext.h"
#include "src/shared/util.h"
#include <connman/setting.h>

#define MAINFILE "main.conf"
#define CONFIGMAINFILE CONFIGDIR "/" MAINFILE
#define CONFIGMAINDIR CONFIGMAINFILE ".d"
#define CONFIGSUFFIX ".conf"

static GKeyFile *load_config(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		if (err->code != G_FILE_ERROR_NOENT) {
			connman_error("Parsing %s failed: %s", file,
								err->message);
		}

		g_error_free(err);
		g_key_file_unref(keyfile);
		return NULL;
	}

	return keyfile;
}

static void check_config(GKeyFile *config, const char *file)
{
	char **keys;
	int j;

	if (!config)
		return;

	keys = g_key_file_get_groups(config, NULL);

	for (j = 0; keys && keys[j]; j++) {
		if (g_strcmp0(keys[j], "General") != 0)
			connman_warn("Unknown group %s in %s", keys[j], file);
	}

	g_strfreev(keys);

	keys = g_key_file_get_keys(config, "General", NULL, NULL);

	for (j = 0; keys && keys[j]; j++) {
		bool found = __connman_setting_is_supported_option(keys[j]);
		if (found)
			break;

		connman_warn("Unknown option %s in %s", keys[j], file);
	}

	g_strfreev(keys);
}

static int config_init(const char *file, bool mainconfig, bool append)
{
	GKeyFile *config;

	config = load_config(file);
	if (config) {
		DBG("parsing %s", file);
		check_config(config, file);
		__connman_setting_read_config_values(config, mainconfig,
									append);
		g_key_file_unref(config);
	}

	return 0;
}

static int config_read(const char *file)
{
	return config_init(file, false, false);
}

static GMainLoop *main_loop = NULL;

static unsigned int __terminated = 0;

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGINT:
	case SIGTERM:
		if (__terminated == 0) {
			DBG("Terminating");
			g_main_loop_quit(main_loop);
		}

		__terminated = 1;
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
		perror("Failed to set signal mask");
		return 0;
	}

	fd = signalfd(-1, &mask, 0);
	if (fd < 0) {
		perror("Failed to create signal descriptor");
		return 0;
	}

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void disconnect_callback(DBusConnection *conn, void *user_data)
{
	connman_error("D-Bus disconnect");

	g_main_loop_quit(main_loop);
}

static gboolean option_detach = TRUE;
static gboolean option_dnsproxy = TRUE;
static gboolean option_backtrace = TRUE;
static gboolean option_version = FALSE;

static bool parse_option(const char *key, const char *value,
					gpointer user_data, GError **error)
{
	const char *option_key;

	if (g_str_has_prefix(key, "--")) {
		option_key = key+2;
	} else if (key[0] == '-') {
		switch (key[1]) {
		case 'c':
			option_key = CONF_OPTION_CONFIG;
			break;
		case 'd':
			option_key = CONF_OPTION_DEBUG;
			break;
		case 'i':
			option_key = CONF_OPTION_DEVICE;
			break;
		case 'I':
			option_key = CONF_OPTION_NODEVICE;
			break;
		case 'p':
			option_key = CONF_OPTION_PLUGIN;
			break;
		case 'P':
			option_key = CONF_OPTION_NOPLUGIN;
			break;
		case 'W':
			option_key = CONF_OPTION_WIFI;
			break;
		default:
			g_printerr("An unknown option shorthand %s\n", key);
			return false;
		}
	} else {
		return false;
	}

	__connman_setting_set_option(option_key, value);

	return true;
}

static GOptionEntry options[] = {
	{ "config", 'c', 0, G_OPTION_ARG_CALLBACK, &parse_option,
				"Load the specified configuration file "
				"instead of " CONFIGMAINFILE, "FILE" },
	{ "debug", 'd', G_OPTION_FLAG_OPTIONAL_ARG,
				G_OPTION_ARG_CALLBACK, &parse_option,
				"Specify debug options to enable", "DEBUG" },
	{ "device", 'i', 0, G_OPTION_ARG_CALLBACK, &parse_option,
			"Specify networking devices or interfaces", "DEV,..." },
	{ "nodevice", 'I', 0, G_OPTION_ARG_CALLBACK, &parse_option,
			"Specify networking interfaces to ignore", "DEV,..." },
	{ "plugin", 'p', 0, G_OPTION_ARG_CALLBACK, &parse_option,
				"Specify plugins to load", "NAME,..." },
	{ "noplugin", 'P', 0, G_OPTION_ARG_CALLBACK, &parse_option,
				"Specify plugins not to load", "NAME,..." },
	{ "wifi", 'W', 0, G_OPTION_ARG_CALLBACK, &parse_option,
				"Specify driver for WiFi/Supplicant", "NAME" },
	{ "nodaemon", 'n', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_detach,
				"Don't fork daemon to background" },
	{ "nodnsproxy", 'r', G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_dnsproxy,
				"Don't support DNS resolving" },
	{ "nobacktrace", 0, G_OPTION_FLAG_REVERSE,
				G_OPTION_ARG_NONE, &option_backtrace,
				"Don't print out backtrace information" },
	{ "version", 'v', 0, G_OPTION_ARG_NONE, &option_version,
				"Show version information and exit" },
	{ NULL },
};

static struct connman_storage_callbacks storage_callbacks = {
	.pre =			__connman_technology_disable_all,
	.unload =		__connman_service_unload_services,
	.load =			__connman_service_load_services,
	.post =			__connman_technology_enable_from_config,
	.uid_changed =		__connman_notifier_storage_uid_changed,
	.access_policy_create =	__connman_access_storage_policy_create,
	.access_change_user = 	__connman_access_storage_change_user,
	.access_policy_free = 	__connman_access_storage_policy_free,
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *error = NULL;
	DBusConnection *conn;
	DBusError err;
	const char *option;
	guint signal;
	int fs_err;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);
	__connman_setting_init();

	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		if (error) {
			g_printerr("%s\n", error->message);
			g_error_free(error);
		} else
			g_printerr("An unknown error occurred\n");
		exit(1);
	}

	g_option_context_free(context);

	if (option_version) {
		printf("%s\n", VERSION);
		exit(0);
	}

	if (option_detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	gweb_log_hook = connman_log;
	gresolv_log_hook = connman_log;
	gdhcp_client_log_hook = connman_log;
	gdhcp_server_log_hook = connman_log;

	main_loop = g_main_loop_new(NULL, FALSE);

	signal = setup_signalfd();

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, CONNMAN_SERVICE, &err);
	if (!conn) {
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with system bus\n");
		exit(1);
	}

	g_dbus_set_disconnect_function(conn, disconnect_callback, NULL, NULL);

	__connman_log_init(argv[0],
			connman_setting_get_string(CONF_OPTION_DEBUG),
			option_detach, option_backtrace, "Connection Manager",
			VERSION);

	__connman_dbus_init(conn);

	option = connman_setting_get_string(CONF_OPTION_CONFIG);
	if (!option)
		config_init(CONFIGMAINFILE, true, false);
	else
		config_init(option, true, false);

	fs_err = util_read_config_files_from(CONFIGMAINDIR, CONFIGSUFFIX,
				NULL, config_read);
	if (fs_err && fs_err != -ENOTDIR)
		connman_error("failed to read configs from %s: %s",
				CONFIGMAINDIR, strerror(-fs_err));

	option = connman_setting_get_string(CONF_FILE_SYSTEM_IDENTITY);
	if (option)
		__connman_set_fsid(option);

	__connman_inotify_init();

	option = connman_setting_get_string(CONF_STORAGE_ROOT);
	__connman_storage_init(option,
				connman_setting_get_string(
						CONF_USER_STORAGE_DIR),
				connman_setting_get_fs_mode(
						CONF_STORAGE_DIR_PERMISSIONS),
				connman_setting_get_fs_mode(
						CONF_STORAGE_FILE_PERMISSIONS));

	fs_err = __connman_storage_create_dir(option,
				connman_setting_get_fs_mode(
						CONF_STORAGE_ROOT_PERMISSIONS));
	if (fs_err)
		connman_error("failed to create storage root %s: %s "
					"settings cannot be saved.",
					option, strerror(-fs_err));

	fs_err = __connman_storage_create_dir(STORAGEDIR,
				connman_setting_get_fs_mode(
						CONF_STORAGE_DIR_PERMISSIONS));
	if (fs_err) {
		connman_error("failed to create storage directory %s: %s "
					"settings cannot be saved",
					STORAGEDIR, strerror(-fs_err));
	} else {
		if (__connman_storage_register_dbus(STORAGE_DIR_TYPE_MAIN,
					&storage_callbacks))
			connman_error("failed to register storage D-Bus");
	}

	umask(connman_setting_get_fs_mode(CONF_UMASK));

	__connman_login_manager_init();
	__connman_util_init();
	__connman_technology_init();
	__connman_notifier_init();
	__connman_agent_init();
	__connman_service_init();
	__connman_peer_service_init();
	__connman_peer_init();
	__connman_provider_init();
	__connman_network_init();
	__connman_config_init();
	__connman_device_init(connman_setting_get_string(CONF_OPTION_DEVICE),
			connman_setting_get_string(CONF_OPTION_NODEVICE));

	__connman_ippool_init();
	__connman_iptables_validate_init();
	__connman_firewall_init();
	__connman_nat_init();
	__connman_tethering_init();
	__connman_counter_init();
	__connman_manager_init();
	__connman_stats_init();
	__connman_clock_init();

	__connman_ipconfig_init();
	__connman_rtnl_init();
	__connman_task_init();
	__connman_proxy_init();
	__connman_detect_init();
	__connman_session_init();
	__connman_timeserver_init();
	__connman_connection_init();

	__connman_plugin_init(connman_setting_get_string(CONF_OPTION_PLUGIN),
			connman_setting_get_string(CONF_OPTION_NOPLUGIN));

	__connman_resolver_init(option_dnsproxy);
	__connman_rtnl_start();
	__connman_dhcp_init();
	__connman_dhcpv6_init();
	__connman_wpad_init();
	__connman_wispr_init();
	__connman_rfkill_init();
	__connman_machine_init();

	g_main_loop_run(main_loop);

	g_source_remove(signal);

	__connman_machine_cleanup();
	__connman_rfkill_cleanup();
	__connman_wispr_cleanup();
	__connman_wpad_cleanup();
	__connman_dhcpv6_cleanup();
	__connman_session_cleanup();
	__connman_plugin_cleanup();
	__connman_provider_cleanup();
	__connman_connection_cleanup();
	__connman_timeserver_cleanup();
	__connman_detect_cleanup();
	__connman_proxy_cleanup();
	__connman_task_cleanup();
	__connman_rtnl_cleanup();
	__connman_resolver_cleanup();

	__connman_firewall_pre_cleanup();
	__connman_iptables_save_all();
	
	__connman_clock_cleanup();
	__connman_stats_cleanup();
	__connman_config_cleanup();
	__connman_manager_cleanup();
	__connman_counter_cleanup();
	__connman_tethering_cleanup();
	__connman_nat_cleanup();
	__connman_firewall_cleanup();
	__connman_iptables_validate_cleanup();
	__connman_peer_service_cleanup();
	__connman_peer_cleanup();
	__connman_ippool_cleanup();
	__connman_device_cleanup();
	__connman_network_cleanup();
	__connman_dhcp_cleanup();
	__connman_service_cleanup();
	__connman_agent_cleanup();
	__connman_ipconfig_cleanup();
	__connman_notifier_cleanup();
	__connman_technology_cleanup();
	__connman_login_manager_cleanup();
	__connman_storage_cleanup();
	__connman_inotify_cleanup();

	__connman_util_cleanup();
	__connman_dbus_cleanup();

	__connman_log_cleanup(option_backtrace);

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	__connman_setting_cleanup();

	return 0;
}
