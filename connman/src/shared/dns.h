/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2022 Matthias Gerstner of SUSE. All rights reserved.
 *  Copyright (C) 2025 Jolla Mobile Ltd. All rights reserved.
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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>

#include <glib.h>

struct dns_listener_data {
	int index;
	/* Allow listener for loopback without resolvfile getting altered.
	 * Needed for systemd-resolved.
	 */
	bool lo_exclude;

	GIOChannel *udp4_listener_channel;
	GIOChannel *tcp4_listener_channel;
	guint udp4_listener_watch;
	guint tcp4_listener_watch;

	GIOChannel *udp6_listener_channel;
	GIOChannel *tcp6_listener_channel;
	guint udp6_listener_watch;
	guint tcp6_listener_watch;
};

struct dns_request_data {
	union {
		struct sockaddr_in6 __sin6; /* Only for the length */
		struct sockaddr sa;
	};
	socklen_t sa_len;
	int client_sk;
	int protocol;
	int family;
	guint16 srcid;
	guint16 dstid;
	guint16 altid;
	guint timeout;
	guint watch;
	guint numserv;
	guint numresp;
	gpointer request;
	gsize request_len;
	gpointer name;
	gpointer resp;
	gsize resplen;
	struct dns_listener_data *ifdata;
	bool append_domain;
};

struct dns_partial_reply {
	uint16_t len;
	uint16_t received;
	unsigned char buf[];
};

struct dns_server_data {
	int index;
	GList *domains;
	char *server;
	struct sockaddr *server_addr;
	socklen_t server_addr_len;
	int protocol;
	GIOChannel *channel;
	guint watch;
	guint timeout;
	bool enabled;
	bool connected;
	struct dns_partial_reply *incoming_reply;
};

struct dns_callbacks {
	void (*create_cache) (void);
	int (*cache_update) (struct dns_server_data *srv,
				const unsigned char *msg, size_t msg_len);
	void (*cache_remove_timer) (void);
	int (*resolv_from_cache) (struct dns_request_data *req,
				gpointer request, const char *lookup);
	int (*send_from_cache) (struct dns_request_data *req,
				const unsigned char *buf, uint16_t qtype,
				int socket, int protocol);
};

enum dns_ipproto {
	DNS_IPPROTO_ALL = 0,
	DNS_IPPROTO_UDP = IPPROTO_UDP,
	DNS_IPPROTO_TCP = IPPROTO_TCP
};

int dns_add_listener(int index, enum dns_ipproto ipproto, bool lo_exclude);
void dns_remove_listener(int index);
int dns_create_server(int index, const char *domain, const char *server,
				int protocol);
int dns_enable_server(int index, const char *server, int protocol, bool enable);
void dns_set_listen_port(unsigned int port);

int dns_init(struct dns_callbacks *cbs);
void dns_cleanup(void);

