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

#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>
#include <unistd.h>

#include "src/shared/dns.h"
#include "src/connman.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t rd:1;
	uint8_t tc:1;
	uint8_t aa:1;
	uint8_t opcode:4;
	uint8_t qr:1;
	uint8_t rcode:4;
	uint8_t z:3;
	uint8_t ra:1;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#elif __BYTE_ORDER == __BIG_ENDIAN
struct domain_hdr {
	uint16_t id;
	uint8_t qr:1;
	uint8_t opcode:4;
	uint8_t aa:1;
	uint8_t tc:1;
	uint8_t rd:1;
	uint8_t ra:1;
	uint8_t z:3;
	uint8_t rcode:4;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__ ((packed));
#else
#error "Unknown byte order"
#endif

struct qtype_qclass {
	uint16_t qtype;
	uint16_t qclass;
} __attribute__ ((packed));

/*
 * The TCP client requires some extra handling as we need to
 * be prepared to receive also partial DNS requests.
 */
struct tcp_partial_client_data {
	int family;
	struct dns_listener_data *ifdata;
	GIOChannel *channel;
	guint watch;
	unsigned char *buf;
	unsigned int buf_end;
	guint timeout;
};

struct domain_question {
	uint16_t type;
	uint16_t class;
} __attribute__ ((packed));

struct domain_rr {
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlen;
} __attribute__ ((packed));

#define NUM_ARRAY_ELEMENTS(a) sizeof(a) / sizeof(a[0])

/*
 * Max length of the DNS TCP packet.
 */
#define TCP_MAX_BUF_LEN 4096

#define DNS_HEADER_SIZE sizeof(struct domain_hdr)
#define DNS_HEADER_TCP_EXTRA_BYTES 2
#define DNS_TCP_HEADER_SIZE DNS_HEADER_SIZE + DNS_HEADER_TCP_EXTRA_BYTES
#define DNS_QUESTION_SIZE sizeof(struct domain_question)
#define DNS_RR_SIZE sizeof(struct domain_rr)
#define DNS_QTYPE_QCLASS_SIZE sizeof(struct qtype_qclass)

enum dns_type {
	/* IPv4 address 32-bit */
	DNS_TYPE_A = ns_t_a,
	/* IPv6 address 128-bit */
	DNS_TYPE_AAAA = ns_t_aaaa,
	/* alias to another name */
	DNS_TYPE_CNAME = ns_t_cname,
	/* start of a zone of authority */
	DNS_TYPE_SOA = ns_t_soa
};

enum dns_class {
	DNS_CLASS_IN = ns_c_in,
	DNS_CLASS_ANY = ns_c_any /* only valid for QCLASS fields */
};

static GSList *server_list;
static GSList *request_list;
static GHashTable *listener_table;
static GHashTable *partial_tcp_req_table;
static in_port_t dns_listen_port = 53;
static struct dns_callbacks *callbacks = NULL;

static guint16 get_id(void)
{
	uint64_t rand;

	/* TODO: return code is ignored, should we rather abort() on error? */
	__connman_util_get_random(&rand);

	return rand;
}

static size_t protocol_offset(int protocol)
{
	switch (protocol) {
	case IPPROTO_UDP:
		return 0;

	case IPPROTO_TCP:
		return DNS_HEADER_TCP_EXTRA_BYTES;

	default:
		/* this should never happen */
		abort();
	}
}

static const char* protocol_label(int protocol)
{
	switch(protocol) {
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_TCP:
		return "TCP";
	default:
		return "BAD_PROTOCOL";
	}
}

static int socket_type(int protocol, int extra_flags)
{
	switch (protocol) {
	case IPPROTO_UDP:
		return SOCK_DGRAM | extra_flags;
	case IPPROTO_TCP:
		return SOCK_STREAM | extra_flags;
	default:
		/* this should never happen */
		abort();
	}
}

static struct dns_request_data *find_request(guint16 id)
{
	for (GSList *list = request_list; list; list = list->next) {
		struct dns_request_data *req = list->data;

		if (req->dstid == id || req->altid == id)
			return req;
	}

	return NULL;
}

static struct dns_server_data *find_server(int index,
					const char *server,
						int protocol)
{
	DBG("index %d server %s proto %d", index, server, protocol);

	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (index < 0 && data->index < 0 &&
				g_str_equal(data->server, server) &&
				data->protocol == protocol)
			return data;

		if (index < 0 ||
				data->index < 0 || !data->server)
			continue;

		if (data->index == index &&
				g_str_equal(data->server, server) &&
				data->protocol == protocol)
			return data;
	}

	return NULL;
}

static void send_response(int sk, unsigned char *buf, size_t len,
				const struct sockaddr *to, socklen_t tolen,
				int protocol)
{
	struct domain_hdr *hdr;
	int err;
	const size_t offset = protocol_offset(protocol);
	const size_t send_size = DNS_HEADER_SIZE + offset;

	DBG("sk %d", sk);

	if (len < send_size)
		return;

	hdr = (void *) (buf + offset);
	if (offset) {
		buf[0] = 0;
		buf[1] = DNS_HEADER_SIZE;
	}

	DBG("id 0x%04x qr %d opcode %d", hdr->id, hdr->qr, hdr->opcode);

	hdr->qr = 1;
	hdr->rcode = ns_r_servfail;

	hdr->qdcount = 0;
	hdr->ancount = 0;
	hdr->nscount = 0;
	hdr->arcount = 0;

	err = sendto(sk, buf, send_size, MSG_NOSIGNAL, to, tolen);
	if (err < 0) {
		connman_error("Failed to send DNS response to %d: %s",
				sk, strerror(errno));
	}
}

static int get_req_udp_socket(struct dns_request_data *req)
{
	GIOChannel *channel;

	if (req->family == AF_INET)
		channel = req->ifdata->udp4_listener_channel;
	else
		channel = req->ifdata->udp6_listener_channel;

	if (!channel)
		return -1;

	return g_io_channel_unix_get_fd(channel);
}

static void destroy_request_data(struct dns_request_data *req)
{
	if (req->timeout > 0)
		g_source_remove(req->timeout);

	g_free(req->resp);
	g_free(req->request);
	g_free(req->name);
	g_free(req);
}

static gboolean request_timeout(gpointer user_data)
{
	struct dns_request_data *req = user_data;
	struct sockaddr *sa;
	int sk = -1;

	if (!req)
		return FALSE;

	DBG("id 0x%04x", req->srcid);

	request_list = g_slist_remove(request_list, req);

	if (req->protocol == IPPROTO_UDP) {
		sk = get_req_udp_socket(req);
		sa = &req->sa;
	} else if (req->protocol == IPPROTO_TCP) {
		sk = req->client_sk;
		sa = NULL;
	}

	if (sk < 0)
		goto out;

	if (req->resplen > 0 && req->resp) {
		/*
		 * Here we have received at least one reply (probably telling
		 * "not found" result), so send that back to client instead
		 * of more fatal server failed error.
		 */
		if (sendto(sk, req->resp, req->resplen, MSG_NOSIGNAL,
				sa, req->sa_len) < 0)
			connman_error("Failed to send response %d: %s",
					sk, strerror(errno));
	} else if (req->request) {
		/*
		 * There was not reply from server at all.
		 */
		struct domain_hdr *hdr =
			(void *)(req->request + protocol_offset(req->protocol));
		hdr->id = req->srcid;

		send_response(sk, req->request, req->request_len,
			sa, req->sa_len, req->protocol);
	}

	/*
	 * We cannot leave TCP client hanging so just kick it out
	 * if we get a request timeout from server.
	 */
	if (req->protocol == IPPROTO_TCP) {
		DBG("client %d removed", req->client_sk);
		g_hash_table_remove(partial_tcp_req_table,
				GINT_TO_POINTER(req->client_sk));
	}

out:
	req->timeout = 0;
	destroy_request_data(req);

	return FALSE;
}

static int append_data(unsigned char *buf, size_t size, const char *data)
{
	unsigned char *ptr = buf;
	size_t len;

	while (true) {
		const char *dot = strchrnul(data, '.');
		len = dot - data;

		if (len == 0)
			break;
		else if (size < len + 1)
			return -1;

		*ptr = len;
		memcpy(ptr + 1, data, len);
		ptr += len + 1;
		size -= len + 1;

		if (!dot)
			break;

		data = dot + 1;
	}

	return ptr - buf;
}

static int append_query(unsigned char *buf, size_t size,
				const char *query, const char *domain)
{
	size_t added;
	size_t left_size = size;
	int res;

	DBG("query %s domain %s", query, domain);

	res = append_data(buf, left_size, query);
	if (res < 0)
		return -1;
	left_size -= res;

	res = append_data(buf + res, left_size, domain);
	if (res < 0)
		return -1;
	left_size -= res;

	if (left_size == 0)
		return -1;

	added = size - left_size;
	*(buf + added) = 0x00;

	return added;
}

static int ns_resolv(struct dns_server_data *server,
				struct dns_request_data *req,
				gpointer request, gpointer name)
{
	int sk = -1;
	int err;
	const char *lookup = (const char *)name;

	if (!lookup || strlen(lookup) == 0)
		return -EINVAL;

	if (callbacks && callbacks->resolv_from_cache) {
		err = callbacks->resolv_from_cache(req, request, lookup);
		if (err > 0)
			/* cache hit */
			return 1;
		else if (err != 0)
			/* error other than cache miss, don't continue */
			return err;
	}

	/* forward request to real DNS server */
	sk = g_io_channel_unix_get_fd(server->channel);

	err = sendto(sk, request, req->request_len, MSG_NOSIGNAL,
			server->server_addr, server->server_addr_len);
	if (err < 0) {
		DBG("Cannot send message to server %s sock %d "
			"protocol %d (%s/%d)",
			server->server, sk, server->protocol,
			strerror(errno), errno);
		return -EIO;
	}

	req->numserv++;

	/* If we have more than one dot, we don't add domains */
	{
		const char *dot = strchr(lookup, '.');
		if (dot && dot != lookup + strlen(lookup) - 1)
			return 0;
	}

	if (server->domains && server->domains->data)
		req->append_domain = true;

	for (GList *list = server->domains; list; list = list->next) {
		int domlen, altlen;
		unsigned char alt[1024];
		const char *domain = list->data;
		const size_t offset = protocol_offset(server->protocol);
		struct domain_hdr *hdr = (void *) (&alt[0] + offset);

		if (!domain)
			continue;

		domlen = strlen(domain) + 1;

		if (domlen < 5)
			return -EINVAL;

		memcpy(alt + offset, &req->altid, sizeof(req->altid));

		memcpy(alt + offset + 2, request + offset + 2,
							DNS_HEADER_SIZE - 2);
		hdr->qdcount = htons(1);

		altlen = append_query(alt + offset + DNS_HEADER_SIZE,
					sizeof(alt) - DNS_HEADER_SIZE - offset,
					name, domain);
		if (altlen < 0)
			return -EINVAL;

		altlen += DNS_HEADER_SIZE;
		altlen += offset;

		memcpy(alt + altlen,
			request + altlen - domlen,
			req->request_len - altlen + domlen);

		if (server->protocol == IPPROTO_TCP) {
			uint16_t req_len = req->request_len + domlen -
						DNS_HEADER_TCP_EXTRA_BYTES;
			uint16_t *len_hdr = (void*)alt;
			*len_hdr = htons(req_len);
		}

		DBG("req %p dstid 0x%04x altid 0x%04x", req, req->dstid,
				req->altid);

		err = send(sk, alt, req->request_len + domlen, MSG_NOSIGNAL);
		if (err < 0)
			return -EIO;

		req->numserv++;
	}

	return 0;
}

static bool convert_label(const char *start, const char *end, const char *ptr,
				char *uptr, int remaining_len, int *used_comp,
				int *used_uncomp)
{
	int comp_pos;
	char name[NS_MAXLABEL];

	const int pos = dn_expand((const u_char *)start, (const u_char *)end, (const u_char *)ptr,
			name, NS_MAXLABEL);
	if (pos < 0) {
		DBG("uncompress error [%d/%s]", errno, strerror(errno));
		return false;
	}

	/*
	 * We need to compress back the name so that we get back to internal
	 * label presentation.
	 */
	comp_pos = dn_comp(name, (u_char *)uptr, remaining_len, NULL, NULL);
	if (comp_pos < 0) {
		DBG("compress error [%d/%s]", errno, strerror(errno));
		return false;
	}

	*used_comp = pos;
	*used_uncomp = comp_pos;

	return true;
}

static const char* uncompress(int16_t field_count, const char *start,
				const char *end, const char *ptr,
				char *uncompressed, int uncomp_len,
				char **uncompressed_ptr)
{
	char *uptr = *uncompressed_ptr; /* position in result buffer */
	char * const uncomp_end = uncompressed + uncomp_len - 1;

	DBG("count %d ptr %p end %p uptr %p", field_count, ptr, end, uptr);

	while (field_count-- > 0 && ptr < end) {
		int dlen;		/* data field length */
		int ulen;		/* uncompress length */
		int pos;		/* position in compressed string */
		char name[NS_MAXLABEL]; /* tmp label */
		uint16_t dns_type, dns_class;
		int comp_pos;

		if (!convert_label(start, end, ptr, name, NS_MAXLABEL,
					&pos, &comp_pos))
			return NULL;

		/*
		 * Copy the uncompressed resource record, type, class and \0 to
		 * tmp buffer.
		 */

		ulen = strlen(name) + 1;
		if ((uptr + ulen) > uncomp_end)
			return NULL;
		memcpy(uptr, name, ulen);

		DBG("pos %d ulen %d left %d name %s", pos, ulen,
			(int)(uncomp_end - (uptr + ulen)), uptr);

		uptr += ulen;

		ptr += pos;

		/*
		 * We copy also the fixed portion of the result (type, class,
		 * ttl, address length and the address)
		 */
		if ((uptr + NS_RRFIXEDSZ) > uncomp_end) {
			DBG("uncompressed data too large for buffer");
			return NULL;
		}
		memcpy(uptr, ptr, NS_RRFIXEDSZ);

		dns_type = uptr[0] << 8 | uptr[1];
		dns_class = uptr[2] << 8 | uptr[3];

		if (dns_class != DNS_CLASS_IN)
			return NULL;

		ptr += NS_RRFIXEDSZ;
		uptr += NS_RRFIXEDSZ;

		/*
		 * Then the variable portion of the result (data length).
		 * Typically this portion is also compressed
		 * so we need to uncompress it also when necessary.
		 */
		if (dns_type == DNS_TYPE_CNAME) {
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			uptr[-2] = comp_pos << 8;
			uptr[-1] = comp_pos & 0xff;

			uptr += comp_pos;
			ptr += pos;

		} else if (dns_type == DNS_TYPE_A || dns_type == DNS_TYPE_AAAA) {
			dlen = uptr[-2] << 8 | uptr[-1];

			if (dlen > (end - ptr) || dlen > (uncomp_end - uptr)) {
				DBG("data len %d too long", dlen);
				return NULL;
			}

			memcpy(uptr, ptr, dlen);
			uptr += dlen;
			ptr += dlen;

		} else if (dns_type == DNS_TYPE_SOA) {
			int total_len = 0;
			char *len_ptr;

			/* Primary name server expansion */
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			total_len += comp_pos;
			len_ptr = &uptr[-2];
			ptr += pos;
			uptr += comp_pos;

			/* Responsible authority's mailbox */
			if (!convert_label(start, end, ptr, uptr,
					uncomp_len - (uptr - uncompressed),
						&pos, &comp_pos))
				return NULL;

			total_len += comp_pos;
			ptr += pos;
			uptr += comp_pos;

			/*
			 * Copy rest of the soa fields (serial number,
			 * refresh interval, retry interval, expiration
			 * limit and minimum ttl). They are 20 bytes long.
			 */
			if ((uptr + 20) > uncomp_end || (ptr + 20) > end) {
				DBG("soa record too long");
				return NULL;
			}
			memcpy(uptr, ptr, 20);
			uptr += 20;
			ptr += 20;
			total_len += 20;

			/*
			 * Finally fix the length of the data part
			 */
			len_ptr[0] = total_len << 8;
			len_ptr[1] = total_len & 0xff;
		}

		*uncompressed_ptr = uptr;
	}

	return ptr;
}

/*
 * removes the qualified domain name part from the given answer sections
 * starting at 'answers', consisting of 'length' bytes.
 *
 * 'name' points the start of the unqualified host label including the leading
 * length octet.
 *
 * returns the new (possibly shorter) length of remaining payload in the
 * answers buffer, or a negative (errno) value to indicate error conditions.
 */
static int strip_domains(const char *name, char *answers, size_t length)
{
	uint16_t data_len;
	struct domain_rr *rr;
	/* length of the name label including the length header octet */
	const size_t name_len = strlen(name);
	const char *end = answers + length;

	while (answers < end) {
		char *ptr = strstr(answers, name);
		if (ptr) {
			char *domain = ptr + name_len;

			/* this now points to the domain part length octet. */
			if (*domain) {
				/*
				 * length of the rest of the labels up to the
				 * null label (zero byte).
				 */
				const size_t domain_len = strlen(domain);
				char *remaining = domain + domain_len;

				/*
				 * now shift the rest of the answer sections
				 * to the left to get rid of the domain label
				 * part
				 */
				memmove(ptr + name_len,
					remaining,
					end - remaining);

				end -= domain_len;
				length -= domain_len;
			}
		}

		/* skip to the next answer section */

		/* the labels up to the root null label */
		answers += strlen(answers) + 1;
		/* the fixed part of the RR */
		rr = (void*)answers;
		if (answers + sizeof(*rr) > end)
			return -EINVAL;
		data_len = htons(rr->rdlen);
		/* skip the rest of the RR */
		answers += sizeof(*rr);
		answers += data_len;
	}

	if (answers > end)
		return -EINVAL;

	return length;
}

/*
 * Removes domain names from replies, if one has been appended during
 * forwarding to the real DNS server.
 *
 * Returns:
 * < 0 on error (abort processing reply)
 * == 0 if the reply should be forwarded unmodified
 * > 0 returns a new reply buffer in *new_reply on success. The return value
 * indicates the new length of the data in *new_reply.
 */
static int dns_reply_fixup_domains(const char *reply, size_t reply_len,
				const size_t offset,
				struct dns_request_data *req,
				char **new_reply)
{
	char uncompressed[NS_MAXDNAME];
	char *uptr, *answers;
	size_t fixed_len;
	int new_an_len;
	const struct domain_hdr *hdr = (void *)(reply + offset);
	const char *eom = reply + reply_len;
	uint16_t header_len = offset + DNS_HEADER_SIZE;
	uint16_t domain_len;
	struct qtype_qclass *qtc;
	uint16_t dns_type;
	uint16_t dns_class;
	uint16_t section_counts[3];
	const char *ptr;
	uint8_t host_len;
	const char *domain;

	/* full header plus at least one byte for the hostname length */
	if (reply_len < header_len + 1U)
		return -EINVAL;

	section_counts[0] = hdr->ancount;
	section_counts[1] = hdr->nscount;
	section_counts[2] = hdr->arcount;

	/*
	 * length octet of the hostname.
	 * ->hostname.domain.net
	 */
	ptr = reply + header_len;
	host_len = *ptr;
	domain = ptr + host_len + 1;
	if (domain >= eom)
		return -EINVAL;

	domain_len = host_len ? strnlen(domain, eom - domain) : 0;

	/*
	 * If the query type is anything other than A or AAAA, then bail out
	 * and pass the message as is.  We only want to deal with IPv4 or IPv6
	 * addresses.
	 */
	qtc = (void*)(domain + domain_len + 1);
	if (((const char*)(qtc + 1)) > eom)
		return -EINVAL;

	dns_type = ntohs(qtc->qtype);
	dns_class = ntohs(qtc->qclass);

	if (domain_len == 0) {
		/* nothing to do */
		return 0;
	}

	/* TODO: This condition looks wrong. It should probably be
	 *
	 *  (dns_type != A && dns_type != AAAA) || dns_class != IN
	 *
	 * doing so, however, changes the behaviour of dnsproxy, e.g. MX
	 * records will be passed back to the client, but without the
	 * adjustment of the appended domain name.
	 */
	if (dns_type != DNS_TYPE_A && dns_type != DNS_TYPE_AAAA &&
			dns_class != DNS_CLASS_IN) {
		DBG("Pass msg dns type %d class %d", dns_type, dns_class);
		return 0;
	}

	/*
	 * Remove the domain name and replace it by the end of reply. Check if
	 * the domain is really there before trying to copy the data. We also
	 * need to uncompress the answers if necessary.  The domain_len can be
	 * 0 because if the original query did not contain a domain name, then
	 * we are sending two packets, first without the domain name and the
	 * second packet with domain name.  The append_domain is set to true
	 * even if we sent the first packet without domain name. In this case
	 * we end up in this branch.
	 */

	/* NOTE: length checks up and including to qtype_qclass have already
	   been done above */

	/*
	 * First copy host (without domain name) into tmp buffer.
	 */
	uptr = &uncompressed[0];
	memcpy(uptr, ptr, host_len + 1);

	uptr[host_len + 1] = '\0'; /* host termination */
	uptr += host_len + 2;

	/*
	 * Copy type and class fields of the question.
	 */
	memcpy(uptr, qtc, sizeof(*qtc));

	/*
	 * ptr points to answers after this
	 */
	ptr = (void*)(qtc + 1);
	uptr += sizeof(*qtc);
	answers = uptr;
	fixed_len = answers - uncompressed;

	/*
	 * We then uncompress the result to buffer so that we can rip off the
	 * domain name part from the question. First answers, then name server
	 * (authority) information, and finally additional record info.
	 */

	for (size_t i = 0; i < NUM_ARRAY_ELEMENTS(section_counts); i++) {
		ptr = uncompress(ntohs(section_counts[i]), reply + offset, eom,
				ptr, uncompressed, NS_MAXDNAME, &uptr);
		if (!ptr) {
			/* failed to uncompress, pass on as is
			 * (TODO: good idea?) */
			return 0;
		}
	}

	/*
	 * The uncompressed buffer now contains an almost valid response.
	 * Final step is to get rid of the domain name because at least glibc
	 * gethostbyname() implementation does extra checks and expects to
	 * find an answer without domain name if we asked a query without
	 * domain part. Note that glibc getaddrinfo() works differently and
	 * accepts FQDN in answer
	 */
	new_an_len = strip_domains(uncompressed, answers, uptr - answers);
	if (new_an_len < 0) {
		DBG("Corrupted packet");
		return -EINVAL;
	}

	/*
	 * Because we have now uncompressed the answers we might have to
	 * create a bigger buffer to hold all that data.
	 *
	 * TODO: only create a bigger buffer if actually necessary, pass
	 * allocation size of input buffer via additional parameter.
	 */

	reply_len = header_len + new_an_len + fixed_len;

	*new_reply = g_try_malloc(reply_len);
	if (!*new_reply)
		return -ENOMEM;

	memcpy(*new_reply, reply, header_len);
	memcpy(*new_reply + header_len, uncompressed, new_an_len + fixed_len);

	return reply_len;
}

static struct dns_request_data* lookup_request(
		const unsigned char *reply, size_t len, int protocol)
{
	const size_t offset = protocol_offset(protocol);
	struct dns_request_data *req;
	struct domain_hdr *hdr = (void *)(reply + offset);

	DBG("Received %zd bytes (id 0x%04x)", len, hdr->id);

	if (len < DNS_HEADER_SIZE + offset)
		return NULL;

	req = find_request(hdr->id);

	if (!req)
		return NULL;

	DBG("req %p dstid 0x%04x altid 0x%04x rcode %d",
			req, req->dstid, req->altid, hdr->rcode);

	req->numresp++;

	return req;
}

static int forward_dns_reply(char *reply, size_t reply_len, int protocol,
				struct dns_server_data *data,
				struct dns_request_data *req)
{
	const size_t offset = protocol_offset(protocol);
	struct domain_hdr *hdr = (void *)(reply + offset);
	int err, sk;

	/* replace with original request ID from our client */
	hdr->id = req->srcid;

	if (hdr->rcode == ns_r_noerror || !req->resp) {
		/*
		 * If the domain name was appended remove it before forwarding
		 * the reply. If there were more than one question, then this
		 * domain name ripping can be hairy so avoid that and bail out
		 * in that that case.
		 *
		 * The reason we are doing this magic is that if the user's
		 * DNS client tries to resolv hostname without domain part, it
		 * also expects to get the result without a domain name part.
		 */
		char *new_reply = NULL;

		if (req->append_domain && ntohs(hdr->qdcount) == 1) {
			const int fixup_res = dns_reply_fixup_domains(
					reply, reply_len,
					offset, req, &new_reply);
			if (fixup_res < 0) {
				/* error occured */
				return fixup_res;
			} else if (fixup_res > 0 && new_reply) {
				/* new reply length */
				reply_len = fixup_res;
				reply = new_reply;
			} else {
				/* keep message as is */
			}
		}

		g_free(req->resp);
		req->resplen = 0;

		req->resp = g_try_malloc(reply_len);
		if (!req->resp)
			return -ENOMEM;

		memcpy(req->resp, reply, reply_len);
		req->resplen = reply_len;

		if (callbacks && callbacks->cache_update)
			callbacks->cache_update(data, (unsigned char*)reply,
								reply_len);

		g_free(new_reply);
	}

	if (req->numresp < req->numserv) {
		if (hdr->rcode > ns_r_noerror) {
			return -EINVAL;
		} else if (hdr->ancount == 0 && req->append_domain) {
			return -EINVAL;
		}
	}

	request_list = g_slist_remove(request_list, req);

	if (protocol == IPPROTO_UDP) {
		sk = get_req_udp_socket(req);
		if (sk < 0) {
			errno = -EIO;
			err = -EIO;
		} else
			err = sendto(sk, req->resp, req->resplen, 0,
				&req->sa, req->sa_len);
	} else {
		const uint16_t tcp_len = htons(req->resplen -
						DNS_HEADER_TCP_EXTRA_BYTES);
		/* correct TCP message length */
		memcpy(req->resp, &tcp_len, sizeof(tcp_len));
		sk = req->client_sk;
		err = send(sk, req->resp, req->resplen, MSG_NOSIGNAL);
	}

	if (err < 0)
		DBG("Cannot send msg, sk %d proto %d errno %d/%s", sk,
			protocol, errno, strerror(errno));
	else
		DBG("proto %d sent %d bytes to %d", protocol, err, sk);

	return err;
}

static void server_destroy_socket(struct dns_server_data *data)
{
	DBG("index %d server %s proto %d", data->index,
					data->server, data->protocol);

	if (data->watch > 0) {
		g_source_remove(data->watch);
		data->watch = 0;
	}

	if (data->timeout > 0) {
		g_source_remove(data->timeout);
		data->timeout = 0;
	}

	if (data->channel) {
		g_io_channel_shutdown(data->channel, TRUE, NULL);
		g_io_channel_unref(data->channel);
		data->channel = NULL;
	}

	g_free(data->incoming_reply);
	data->incoming_reply = NULL;
}

static void destroy_server(struct dns_server_data *server)
{
	DBG("index %d server %s sock %d", server->index, server->server,
			server->channel ?
			g_io_channel_unix_get_fd(server->channel): -1);

	server_list = g_slist_remove(server_list, server);
	server_destroy_socket(server);

	if (server->protocol == IPPROTO_UDP && server->enabled)
		DBG("Removing DNS server %s", server->server);

	g_free(server->server);
	g_list_free_full(server->domains, g_free);
	g_free(server->server_addr);

	if (callbacks && callbacks->cache_remove_timer)
		callbacks->cache_remove_timer();

	g_free(server);
}

static gboolean udp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	unsigned char buf[4096];
	int sk, res;
	ssize_t len;
	struct dns_server_data *data = user_data;
	struct dns_request_data *req;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP server %s", data->server);
		server_destroy_socket(data);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(channel);
	len = recv(sk, buf, sizeof(buf), 0);

	if (len <= 0)
		return TRUE;

	req = lookup_request(buf, len, IPPROTO_UDP);

	if (!req)
		/* invalid / corrupt request */
		return TRUE;

	res = forward_dns_reply((char*)buf, len, IPPROTO_UDP, data, req);

	/* on success or no further responses are expected, destroy the req */
	if (res == 0 || req->numresp >= req->numserv)
		destroy_request_data(req);

	return TRUE;
}

static gboolean tcp_server_event(GIOChannel *channel, GIOCondition condition,
							gpointer user_data)
{
	struct dns_request_data *req;
	struct dns_server_data *server = user_data;
	int sk = g_io_channel_unix_get_fd(channel);
	if (sk == 0)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		GSList *list;
hangup:
		DBG("TCP server channel closed, sk %d", sk);

		/*
		 * Discard any partial response which is buffered; better
		 * to get a proper response from a working server.
		 */
		g_free(server->incoming_reply);
		server->incoming_reply = NULL;

		list = request_list;
		while (list) {
			struct domain_hdr *hdr;
			req = list->data;
			list = list->next;

			if (req->protocol == IPPROTO_UDP)
				continue;
			else if (!req->request)
				continue;

			/*
			 * If we're not waiting for any further response
			 * from another name server, then we send an error
			 * response to the client.
			 */
			if (req->numserv && --(req->numserv))
				continue;

			hdr = (void *)(req->request +
						DNS_HEADER_TCP_EXTRA_BYTES);
			hdr->id = req->srcid;
			send_response(req->client_sk, req->request,
				req->request_len, NULL, 0, IPPROTO_TCP);

			request_list = g_slist_remove(request_list, req);
		}

		destroy_server(server);

		return FALSE;
	}

	if ((condition & G_IO_OUT) && !server->connected) {
		bool no_request_sent = true;
		struct dns_server_data *udp_server = find_server(
				server->index, server->server,
				IPPROTO_UDP);
		if (udp_server) {
			for (GList *domains = udp_server->domains; domains;
						domains = domains->next) {
				const char *dom = domains->data;

				DBG("Adding domain %s to %s",
						dom, server->server);

				server->domains = g_list_append(server->domains,
								g_strdup(dom));
			}
		}

		/*
		 * Remove the G_IO_OUT flag from the watch, otherwise we end
		 * up in a busy loop, because the socket is constantly writable.
		 *
		 * There seems to be no better way in g_io to do that than
		 * re-adding the watch.
		 */
		g_source_remove(server->watch);
		server->watch = g_io_add_watch(server->channel,
			G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
			tcp_server_event, server);

		server->connected = true;
		server_list = g_slist_append(server_list, server);

		/* don't advance the list in the for loop, because we might
		 * need to delete elements while iterating through it */
		for (GSList *list = request_list; list; ) {
			int status;
			req = list->data;

			if (req->protocol == IPPROTO_UDP) {
				list = list->next;
				continue;
			}

			DBG("Sending req %s over TCP", (char *)req->name);

			status = ns_resolv(server, req,
						req->request, req->name);
			if (status > 0) {
				/*
				 * A cached result was sent,
				 * so the request can be released
				 */
				list = list->next;
				request_list = g_slist_remove(request_list,
									req);
				destroy_request_data(req);
				continue;
			} else if (status < 0) {
				list = list->next;
				continue;
			}

			no_request_sent = false;

			if (req->timeout > 0)
				g_source_remove(req->timeout);

			req->timeout = g_timeout_add_seconds(30,
						request_timeout, req);
			list = list->next;
		}

		if (no_request_sent) {
			destroy_server(server);
			return FALSE;
		}

	} else if (condition & G_IO_IN) {
		struct dns_partial_reply *reply = server->incoming_reply;
		int bytes_recv;
		int res;

		if (!reply) {
			uint16_t reply_len;
			size_t bytes_len;

			bytes_recv = recv(sk, &reply_len, sizeof(reply_len),
								MSG_PEEK);
			if (!bytes_recv) {
				goto hangup;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				goto hangup;
			}

			bytes_len = bytes_recv;
			if (bytes_len < sizeof(reply_len))
				return TRUE;

			/* the header contains the length of the message
			 * excluding the two length bytes */
			reply_len = ntohs(reply_len) +
						DNS_HEADER_TCP_EXTRA_BYTES;

			DBG("TCP reply %d bytes from %d", reply_len, sk);

			reply = g_try_malloc(sizeof(*reply) + reply_len + 2);
			if (!reply)
				return TRUE;

			reply->len = reply_len;
			/* we only peeked the two length bytes, so we have to
			   receive the complete message below proper. */
			reply->received = 0;

			server->incoming_reply = reply;
		}

		while (reply->received < reply->len) {
			bytes_recv = recv(sk, reply->buf + reply->received,
					reply->len - reply->received, 0);
			if (!bytes_recv) {
				connman_error("DNS proxy TCP disconnect");
				break;
			} else if (bytes_recv < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					return TRUE;

				connman_error("DNS proxy error %s",
						strerror(errno));
				break;
			}
			reply->received += bytes_recv;
		}

		req = lookup_request(reply->buf, reply->received, IPPROTO_TCP);

		if (!req)
			/* invalid / corrupt request */
			return TRUE;

		res = forward_dns_reply((char*)reply->buf, reply->received,
						IPPROTO_TCP, server, req);

		g_free(reply);
		server->incoming_reply = NULL;

		/* on success or if no further responses are expected close
		 * connection */
		if (res == 0 || req->numresp >= req->numserv) {
			destroy_request_data(req);
			destroy_server(server);
			return FALSE;
		}

		/*
		 * keep the TCP connection open, there are more
		 * requests to be answered
		 */
		return TRUE;
	}

	return TRUE;
}

static gboolean tcp_idle_timeout(gpointer user_data)
{
	struct dns_server_data *server = user_data;

	DBG("");

	if (!server)
		return FALSE;

	destroy_server(server);

	return FALSE;
}

static int server_create_socket(struct dns_server_data *data)
{
	int err;
	char *interface;
	int sk = socket(data->server_addr->sa_family,
		data->protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM,
		data->protocol);

	DBG("index %d server %s proto %d", data->index,
					data->server, data->protocol);

	if (sk < 0) {
		err = errno;
		connman_error("Failed to create server %s socket",
							data->server);
		server_destroy_socket(data);
		return -err;
	}

	DBG("sk %d", sk);

	interface = connman_inet_ifname(data->index);
	if (interface) {
		if (setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					interface,
					strlen(interface) + 1) < 0) {
			err = errno;
			connman_error("Failed to bind server %s "
						"to interface %s",
						data->server, interface);
			close(sk);
			server_destroy_socket(data);
			g_free(interface);
			return -err;
		}
		g_free(interface);
	}

	data->channel = g_io_channel_unix_new(sk);
	if (!data->channel) {
		connman_error("Failed to create server %s channel",
							data->server);
		close(sk);
		server_destroy_socket(data);
		return -ENOMEM;
	}

	g_io_channel_set_close_on_unref(data->channel, TRUE);

	if (data->protocol == IPPROTO_TCP) {
		g_io_channel_set_flags(data->channel, G_IO_FLAG_NONBLOCK, NULL);
		data->watch = g_io_add_watch(data->channel,
			G_IO_OUT | G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR,
						tcp_server_event, data);
		data->timeout = g_timeout_add_seconds(30, tcp_idle_timeout,
								data);
	} else
		data->watch = g_io_add_watch(data->channel,
			G_IO_IN | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
						udp_server_event, data);

	if (connect(sk, data->server_addr, data->server_addr_len) < 0) {
		err = errno;

		if ((data->protocol == IPPROTO_TCP && errno != EINPROGRESS) ||
				data->protocol == IPPROTO_UDP) {

			connman_error("Failed to connect to server %s",
								data->server);
			server_destroy_socket(data);
			return -err;
		}
	}

	if (callbacks && callbacks->create_cache)
		callbacks->create_cache();

	return 0;
}

static void enable_fallback(bool enable)
{
	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (data->index != -1)
			continue;

		if (enable)
			DBG("Enabling fallback DNS server %s", data->server);
		else
			DBG("Disabling fallback DNS server %s", data->server);

		data->enabled = enable;
	}
}

static unsigned int get_enabled_server_number(void)
{
	GSList *list;
	unsigned int result = 0;

	for (list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (data->index != -1 && data->enabled == true)
			result++;
	}
	return result;
}

static struct dns_server_data *create_server(int index,
					const char *domain, const char *server,
					int protocol)
{
	struct dns_server_data *data = g_try_new0(struct dns_server_data, 1);
	struct addrinfo hints, *rp;
	int ret;

	DBG("index %d server %s", index, server);

	if (!data) {
		connman_error("Failed to allocate server %s data", server);
		return NULL;
	}

	data->index = index;
	if (domain)
		data->domains = g_list_append(data->domains, g_strdup(domain));
	data->server = g_strdup(server);
	data->protocol = protocol;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socket_type(protocol, 0);
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV | AI_NUMERICHOST;

	ret = getaddrinfo(data->server, "53", &hints, &rp);
	if (ret) {
		connman_error("Failed to parse server %s address: %s\n",
			      data->server, gai_strerror(ret));
		destroy_server(data);
		return NULL;
	}

	/* Do not blindly copy this code elsewhere; it doesn't loop over the
	   results using ->ai_next as it should. That's OK in *this* case
	   because it was a numeric lookup; we *know* there's only one. */

	data->server_addr_len = rp->ai_addrlen;

	switch (rp->ai_family) {
	case AF_INET:
		data->server_addr = (struct sockaddr *)
					g_try_new0(struct sockaddr_in, 1);
		break;
	case AF_INET6:
		data->server_addr = (struct sockaddr *)
					g_try_new0(struct sockaddr_in6, 1);
		break;
	default:
		connman_error("Wrong address family %d", rp->ai_family);
		break;
	}
	if (!data->server_addr) {
		freeaddrinfo(rp);
		destroy_server(data);
		return NULL;
	}
	memcpy(data->server_addr, rp->ai_addr, rp->ai_addrlen);
	freeaddrinfo(rp);

	if (server_create_socket(data) != 0) {
		destroy_server(data);
		return NULL;
	}

	if (protocol == IPPROTO_UDP) {
		if (__connman_service_index_is_default(data->index) ||
				__connman_service_index_is_split_routing(
								data->index)) {
			data->enabled = true;
			DBG("Adding DNS server %s", data->server);

			enable_fallback(false);
		} else if (data->index == -1 &&
					get_enabled_server_number() == 0) {
			data->enabled = true;
			DBG("Adding fallback DNS server %s", data->server);
		}

		server_list = g_slist_append(server_list, data);
	}

	return data;
}

static bool resolv(struct dns_request_data *req,
				gpointer request, gpointer name)
{
	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (data->protocol == IPPROTO_TCP) {
			DBG("server %s ignored proto TCP", data->server);
			continue;
		}

		DBG("server %s enabled %d", data->server, data->enabled);

		if (!data->enabled)
			continue;

		if (!data->channel && data->protocol == IPPROTO_UDP) {
			if (server_create_socket(data) < 0) {
				DBG("socket creation failed while resolving");
				continue;
			}
		}

		if (ns_resolv(data, req, request, name) > 0)
			return true;
	}

	return false;
}

/*
 * Parses the given request buffer. `buf´ is expected to be the start of the
 * domain_hdr structure i.e. the TCP length header is not handled by this
 * function.
 * Returns the ascii string dot representation of the query in `name´, which
 * must be able to hold `size´ bytes.
 *
 * Returns < 0 on error (errno) or zero on success.
 */
static int parse_request(unsigned char *buf, size_t len,
					char *name, size_t size)
{
	static const unsigned char OPT_EDNS0_TYPE[2] = { 0x00, 0x29 };
	struct domain_hdr *hdr = (void *) buf;
	uint16_t qdcount, ancount, nscount, arcount;
	unsigned char *ptr = buf + DNS_HEADER_SIZE;
	size_t remain = len - DNS_HEADER_SIZE;
	size_t used = 0;

	if (len < DNS_HEADER_SIZE + DNS_QTYPE_QCLASS_SIZE) {
		DBG("Dropped DNS request with short length %zd", len);
		return -EINVAL;
	}

	if (!name || !size)
		return -EINVAL;

	qdcount = ntohs(hdr->qdcount);
	ancount = ntohs(hdr->ancount);
	nscount = ntohs(hdr->nscount);
	arcount = ntohs(hdr->arcount);

	if (hdr->qr || qdcount != 1 || ancount || nscount) {
		DBG("Dropped DNS request with bad flags/counts qr %d "
			"with len %zd qdcount %d ancount %d nscount %d",
			hdr->qr, len, qdcount, ancount, nscount);

		return -EINVAL;
	}

	DBG("id 0x%04x qr %d opcode %d qdcount %d arcount %d",
					hdr->id, hdr->qr, hdr->opcode,
							qdcount, arcount);

	name[0] = '\0';

	/* parse DNS query string into `name' out parameter */
	while (remain > 0) {
		uint8_t label_len = *ptr;

		if (label_len == 0x00) {
			struct qtype_qclass *q =
					(struct qtype_qclass *)(ptr + 1);
			uint16_t class;

			if (remain < sizeof(*q)) {
				DBG("Dropped malformed DNS query");
				return -EINVAL;
			}

			class = ntohs(q->qclass);
			if (class != DNS_CLASS_IN && class != DNS_CLASS_ANY) {
				DBG("Dropped non-IN DNS class %d", class);
				return -EINVAL;
			}

			ptr += sizeof(*q) + 1;
			remain -= (sizeof(*q) + 1);
			break;
		}

		if (used + label_len + 1 > size)
			return -ENOBUFS;

		strncat(name, (char *) (ptr + 1), label_len);
		strcat(name, ".");

		used += label_len + 1;
		ptr += label_len + 1;
		remain -= label_len + 1;
	}

	if (arcount && remain >= DNS_RR_SIZE + 1 && !ptr[0] &&
		ptr[1] == OPT_EDNS0_TYPE[0] && ptr[2] == OPT_EDNS0_TYPE[1]) {
		struct domain_rr *edns0 = (struct domain_rr *)(ptr + 1);

		DBG("EDNS0 buffer size %u", ntohs(edns0->class));
	} else if (!arcount && remain) {
		DBG("DNS request with %zd garbage bytes", remain);
	}

	DBG("query %s", name);

	return 0;
}

static void client_reset(struct tcp_partial_client_data *client)
{
	if (!client)
		return;

	if (client->channel) {
		DBG("client %d closing",
			g_io_channel_unix_get_fd(client->channel));

		g_io_channel_unref(client->channel);
		client->channel = NULL;
	}

	if (client->watch > 0) {
		g_source_remove(client->watch);
		client->watch = 0;
	}

	if (client->timeout > 0) {
		g_source_remove(client->timeout);
		client->timeout = 0;
	}

	g_free(client->buf);
	client->buf = NULL;

	client->buf_end = 0;
}

static size_t get_msg_len(const unsigned char *buf)
{
	return buf[0]<<8 | buf[1];
}

static bool read_tcp_data(struct tcp_partial_client_data *client,
				void *client_addr, socklen_t client_addr_len,
				int read_len)
{
	char query[TCP_MAX_BUF_LEN];
	struct dns_request_data *req;
	struct domain_hdr *hdr;
	int client_sk = g_io_channel_unix_get_fd(client->channel);
	int err;
	size_t msg_len;
	bool waiting_for_connect = false;
	uint16_t qtype = 0;

	if (read_len == 0) {
		DBG("client %d closed, pending %d bytes",
			client_sk, client->buf_end);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return false;
	}

	DBG("client %d received %d bytes", client_sk, read_len);

	client->buf_end += read_len;

	/* we need at least the message length header */
	if (client->buf_end < DNS_HEADER_TCP_EXTRA_BYTES)
		return true;

	msg_len = get_msg_len(client->buf);
	if (msg_len > TCP_MAX_BUF_LEN) {
		DBG("client %d sent too much data %zd", client_sk, msg_len);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return false;
	}

read_another:
	DBG("client %d msg len %zd end %d past end %zd", client_sk, msg_len,
		client->buf_end, client->buf_end - (msg_len + 2));

	if (client->buf_end < (msg_len + 2)) {
		DBG("client %d still missing %zd bytes",
			client_sk,
			msg_len + 2 - client->buf_end);
		return true;
	}

	DBG("client %d all data %zd received", client_sk, msg_len);

	err = parse_request(client->buf + DNS_HEADER_TCP_EXTRA_BYTES,
			msg_len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(client_sk, client->buf,
			msg_len + DNS_HEADER_TCP_EXTRA_BYTES,
			NULL, 0, IPPROTO_TCP);
		return true;
	}

	req = g_try_new0(struct dns_request_data, 1);
	if (!req)
		return true;

	memcpy(&req->sa, client_addr, client_addr_len);
	req->sa_len = client_addr_len;
	req->client_sk = client_sk;
	req->protocol = IPPROTO_TCP;
	req->family = client->family;

	hdr = (void*)(client->buf + DNS_HEADER_TCP_EXTRA_BYTES);

	memcpy(&req->srcid, &hdr->id, sizeof(req->srcid));
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = msg_len + DNS_HEADER_TCP_EXTRA_BYTES;

	/* replace ID the request for forwarding */
	memcpy(&hdr->id, &req->dstid, sizeof(hdr->id));

	req->numserv = 0;
	req->ifdata = client->ifdata;
	req->append_domain = false;

	/*
	 * Check if the answer is found in the cache before
	 * creating sockets to the server.
	 */
	if (callbacks && callbacks->send_from_cache) {
		if (callbacks->send_from_cache(req, client->buf, qtype,
						client_sk, IPPROTO_TCP) > 0) {
			DBG("cache hit %s type %s", query,
					qtype == DNS_TYPE_A ? "A" : "AAAA");
			return true;
		}
	}

	for (GSList *list = server_list; list; list = list->next) {
		struct dns_server_data *data = list->data;

		if (data->protocol != IPPROTO_UDP || !data->enabled)
			continue;

		if (!create_server(data->index, NULL, data->server,
					IPPROTO_TCP))
			continue;

		waiting_for_connect = true;
	}

	if (!waiting_for_connect) {
		/* No server is waiting for connect */
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		return true;
	}

	/*
	 * The server is not connected yet.
	 * Copy the relevant buffers.
	 * The request will actually be sent once we're
	 * properly connected over TCP to the nameserver.
	 */
	req->request = g_try_malloc0(req->request_len);
	if (!req->request) {
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req);
		goto out;
	}
	memcpy(req->request, client->buf, req->request_len);

	req->name = g_try_malloc0(sizeof(query));
	if (!req->name) {
		send_response(client_sk, client->buf,
			req->request_len, NULL, 0, IPPROTO_TCP);
		g_free(req->request);
		g_free(req);
		goto out;
	}
	memcpy(req->name, query, sizeof(query));

	req->timeout = g_timeout_add_seconds(30, request_timeout, req);

	request_list = g_slist_append(request_list, req);

out:
	if (client->buf_end > (msg_len + DNS_HEADER_TCP_EXTRA_BYTES)) {
		DBG("client %d buf %p -> %p end %d len %d new %zd",
			client_sk,
			client->buf + msg_len + 2,
			client->buf, client->buf_end,
			TCP_MAX_BUF_LEN - client->buf_end,
			client->buf_end - (msg_len + 2));
		memmove(client->buf, client->buf + msg_len + 2,
			TCP_MAX_BUF_LEN - client->buf_end);
		client->buf_end = client->buf_end - (msg_len + 2);

		/*
		 * If we have a full message waiting, just read it
		 * immediately.
		 */
		msg_len = get_msg_len(client->buf);
		if ((msg_len + 2) == client->buf_end) {
			DBG("client %d reading another %zd bytes", client_sk,
								msg_len + 2);
			goto read_another;
		}
	} else {
		DBG("client %d clearing reading buffer", client_sk);

		client->buf_end = 0;
		memset(client->buf, 0, TCP_MAX_BUF_LEN);

		/*
		 * We received all the packets from client so we must also
		 * remove the timeout handler here otherwise we might get
		 * timeout while waiting the results from server.
		 */
		g_source_remove(client->timeout);
		client->timeout = 0;
	}

	return true;
}

static gboolean tcp_client_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct tcp_partial_client_data *client = user_data;
	int client_sk = g_io_channel_unix_get_fd(channel);
	int len;
	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));

		connman_error("Error with TCP client %d channel", client_sk);
		return FALSE;
	}

	switch (client->family) {
	case AF_INET:
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
		break;
	case AF_INET6:
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
		break;
	default:
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		connman_error("client %p corrupted", client);
		return FALSE;
	}

	len = recvfrom(client_sk, client->buf + client->buf_end,
			TCP_MAX_BUF_LEN - client->buf_end - 1, 0,
			client_addr, client_addr_len);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return TRUE;

		DBG("client %d cannot read errno %d/%s", client_sk, -errno,
			strerror(errno));
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return FALSE;
	}

	client->buf[client->buf_end + len] = '\0';

	return read_tcp_data(client, client_addr, *client_addr_len, len);
}

static gboolean client_timeout(gpointer user_data)
{
	struct tcp_partial_client_data *client = user_data;
	int sock = g_io_channel_unix_get_fd(client->channel);

	DBG("client %d timeout pending %d bytes", sock, client->buf_end);

	g_hash_table_remove(partial_tcp_req_table, GINT_TO_POINTER(sock));

	return FALSE;
}

static bool tcp_listener_event(GIOChannel *channel, GIOCondition condition,
				struct dns_listener_data *ifdata, int family,
				guint *listener_watch)
{
	int sk = -1, client_sk = -1;
	int recv_len;
	size_t msg_len;
	fd_set readfds;
	struct timeval tv = {.tv_sec = 0, .tv_usec = 0};

	struct tcp_partial_client_data *client;
	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	DBG("condition 0x%02x channel %p ifdata %p family %d",
		condition, channel, ifdata, family);

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		if (*listener_watch > 0)
			g_source_remove(*listener_watch);
		*listener_watch = 0;

		connman_error("Error with TCP listener channel");

		return false;
	}

	sk = g_io_channel_unix_get_fd(channel);

	if (family == AF_INET) {
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
	} else {
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
	}

	FD_ZERO(&readfds);
	FD_SET(sk, &readfds);

	/* TODO: check select return code */
	select(sk + 1, &readfds, NULL, NULL, &tv);
	if (!FD_ISSET(sk, &readfds)) {
		DBG("No data to read from master %d, waiting.", sk);
		return true;
	}

	client_sk = accept(sk, client_addr, client_addr_len);
	if (client_sk < 0) {
		connman_error("Accept failure on TCP listener");
		*listener_watch = 0;
		return false;
	}
	DBG("client %d accepted", client_sk);

	fcntl(client_sk, F_SETFL, O_NONBLOCK);

	client = g_hash_table_lookup(partial_tcp_req_table,
						GINT_TO_POINTER(client_sk));
	if (!client) {
		client = g_try_new0(struct tcp_partial_client_data, 1);
		if (!client) {
			close(client_sk);
			return false;
		}

		g_hash_table_insert(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk),
					client);

		client->channel = g_io_channel_unix_new(client_sk);
		g_io_channel_set_close_on_unref(client->channel, TRUE);

		client->watch = g_io_add_watch(client->channel,
						G_IO_IN, tcp_client_event,
						(gpointer)client);

		client->ifdata = ifdata;

		DBG("client %d created %p", client_sk, client);
	} else {
		DBG("client %d already exists %p", client_sk, client);
	}

	if (!client->buf) {
		client->buf = g_try_malloc(TCP_MAX_BUF_LEN);
		if (!client->buf)
			return false;
	}
	memset(client->buf, 0, TCP_MAX_BUF_LEN);
	client->buf_end = 0;
	client->family = family;

	if (client->timeout == 0)
		client->timeout = g_timeout_add_seconds(2, client_timeout,
							client);

	/*
	 * Check how much data there is. If all is there, then we can
	 * proceed normally, otherwise read the bits until everything
	 * is received or timeout occurs.
	 */
	recv_len = recv(client_sk, client->buf, TCP_MAX_BUF_LEN, 0);
	if (recv_len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			DBG("client %d no data to read, waiting", client_sk);
			return true;
		}

		DBG("client %d cannot read errno %d/%s", client_sk, -errno,
			strerror(errno));
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return true;
	}

	if (recv_len < DNS_HEADER_TCP_EXTRA_BYTES) {
		DBG("client %d not enough data to read, waiting", client_sk);
		client->buf_end += recv_len;
		return true;
	}

	msg_len = get_msg_len(client->buf);
	if (msg_len > TCP_MAX_BUF_LEN) {
		DBG("client %d invalid message length %zd ignoring packet",
			client_sk, msg_len);
		g_hash_table_remove(partial_tcp_req_table,
					GINT_TO_POINTER(client_sk));
		return true;
	}

	/*
	 * The packet length bytes do not contain the total message length,
	 * that is the reason to -2 below.
	 */
	if (msg_len != (size_t)(recv_len - DNS_HEADER_TCP_EXTRA_BYTES)) {
		DBG("client %d sent %d bytes but expecting %zd pending %zd",
					client_sk, recv_len, msg_len + 2,
					msg_len + 2 - recv_len);

		client->buf_end += recv_len;
		return true;
	}

	return read_tcp_data(client, client_addr, *client_addr_len, recv_len);
}

static gboolean tcp4_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct dns_listener_data *ifdata = user_data;

	return tcp_listener_event(channel, condition, ifdata, AF_INET,
				&ifdata->tcp4_listener_watch);
}

static gboolean tcp6_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct dns_listener_data *ifdata = user_data;

	return tcp_listener_event(channel, condition, user_data, AF_INET6,
				&ifdata->tcp6_listener_watch);
}

static bool udp_listener_event(GIOChannel *channel, GIOCondition condition,
				struct dns_listener_data *ifdata, int family,
				guint *listener_watch)
{
	unsigned char buf[769];
	char query[512];
	struct dns_request_data *req = NULL;
	struct domain_hdr *hdr = NULL;
	int sk = -1, err, len;

	struct sockaddr_in6 client_addr6;
	socklen_t client_addr6_len = sizeof(client_addr6);
	struct sockaddr_in client_addr4;
	socklen_t client_addr4_len = sizeof(client_addr4);
	void *client_addr;
	socklen_t *client_addr_len;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP)) {
		connman_error("Error with UDP listener channel");
		*listener_watch = 0;
		return false;
	}

	if (family == AF_INET) {
		client_addr = &client_addr4;
		client_addr_len = &client_addr4_len;
	} else {
		client_addr = &client_addr6;
		client_addr_len = &client_addr6_len;
	}

	memset(client_addr, 0, *client_addr_len);
	sk = g_io_channel_unix_get_fd(channel);
	len = recvfrom(sk, buf, sizeof(buf) - 1, 0, client_addr,
							client_addr_len);
	if (len < 2)
		return true;

	buf[len] = '\0';

	DBG("Received %d bytes (id 0x%04x)", len, buf[0] | buf[1] << 8);

	err = parse_request(buf, len, query, sizeof(query));
	if (err < 0 || (g_slist_length(server_list) == 0)) {
		send_response(sk, buf, len, client_addr,
				*client_addr_len, IPPROTO_UDP);
		return true;
	}

	req = g_try_new0(struct dns_request_data, 1);
	if (!req)
		return true;

	memcpy(&req->sa, client_addr, *client_addr_len);
	req->sa_len = *client_addr_len;
	req->client_sk = 0;
	req->protocol = IPPROTO_UDP;
	req->family = family;

	hdr = (void*)buf;

	req->srcid = hdr->id;
	req->dstid = get_id();
	req->altid = get_id();
	req->request_len = len;

	hdr->id = req->dstid;

	req->numserv = 0;
	req->ifdata = ifdata;
	req->append_domain = false;

	if (resolv(req, buf, query)) {
		/* a cached result was sent, so the request can be released */
	        g_free(req);
		return true;
	}

	req->name = g_strdup(query);
	req->request = g_malloc(len);
	memcpy(req->request, buf, len);
	req->timeout = g_timeout_add_seconds(5, request_timeout, req);
	request_list = g_slist_append(request_list, req);

	return true;
}

static gboolean udp4_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct dns_listener_data *ifdata = user_data;

	return udp_listener_event(channel, condition, ifdata, AF_INET,
				&ifdata->udp4_listener_watch);
}

static gboolean udp6_listener_event(GIOChannel *channel, GIOCondition condition,
				gpointer user_data)
{
	struct dns_listener_data *ifdata = user_data;

	return udp_listener_event(channel, condition, user_data, AF_INET6,
				&ifdata->udp6_listener_watch);
}

static GIOChannel *get_listener(int family, int protocol, int index)
{
	GIOChannel *channel = NULL;
	union {
		struct sockaddr sa;
		struct sockaddr_in6 sin6;
		struct sockaddr_in sin;
	} s;
	socklen_t slen;
	const char *proto = protocol_label(protocol);
	const int type = socket_type(protocol, SOCK_CLOEXEC);
	char *interface;
	int sk = socket(family, type, protocol);

	DBG("family %d protocol %d index %d", family, protocol, index);

	if (sk < 0) {
		if (family == AF_INET6 && errno == EAFNOSUPPORT) {
			connman_error("No IPv6 support");
		} else {
			connman_error("Failed to create %s listener socket",
									proto);
		}
		return NULL;
	}

	interface = connman_inet_ifname(index);
	if (!interface || setsockopt(sk, SOL_SOCKET, SO_BINDTODEVICE,
					interface,
					strlen(interface) + 1) < 0) {
		connman_error("Failed to bind %s listener interface "
			"for %s (%d/%s)",
			proto, family == AF_INET ? "IPv4" : "IPv6",
			-errno, strerror(errno));
		close(sk);
		g_free(interface);
		return NULL;
	}
	g_free(interface);

	if (family == AF_INET6) {
		memset(&s.sin6, 0, sizeof(s.sin6));
		s.sin6.sin6_family = AF_INET6;
		s.sin6.sin6_port = htons(dns_listen_port);
		slen = sizeof(s.sin6);

		if (__connman_inet_get_interface_address(index,
						AF_INET6,
						&s.sin6.sin6_addr) < 0) {
			/* So we could not find suitable IPv6 address for
			 * the interface. This could happen if we have
			 * disabled IPv6 for the interface.
			 */
			close(sk);
			return NULL;
		}

	} else if (family == AF_INET) {
		memset(&s.sin, 0, sizeof(s.sin));
		s.sin.sin_family = AF_INET;
		s.sin.sin_port = htons(dns_listen_port);
		slen = sizeof(s.sin);

		if (__connman_inet_get_interface_address(index,
						AF_INET,
						&s.sin.sin_addr) < 0) {
			close(sk);
			return NULL;
		}
	} else {
		close(sk);
		return NULL;
	}

	if (bind(sk, &s.sa, slen) < 0) {
		connman_error("Failed to bind %s listener socket", proto);
		close(sk);
		return NULL;
	}

	if (protocol == IPPROTO_TCP) {
		if (listen(sk, 10) < 0) {
			connman_error("Failed to listen on TCP socket %d/%s",
				-errno, strerror(errno));
			close(sk);
			return NULL;
		}

		if (fcntl(sk, F_SETFL, O_NONBLOCK) < 0) {
			connman_error("Failed to set TCP listener socket to "
						"non-blocking %d/%s",
						-errno, strerror(errno));
			close(sk);
			return NULL;
		}
	}

	channel = g_io_channel_unix_new(sk);
	if (!channel) {
		connman_error("Failed to create %s listener channel", proto);
		close(sk);
		return NULL;
	}

	g_io_channel_set_close_on_unref(channel, TRUE);

	return channel;
}

#define UDP_IPv4_FAILED 0x01
#define TCP_IPv4_FAILED 0x02
#define UDP_IPv6_FAILED 0x04
#define TCP_IPv6_FAILED 0x08
#define UDP_FAILED (UDP_IPv4_FAILED | UDP_IPv6_FAILED)
#define TCP_FAILED (TCP_IPv4_FAILED | TCP_IPv6_FAILED)
#define IPv6_FAILED (UDP_IPv6_FAILED | TCP_IPv6_FAILED)
#define IPv4_FAILED (UDP_IPv4_FAILED | TCP_IPv4_FAILED)

static int create_dns_listener(int protocol, struct dns_listener_data *ifdata)
{
	int ret = 0;

	if (protocol == IPPROTO_TCP) {
		ifdata->tcp4_listener_channel = get_listener(AF_INET, protocol,
							ifdata->index);
		if (ifdata->tcp4_listener_channel)
			ifdata->tcp4_listener_watch =
				g_io_add_watch(ifdata->tcp4_listener_channel,
					G_IO_IN, tcp4_listener_event,
					(gpointer)ifdata);
		else
			ret |= TCP_IPv4_FAILED;

		ifdata->tcp6_listener_channel = get_listener(AF_INET6, protocol,
							ifdata->index);
		if (ifdata->tcp6_listener_channel)
			ifdata->tcp6_listener_watch =
				g_io_add_watch(ifdata->tcp6_listener_channel,
					G_IO_IN, tcp6_listener_event,
					(gpointer)ifdata);
		else
			ret |= TCP_IPv6_FAILED;
	} else {
		ifdata->udp4_listener_channel = get_listener(AF_INET, protocol,
							ifdata->index);
		if (ifdata->udp4_listener_channel)
			ifdata->udp4_listener_watch =
				g_io_add_watch(ifdata->udp4_listener_channel,
					G_IO_IN, udp4_listener_event,
					(gpointer)ifdata);
		else
			ret |= UDP_IPv4_FAILED;

		ifdata->udp6_listener_channel = get_listener(AF_INET6, protocol,
							ifdata->index);
		if (ifdata->udp6_listener_channel)
			ifdata->udp6_listener_watch =
				g_io_add_watch(ifdata->udp6_listener_channel,
					G_IO_IN, udp6_listener_event,
					(gpointer)ifdata);
		else
			ret |= UDP_IPv6_FAILED;
	}

	return ret;
}

static void destroy_udp_listener(struct dns_listener_data *ifdata)
{
	DBG("index %d", ifdata->index);

	if (ifdata->udp4_listener_watch > 0)
		g_source_remove(ifdata->udp4_listener_watch);

	if (ifdata->udp6_listener_watch > 0)
		g_source_remove(ifdata->udp6_listener_watch);

	if (ifdata->udp4_listener_channel)
		g_io_channel_unref(ifdata->udp4_listener_channel);
	if (ifdata->udp6_listener_channel)
		g_io_channel_unref(ifdata->udp6_listener_channel);
}

static void destroy_tcp_listener(struct dns_listener_data *ifdata)
{
	DBG("index %d", ifdata->index);

	if (ifdata->tcp4_listener_watch > 0)
		g_source_remove(ifdata->tcp4_listener_watch);
	if (ifdata->tcp6_listener_watch > 0)
		g_source_remove(ifdata->tcp6_listener_watch);

	if (ifdata->tcp4_listener_channel)
		g_io_channel_unref(ifdata->tcp4_listener_channel);
	if (ifdata->tcp6_listener_channel)
		g_io_channel_unref(ifdata->tcp6_listener_channel);
}

static int create_listener(struct dns_listener_data *ifdata,
						enum dns_ipproto ipproto)
{
	int index;
	int err = 0;

	if (ipproto == DNS_IPPROTO_ALL || ipproto == DNS_IPPROTO_UDP) {
		err = create_dns_listener(IPPROTO_UDP, ifdata);
		if ((err & UDP_FAILED) == UDP_FAILED)
			return -EIO;
	}

	if (ipproto == DNS_IPPROTO_ALL || ipproto == DNS_IPPROTO_TCP) {
		err |= create_dns_listener(IPPROTO_TCP, ifdata);
		if ((err & TCP_FAILED) == TCP_FAILED) {
			destroy_udp_listener(ifdata);
			return -EIO;
		}
	}

	index = connman_inet_ifindex("lo");
	if (ifdata->index == index && !ifdata->lo_exclude) {
#ifdef SYSTEMD_RESOLVED_DNS_BACKEND
		if (((err & IPv6_FAILED) != IPv6_FAILED) ||
					((err & IPv4_FAILED) != IPv4_FAILED))
			__connman_resolvfile_append(index, NULL,
								DNS_BACKEND_V4);
#else
		if ((err & IPv6_FAILED) != IPv6_FAILED)
			__connman_resolvfile_append(index, NULL,
								DNS_BACKEND_V6);

		if ((err & IPv4_FAILED) != IPv4_FAILED)
			__connman_resolvfile_append(index, NULL,
								DNS_BACKEND_V4);
#endif
	}

	return 0;
}

static void destroy_listener(struct dns_listener_data *ifdata)
{
	int index = connman_inet_ifindex("lo");

	if (ifdata->index == index && !ifdata->lo_exclude) {

		__connman_resolvfile_remove(index, NULL, DNS_BACKEND_V4);

// With internal DNS this is defined, with systemd-resolved it is not.
#ifndef SYSTEMD_RESOLVED_DNS_BACKEND
		__connman_resolvfile_remove(index, NULL, DNS_BACKEND_V6);
#endif
	}

	for (GSList *list = request_list; list; list = list->next) {
		struct dns_request_data *req = list->data;

		DBG("Dropping request (id 0x%04x -> 0x%04x)",
						req->srcid, req->dstid);
		destroy_request_data(req);
		list->data = NULL;
	}

	g_slist_free(request_list);
	request_list = NULL;

	destroy_tcp_listener(ifdata);
	destroy_udp_listener(ifdata);
}

static void remove_listener(gpointer key, gpointer value, gpointer user_data)
{
	int index = GPOINTER_TO_INT(key);
	struct dns_listener_data *ifdata = value;

	DBG("index %d", index);

	destroy_listener(ifdata);
}

static int lookup_listener_by_index(int index)
{
	if (index < 0)
		return -EINVAL;

	if (!listener_table)
		return -ENOENT;

	if (g_hash_table_lookup(listener_table, GINT_TO_POINTER(index)))
		return 0;

	return -ENODATA;
}

int dns_add_listener(int index, enum dns_ipproto ipproto, bool lo_exclude)
{
	struct dns_listener_data *ifdata;
	int err;

	err = lookup_listener_by_index(index);
	switch (err) {
	case -EINVAL:
		DBG("invalid index %d", index);
		/* fall-through */
	case -ENOENT:
		return err;
	case -ENODATA:
		break;
	case 0:
		return 0;
	}

	ifdata = g_try_new0(struct dns_listener_data, 1);
	if (!ifdata)
		return -ENOMEM;

	ifdata->index = index;
	ifdata->lo_exclude = lo_exclude;
	ifdata->udp4_listener_channel = NULL;
	ifdata->udp4_listener_watch = 0;
	ifdata->tcp4_listener_channel = NULL;
	ifdata->tcp4_listener_watch = 0;
	ifdata->udp6_listener_channel = NULL;
	ifdata->udp6_listener_watch = 0;
	ifdata->tcp6_listener_channel = NULL;
	ifdata->tcp6_listener_watch = 0;

	err = create_listener(ifdata, ipproto);
	if (err < 0) {
		connman_error("Couldn't create listener for index %d err %d",
				index, err);
		g_free(ifdata);
		return err;
	}

	g_hash_table_insert(listener_table, GINT_TO_POINTER(ifdata->index),
			ifdata);

	return 0;
}

void dns_remove_listener(int index)
{
	struct dns_listener_data *ifdata;

	if (!listener_table)
		return;

	ifdata = g_hash_table_lookup(listener_table, GINT_TO_POINTER(index));
	if (!ifdata)
		return;

	destroy_listener(ifdata);

	g_hash_table_remove(listener_table, GINT_TO_POINTER(index));
}

int dns_create_server(int index, const char *domain, const char *server,
								int protocol)
{
	struct dns_server_data *data;

	data = create_server(index, domain, server, protocol);
	if (!data)
		return -EINVAL;

	return 0;
}

int dns_enable_server(int index, const char *server, int protocol, bool enable)
{
	struct dns_server_data *data;

	data = find_server(index, server, protocol);
	if (!data)
		return -ENOENT;

	data->enabled = enable;

	return 0;
}

void dns_set_listen_port(unsigned int port)
{
	dns_listen_port = port;
}

static void free_partial_reqs(gpointer value)
{
	struct tcp_partial_client_data *data = value;

	client_reset(data);
	g_free(data);
}

int dns_init(struct dns_callbacks *cbs)
{
	DBG("");

	listener_table = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, g_free);
	if (!listener_table)
		return -ENOMEM;

	partial_tcp_req_table = g_hash_table_new_full(g_direct_hash,
							g_direct_equal,
							NULL,
							free_partial_reqs);

	callbacks = cbs;

	return 0;
}

void dns_cleanup(void)
{
	DBG("");

	g_hash_table_foreach(listener_table, remove_listener, NULL);
	g_hash_table_destroy(listener_table);
	g_hash_table_destroy(partial_tcp_req_table);
}
