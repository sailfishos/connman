/*
 *  ConnMan netfilter-conntrack dummy functions
 *
 *  Copyright (C) 2024  xxx
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <unistd.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct nfct_handle *nfct_open(uint8_t subsys_id, unsigned int subscriptions)
{
	return NULL;
}

int nfct_close(struct nfct_handle *cth)
{
	g_assert(cth);
	return 0;
}

struct nf_conntrack *nfct_new(void)
{
	return NULL;
}

void nfct_destroy(struct nf_conntrack *ct)
{
	g_assert(ct);
	return;
}

int nfct_callback_register(struct nfct_handle *h,
				enum nf_conntrack_msg_type type,
				int (*cb)(enum nf_conntrack_msg_type type,
						struct nf_conntrack *ct,
						void *data),
				void *data)
{
	g_assert(h);
	g_assert(cb);

	return 0;
}

void nfct_callback_unregister(struct nfct_handle *h)
{
	g_assert(h);
}

void nfct_set_attr(struct nf_conntrack *ct,
				const enum nf_conntrack_attr type,
				const void *value)
{
	g_assert(ct);
	g_assert(value);
	return;
}

void nfct_set_attr_u8(struct nf_conntrack *ct,
				const enum nf_conntrack_attr type,
				uint8_t value)
{
	g_assert(ct);
	return;
}

void nfct_set_attr_u16(struct nf_conntrack *ct,
				const enum nf_conntrack_attr type,
				uint16_t value)
{
	g_assert(ct);
	return;
}

void nfct_set_attr_u32(struct nf_conntrack *ct,
				const enum nf_conntrack_attr type,
				uint32_t value)
{
	g_assert(ct);
	return;
}



const void *nfct_get_attr(const struct nf_conntrack *ct,
					const enum nf_conntrack_attr type)
{
	g_assert(ct);
	return NULL;
}

uint8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
					 const enum nf_conntrack_attr type)
{
	g_assert(ct);
	return 0;
}

uint16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
					const enum nf_conntrack_attr type)
{
	g_assert(ct);
	return 0;
}

uint32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
					const enum nf_conntrack_attr type)
{
	g_assert(ct);
	return 0;
}

int nfct_query(struct nfct_handle *h, const enum nf_conntrack_query query,
					const void *data)
{
	g_assert(h);
	return 0;
}

