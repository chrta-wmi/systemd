/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <netinet/in.h>

#include "dns-answer.h"
#include "dns-rr.h"
#include "resolved-dns-scope.h"
#include "resolved-dns-zone.h"
#include "resolved-mdns.h"
#include "tests.h"
#include "time-util.h"

static DnsResourceRecord* a_rr(const char *name, uint32_t addr) {
        DnsResourceRecord *rr;

        rr = dns_resource_record_new_full(DNS_CLASS_IN, DNS_TYPE_A, name);
        ASSERT_NOT_NULL(rr);
        rr->ttl = MDNS_DEFAULT_TTL;
        rr->a.in_addr.s_addr = htobe32(addr);

        return rr;
}

TEST(mdns_zone_item_next_multicast_usec) {
        DnsZoneItem i = {};

        /* Never multicast before */
        ASSERT_EQ(mdns_zone_item_next_multicast_usec(&i, /* probe= */ false), 0u);
        ASSERT_EQ(mdns_zone_item_next_multicast_usec(&i, /* probe= */ true), 0u);

        /* Regular queries: at most once per second, probe queries: at most every 250 ms */
        i.last_multicast_usec = 10 * USEC_PER_SEC;
        ASSERT_EQ(mdns_zone_item_next_multicast_usec(&i, /* probe= */ false), 11 * USEC_PER_SEC);
        ASSERT_EQ(mdns_zone_item_next_multicast_usec(&i, /* probe= */ true), 10 * USEC_PER_SEC + 250 * USEC_PER_MSEC);
}

TEST(dns_zone_set_last_multicast) {
        _cleanup_(dns_resource_record_unrefp) DnsResourceRecord *rr1 = NULL, *rr1_copy = NULL, *rr2 = NULL, *foreign = NULL;
        _cleanup_(dns_answer_unrefp) DnsAnswer *answer = NULL;
        DnsScope scope = { .protocol = DNS_PROTOCOL_MDNS };
        DnsZone zone = {};
        DnsZoneItem *i;

        rr1 = a_rr("host.local", 0xc0000201);      /* 192.0.2.1 */
        rr1_copy = a_rr("host.local", 0xc0000201);
        rr2 = a_rr("host.local", 0xc0000202);      /* 192.0.2.2 */
        foreign = a_rr("other.local", 0xc0000203); /* 192.0.2.3 */

        ASSERT_OK(dns_zone_put(&zone, &scope, rr1, /* probe= */ false));
        ASSERT_OK(dns_zone_put(&zone, &scope, rr2, /* probe= */ false));

        /* An equal RR (not the same object) marks the zone item, RRs not in the zone are ignored */
        answer = dns_answer_new(2);
        ASSERT_NOT_NULL(answer);
        ASSERT_OK(dns_answer_add(answer, rr1_copy, /* ifindex= */ 0, DNS_ANSWER_CACHE_FLUSH, /* rrsig= */ NULL));
        ASSERT_OK(dns_answer_add(answer, foreign, /* ifindex= */ 0, /* flags= */ 0, /* rrsig= */ NULL));

        dns_zone_set_last_multicast(&zone, answer, 42 * USEC_PER_SEC);

        ASSERT_NOT_NULL(i = dns_zone_get(&zone, rr1));
        ASSERT_EQ(i->last_multicast_usec, 42 * USEC_PER_SEC);

        ASSERT_NOT_NULL(i = dns_zone_get(&zone, rr2));
        ASSERT_EQ(i->last_multicast_usec, 0u);

        dns_zone_flush(&zone);
}

DEFINE_TEST_MAIN(LOG_DEBUG)
