/*
 * IEEE 802.1X-2020 ANCP — Announced Network Connectivity Protocol
 *
 * Implements: #49 REQ-F-ANCP-001 (ANCP implementation per Clause 10)
 * Implements: #27 StR-004 (EAPOL Announcement support)
 * See: IEEE 802.1X-2020, Clause 10, Clause 11.12
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_1X_ANCP_H
#define IEEE802_1X_ANCP_H

#include <stdbool.h>
#include <stddef.h>
#include "common/defs.h"

/**
 * enum ieee802_1x_ancp_tlv_type - EAPOL-Announcement TLV types per Clause 11.12
 */
enum ieee802_1x_ancp_tlv_type {
	ANCP_TLV_NID_SET = 1,           /* Clause 11.12.1 */
	ANCP_TLV_ACCESS_INFO = 2,       /* Clause 11.12.2 */
	ANCP_TLV_MACSEC_CIPHER = 3,     /* Clause 11.12.3 */
	ANCP_TLV_KEY_MGMT_DOMAIN = 4,   /* Clause 11.12.4 */
};

#define ANCP_NID_SET_MAX 16
#define ANCP_CIPHER_SUITE_MAX 8

/**
 * struct ieee802_1x_ancp_nid - NID Set entry from Announcement
 *
 * Per Clause 11.12.1, each NID in a NID Set TLV carries an identifier
 * and access policy flags.
 */
struct ieee802_1x_ancp_nid {
	char name[64];             /* NID identifier */
	bool use_eap;              /* EAP authentication required */
	bool unauth_allowed;       /* Unauthenticated access allowed */
	bool unsecure_allowed;     /* Unsecured access allowed */
};

/**
 * struct ieee802_1x_ancp_announcement - Parsed EAPOL-Announcement
 *
 * Holds the result of parsing an EAPOL-Announcement frame.
 */
struct ieee802_1x_ancp_announcement {
	struct ieee802_1x_ancp_nid nids[ANCP_NID_SET_MAX];
	size_t nid_count;

	u64 cipher_suites[ANCP_CIPHER_SUITE_MAX];
	size_t cipher_suite_count;

	bool valid;                /* Announcement passed validation */
};

/**
 * ieee802_1x_ancp_parse_announcement - Parse an EAPOL-Announcement frame
 * @data: Raw frame payload (after EAPOL header).
 * @len: Length of data in bytes.
 * @result: Output structure to populate.
 * Returns: 0 on success, -1 on parse error.
 *
 * @implements #49 REQ-F-ANCP-001
 * @see IEEE 802.1X-2020, Clause 11.12
 */
int ieee802_1x_ancp_parse_announcement(const u8 *data, size_t len,
				       struct ieee802_1x_ancp_announcement *result);

/**
 * ieee802_1x_ancp_validate - Validate an EAPOL-Announcement frame
 * @data: Raw frame payload.
 * @len: Length of data in bytes.
 * Returns: true if frame is a valid EAPOL-Announcement.
 *
 * @see IEEE 802.1X-2020, Clause 11.12.6
 */
bool ieee802_1x_ancp_validate(const u8 *data, size_t len);

/**
 * ieee802_1x_ancp_nid_count - Return number of NIDs from last parsed announcement
 * @ann: Parsed announcement pointer.
 */
size_t ieee802_1x_ancp_nid_count(const struct ieee802_1x_ancp_announcement *ann);

/**
 * ieee802_1x_ancp_get_nid - Get a specific NID from parsed announcement
 * @ann: Parsed announcement pointer.
 * @index: NID index (0-based).
 * Returns: Pointer to NID entry, or NULL if index out of range.
 */
const struct ieee802_1x_ancp_nid *
ieee802_1x_ancp_get_nid(const struct ieee802_1x_ancp_announcement *ann,
			size_t index);

#endif /* IEEE802_1X_ANCP_H */
