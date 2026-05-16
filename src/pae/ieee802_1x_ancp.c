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

#ifdef CONFIG_IEEE8021X_2020

#include "utils/includes.h"
#include "utils/common.h"
#include "pae/ieee802_1x_ancp.h"

/* TLV header: 1 byte type, 1 byte length */
#define ANCP_TLV_HEADER_LEN 2

/* Minimum TLV: header only */
#define ANCP_TLV_MIN_LEN ANCP_TLV_HEADER_LEN

/* NID entry in TLV: 1 byte name_len, name bytes, 1 byte flags */
#define ANCP_NID_ENTRY_MIN_LEN 3  /* name_len(1) + flags(1) + at least 1 char */

/* NID flags bitmask */
#define ANCP_NID_FLAG_USE_EAP       0x01
#define ANCP_NID_FLAG_UNAUTH        0x02
#define ANCP_NID_FLAG_UNSECURE      0x04


static int ancp_parse_nid_set_tlv(const u8 *tlv_data, size_t tlv_len,
				  struct ieee802_1x_ancp_announcement *result)
{
	const u8 *pos = tlv_data;
	const u8 *end = tlv_data + tlv_len;

	while (pos < end && result->nid_count < ANCP_NID_SET_MAX) {
		u8 name_len;
		u8 flags;
		size_t entry_idx;
		const u8 *name_start;
		size_t copy_len;

		if (end - pos < 2)
			break;

		name_len = *pos++;
		if (name_len == 0 || end - pos < name_len + 1)
			break;

		name_start = pos;
		pos += name_len;
		flags = *pos++;

		entry_idx = result->nid_count;
		copy_len = name_len < sizeof(result->nids[0].name) - 1 ?
			   name_len : sizeof(result->nids[0].name) - 1;
		os_memcpy(result->nids[entry_idx].name, name_start, copy_len);
		result->nids[entry_idx].name[copy_len] = '\0';
		result->nids[entry_idx].use_eap = !!(flags & ANCP_NID_FLAG_USE_EAP);
		result->nids[entry_idx].unauth_allowed = !!(flags & ANCP_NID_FLAG_UNAUTH);
		result->nids[entry_idx].unsecure_allowed = !!(flags & ANCP_NID_FLAG_UNSECURE);
		result->nid_count++;
	}

	return 0;
}


static int ancp_parse_cipher_suite_tlv(const u8 *tlv_data, size_t tlv_len,
				       struct ieee802_1x_ancp_announcement *result)
{
	const u8 *pos = tlv_data;
	const u8 *end = tlv_data + tlv_len;

	while (pos + sizeof(u64) <= end &&
	       result->cipher_suite_count < ANCP_CIPHER_SUITE_MAX) {
		u64 cs = WPA_GET_BE64(pos);
		result->cipher_suites[result->cipher_suite_count] = cs;
		result->cipher_suite_count++;
		pos += sizeof(u64);
	}

	return 0;
}


int ieee802_1x_ancp_parse_announcement(const u8 *data, size_t len,
				       struct ieee802_1x_ancp_announcement *result)
{
	const u8 *pos;
	const u8 *end;

	if (!data || !result || len < ANCP_TLV_MIN_LEN)
		return -1;

	os_memset(result, 0, sizeof(*result));
	pos = data;
	end = data + len;

	while (pos + ANCP_TLV_HEADER_LEN <= end) {
		u8 tlv_type = *pos++;
		u8 tlv_len = *pos++;

		if (pos + tlv_len > end) {
			wpa_printf(MSG_DEBUG,
				   "ANCP: TLV %d length %d exceeds frame", tlv_type, tlv_len);
			return -1;
		}

		switch (tlv_type) {
		case ANCP_TLV_NID_SET:
			ancp_parse_nid_set_tlv(pos, tlv_len, result);
			break;
		case ANCP_TLV_ACCESS_INFO:
			/* Access Information TLV — parsed but not yet used */
			wpa_hexdump(MSG_MSGDUMP, "ANCP: Access Info TLV", pos, tlv_len);
			break;
		case ANCP_TLV_MACSEC_CIPHER:
			ancp_parse_cipher_suite_tlv(pos, tlv_len, result);
			break;
		case ANCP_TLV_KEY_MGMT_DOMAIN:
			/* Key Management Domain TLV — parsed but not yet used */
			wpa_hexdump(MSG_MSGDUMP, "ANCP: Key Mgmt Domain TLV", pos, tlv_len);
			break;
		default:
			wpa_printf(MSG_DEBUG, "ANCP: Unknown TLV type %d len %d",
				   tlv_type, tlv_len);
			break;
		}

		pos += tlv_len;
	}

	result->valid = true;
	return 0;
}


bool ieee802_1x_ancp_validate(const u8 *data, size_t len)
{
	const u8 *pos;
	const u8 *end;

	if (!data || len < ANCP_TLV_MIN_LEN)
		return false;

	pos = data;
	end = data + len;

	while (pos + ANCP_TLV_HEADER_LEN <= end) {
		u8 tlv_type = *pos++;
		u8 tlv_len = *pos++;

		if (pos + tlv_len > end)
			return false;

		/* Validate TLV type is in known range */
		if (tlv_type > ANCP_TLV_KEY_MGMT_DOMAIN && tlv_type < 128) {
			wpa_printf(MSG_DEBUG,
				   "ANCP: Unknown mandatory TLV type %d", tlv_type);
			return false;
		}

		pos += tlv_len;
	}

	return true;
}


size_t ieee802_1x_ancp_nid_count(const struct ieee802_1x_ancp_announcement *ann)
{
	if (!ann)
		return 0;
	return ann->nid_count;
}


const struct ieee802_1x_ancp_nid *
ieee802_1x_ancp_get_nid(const struct ieee802_1x_ancp_announcement *ann,
			size_t index)
{
	if (!ann || index >= ann->nid_count)
		return NULL;
	return &ann->nids[index];
}

#endif /* CONFIG_IEEE8021X_2020 */
