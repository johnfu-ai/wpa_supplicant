/*
 * test_ieee802_1x_ancp.c — Unit tests for ANCP (Clause 10)
 *
 * Verifies: #49 REQ-F-ANCP-001 (ANCP implementation)
 * Verifies: #27 StR-004 (EAPOL Announcement support)
 * See: IEEE 802.1X-2020, Clause 10, Clause 11.12
 *
 * Build (run from tests/pae/):
 *   make test_ieee802_1x_ancp
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"

void *os_zalloc(size_t size) { return calloc(1, size); }

void wpa_printf(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

void wpa_hexdump(int level, const char *title, const void *p, size_t len)
{
	(void)level; (void)title; (void)p; (void)len;
}

/* Component under test */
#include "pae/ieee802_1x_ancp.h"

/* ------------------------------------------------------------------ */
/* Test infrastructure                                                 */
/* ------------------------------------------------------------------ */

static int tests_run    = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN(name) \
	do { \
		tests_run++; \
		printf("  %-55s", #name); \
		name(); \
		printf("PASS\n"); \
		tests_passed++; \
	} while (0)

#define FAIL(msg) \
	do { \
		printf("FAIL\n    -> %s (line %d)\n", msg, __LINE__); \
		tests_failed++; \
		return; \
	} while (0)

#define ASSERT_NOT_NULL(p) \
	do { if (!(p)) FAIL(#p " was NULL"); } while (0)

#define ASSERT_NULL(p) \
	do { if ((p)) FAIL(#p " was not NULL"); } while (0)

#define ASSERT_EQ(a, b) \
	do { if ((a) != (b)) FAIL(#a " != " #b); } while (0)

#define ASSERT_TRUE(x) ASSERT_EQ((x), true)
#define ASSERT_FALSE(x) ASSERT_EQ((x), false)
#define ASSERT_STREQ(a, b) \
	do { if (strcmp((a), (b)) != 0) FAIL(#a " != " #b); } while (0)


/* === ANCP tests === */

TEST(ancp_parse_null_data_returns_error)
{
	struct ieee802_1x_ancp_announcement ann;
	int ret = ieee802_1x_ancp_parse_announcement(NULL, 10, &ann);
	ASSERT_EQ(ret, -1);
}


TEST(ancp_parse_null_result_returns_error)
{
	u8 data[] = {0x01, 0x00};
	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), NULL);
	ASSERT_EQ(ret, -1);
}


TEST(ancp_parse_empty_data_returns_error)
{
	struct ieee802_1x_ancp_announcement ann;
	int ret = ieee802_1x_ancp_parse_announcement((u8 *)"", 0, &ann);
	ASSERT_EQ(ret, -1);
}


TEST(ancp_parse_empty_tlv_list)
{
	struct ieee802_1x_ancp_announcement ann;
	u8 data[] = {0x01, 0x00};  /* NID Set TLV with 0 length */
	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ret, 0);
	ASSERT_TRUE(ann.valid);
	ASSERT_EQ(ann.nid_count, 0);
}


TEST(ancp_parse_nid_set_tlv)
{
	struct ieee802_1x_ancp_announcement ann;
	/* TLV: type=1 (NID Set), len=6, name_len=4, name="Corp", flags=0x01 (use_eap) */
	u8 data[] = {0x01, 0x06, 0x04, 'C', 'o', 'r', 'p', 0x01};

	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ret, 0);
	ASSERT_TRUE(ann.valid);
	ASSERT_EQ(ann.nid_count, 1);
	ASSERT_STREQ(ann.nids[0].name, "Corp");
	ASSERT_TRUE(ann.nids[0].use_eap);
	ASSERT_FALSE(ann.nids[0].unauth_allowed);
	ASSERT_FALSE(ann.nids[0].unsecure_allowed);
}


TEST(ancp_parse_nid_set_multiple_nids)
{
	struct ieee802_1x_ancp_announcement ann;
	/* TLV: type=1 (NID Set), len=12
	 * NID1: name_len=4, name="Corp", flags=0x01 (use_eap)
	 * NID2: name_len=4, name="Gest", flags=0x02 (unauth) */
	u8 data[] = {
		0x01, 0x0c,
		0x04, 'C', 'o', 'r', 'p', 0x01,
		0x04, 'G', 'e', 's', 't', 0x02
	};

	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(ann.nid_count, 2);
	ASSERT_TRUE(ann.nids[0].use_eap);
	ASSERT_FALSE(ann.nids[0].unauth_allowed);
	ASSERT_FALSE(ann.nids[1].use_eap);
	ASSERT_TRUE(ann.nids[1].unauth_allowed);
}


TEST(ancp_parse_truncated_tlv_returns_error)
{
	struct ieee802_1x_ancp_announcement ann;
	/* TLV: type=1, len=10 but only 2 bytes follow */
	u8 data[] = {0x01, 0x0a, 0x03, 'C'};

	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ret, -1);
}


TEST(ancp_validate_valid_frame)
{
	u8 data[] = {0x01, 0x00};
	ASSERT_TRUE(ieee802_1x_ancp_validate(data, sizeof(data)));
}


TEST(ancp_validate_null_data)
{
	ASSERT_FALSE(ieee802_1x_ancp_validate(NULL, 10));
}


TEST(ancp_validate_empty_data)
{
	ASSERT_FALSE(ieee802_1x_ancp_validate((u8 *)"", 0));
}


TEST(ancp_validate_truncated_tlv)
{
	u8 data[] = {0x01, 0x05, 0x03};  /* claims 5 bytes, only 1 follows */
	ASSERT_FALSE(ieee802_1x_ancp_validate(data, sizeof(data)));
}


TEST(ancp_nid_count)
{
	struct ieee802_1x_ancp_announcement ann;
	u8 data[] = {
		0x01, 0x0c,
		0x04, 'C', 'o', 'r', 'p', 0x01,
		0x04, 'G', 'e', 's', 't', 0x02
	};

	ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ieee802_1x_ancp_nid_count(&ann), 2);
}


TEST(ancp_nid_count_null)
{
	ASSERT_EQ(ieee802_1x_ancp_nid_count(NULL), 0);
}


TEST(ancp_get_nid_valid_index)
{
	struct ieee802_1x_ancp_announcement ann;
	u8 data[] = {
		0x01, 0x0c,
		0x04, 'C', 'o', 'r', 'p', 0x01,
		0x04, 'G', 'e', 's', 't', 0x02
	};

	ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	const struct ieee802_1x_ancp_nid *nid = ieee802_1x_ancp_get_nid(&ann, 0);
	ASSERT_NOT_NULL(nid);
	ASSERT_STREQ(nid->name, "Corp");
}


TEST(ancp_get_nid_out_of_range)
{
	struct ieee802_1x_ancp_announcement ann;
	os_memset(&ann, 0, sizeof(ann));
	ann.nid_count = 0;
	ASSERT_NULL(ieee802_1x_ancp_get_nid(&ann, 0));
}


TEST(ancp_get_nid_null)
{
	ASSERT_NULL(ieee802_1x_ancp_get_nid(NULL, 0));
}


TEST(ancp_parse_cipher_suite_tlv)
{
	struct ieee802_1x_ancp_announcement ann;
	/* TLV: type=3 (MACsec Cipher), len=8, one 64-bit cipher suite */
	u8 data[] = {
		0x03, 0x08,
		0x00, 0x80, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x01
	};

	int ret = ieee802_1x_ancp_parse_announcement(data, sizeof(data), &ann);
	ASSERT_EQ(ret, 0);
	ASSERT_EQ(ann.cipher_suite_count, 1);
}


int main(void)
{
	printf("ANCP Tests (Clause 10)\n");
	printf("======================\n\n");

	RUN(ancp_parse_null_data_returns_error);
	RUN(ancp_parse_null_result_returns_error);
	RUN(ancp_parse_empty_data_returns_error);
	RUN(ancp_parse_empty_tlv_list);
	RUN(ancp_parse_nid_set_tlv);
	RUN(ancp_parse_nid_set_multiple_nids);
	RUN(ancp_parse_truncated_tlv_returns_error);
	RUN(ancp_validate_valid_frame);
	RUN(ancp_validate_null_data);
	RUN(ancp_validate_empty_data);
	RUN(ancp_validate_truncated_tlv);
	RUN(ancp_nid_count);
	RUN(ancp_nid_count_null);
	RUN(ancp_get_nid_valid_index);
	RUN(ancp_get_nid_out_of_range);
	RUN(ancp_get_nid_null);
	RUN(ancp_parse_cipher_suite_tlv);

	printf("\nResults: %d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
