/*
 * test_ieee802_1x_nid.c — Unit tests for NID management (Clause 12.5)
 *
 * Verifies: #20 REQ-F-LOGON-002 (NID management and per-network policy)
 * Verifies: #50 REQ-F-NID-001 (Multi-NID group management)
 * See: IEEE 802.1X-2020, Clause 12.5.3
 *
 * Build (run from tests/pae/):
 *   make test_ieee802_1x_nid
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

/* Component under test */
#include "pae/ieee802_1x_logon.h"

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

/* ------------------------------------------------------------------ */
/* Mock DI context                                                     */
/* ------------------------------------------------------------------ */

static void mock_connect(void *ctx) { (void)ctx; }
static void mock_disconnect(void *ctx) { (void)ctx; }
static void mock_cp_auth(void *ctx) { (void)ctx; }
static void mock_cp_secure(void *ctx) { (void)ctx; }
static void mock_cp_pending(void *ctx) { (void)ctx; }
static void mock_cp_unauth(void *ctx) { (void)ctx; }

static struct ieee802_1x_logon_ctx mock_ctx = {
	.ctx = NULL,
	.logon_connect = mock_connect,
	.logon_disconnect = mock_disconnect,
	.cp_connect_authenticated = mock_cp_auth,
	.cp_connect_secure = mock_cp_secure,
	.cp_connect_pending = mock_cp_pending,
	.cp_connect_unauthenticated = mock_cp_unauth,
};


/* === NID table tests === */

TEST(nid_add_returns_entry)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ASSERT_NOT_NULL(logon);

	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_add(logon, "CorpNet");
	ASSERT_NOT_NULL(entry);
	ASSERT_FALSE(entry->use_eap);
	ASSERT_EQ(entry->unauth_allowed, NID_ACCESS_NEVER);
	ASSERT_EQ(entry->unsecure_allowed, NID_ACCESS_NEVER);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_add_null_logon_returns_null)
{
	struct ieee802_1x_nid_entry *entry = ieee802_1x_logon_nid_add(NULL, "test");
	ASSERT_NULL(entry);
}


TEST(nid_add_null_name_returns_null)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *entry = ieee802_1x_logon_nid_add(logon, NULL);
	ASSERT_NULL(entry);
	ieee802_1x_logon_deinit(logon);
}


TEST(nid_lookup_finds_existing)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ieee802_1x_logon_nid_add(logon, "CorpNet");

	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_lookup(logon, "CorpNet");
	ASSERT_NOT_NULL(entry);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_lookup_missing_returns_null)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_lookup(logon, "Nonexistent");
	ASSERT_NULL(entry);
	ieee802_1x_logon_deinit(logon);
}


TEST(nid_lookup_null_logon_returns_null)
{
	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_lookup(NULL, "test");
	ASSERT_NULL(entry);
}


TEST(nid_remove_existing)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ieee802_1x_logon_nid_add(logon, "CorpNet");

	int ret = ieee802_1x_logon_nid_remove(logon, "CorpNet");
	ASSERT_EQ(ret, 0);

	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_lookup(logon, "CorpNet");
	ASSERT_NULL(entry);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_remove_missing_returns_error)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	int ret = ieee802_1x_logon_nid_remove(logon, "Nonexistent");
	ASSERT_EQ(ret, -1);
	ieee802_1x_logon_deinit(logon);
}


TEST(nid_remove_null_logon_returns_error)
{
	int ret = ieee802_1x_logon_nid_remove(NULL, "test");
	ASSERT_EQ(ret, -1);
}


TEST(nid_policy_use_eap)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_add(logon, "CorpNet");
	entry->use_eap = true;
	entry->unauth_allowed = NID_ACCESS_NEVER;
	entry->unsecure_allowed = NID_ACCESS_NEVER;

	entry = ieee802_1x_logon_nid_lookup(logon, "CorpNet");
	ASSERT_TRUE(entry->use_eap);
	ASSERT_EQ(entry->unauth_allowed, NID_ACCESS_NEVER);
	ASSERT_EQ(entry->unsecure_allowed, NID_ACCESS_NEVER);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_policy_guest_unauth_immediate)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *entry =
		ieee802_1x_logon_nid_add(logon, "GuestNet");
	entry->use_eap = false;
	entry->unauth_allowed = NID_ACCESS_IMMEDIATE;

	entry = ieee802_1x_logon_nid_lookup(logon, "GuestNet");
	ASSERT_FALSE(entry->use_eap);
	ASSERT_EQ(entry->unauth_allowed, NID_ACCESS_IMMEDIATE);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_set_current)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ieee802_1x_logon_nid_add(logon, "CorpNet");

	int ret = ieee802_1x_logon_nid_set_current(logon, "CorpNet");
	ASSERT_EQ(ret, 0);

	const char *current = ieee802_1x_logon_nid_get_current(logon);
	ASSERT_NOT_NULL(current);
	ASSERT_STREQ(current, "CorpNet");

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_set_current_missing_returns_error)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	int ret = ieee802_1x_logon_nid_set_current(logon, "Nonexistent");
	ASSERT_EQ(ret, -1);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_get_current_no_selection_returns_null)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ieee802_1x_logon_nid_add(logon, "CorpNet");

	const char *current = ieee802_1x_logon_nid_get_current(logon);
	ASSERT_NULL(current);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_multiple_entries)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);

	struct ieee802_1x_nid_entry *e1 = ieee802_1x_logon_nid_add(logon, "CorpNet");
	struct ieee802_1x_nid_entry *e2 = ieee802_1x_logon_nid_add(logon, "GuestNet");
	ASSERT_NOT_NULL(e1);
	ASSERT_NOT_NULL(e2);

	e1->use_eap = true;
	e2->use_eap = false;

	e1 = ieee802_1x_logon_nid_lookup(logon, "CorpNet");
	e2 = ieee802_1x_logon_nid_lookup(logon, "GuestNet");
	ASSERT_TRUE(e1->use_eap);
	ASSERT_FALSE(e2->use_eap);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_count)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ASSERT_EQ(ieee802_1x_logon_nid_count(logon), 0);

	ieee802_1x_logon_nid_add(logon, "Corp");
	ASSERT_EQ(ieee802_1x_logon_nid_count(logon), 1);

	ieee802_1x_logon_nid_add(logon, "Guest");
	ASSERT_EQ(ieee802_1x_logon_nid_count(logon), 2);

	ieee802_1x_logon_nid_remove(logon, "Corp");
	ASSERT_EQ(ieee802_1x_logon_nid_count(logon), 1);

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_count_null_logon)
{
	ASSERT_EQ(ieee802_1x_logon_nid_count(NULL), 0);
}


TEST(nid_duplicate_add_returns_existing)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *e1 = ieee802_1x_logon_nid_add(logon, "Corp");
	e1->use_eap = true;

	struct ieee802_1x_nid_entry *e2 = ieee802_1x_logon_nid_add(logon, "Corp");
	ASSERT_NOT_NULL(e2);
	ASSERT_EQ(ieee802_1x_logon_nid_count(logon), 1);
	ASSERT_TRUE(e2->use_eap); /* preserves existing policy */

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_remove_shifts_current_nid)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	ieee802_1x_logon_nid_add(logon, "First");
	ieee802_1x_logon_nid_add(logon, "Second");
	ieee802_1x_logon_nid_add(logon, "Third");

	ieee802_1x_logon_nid_set_current(logon, "Third");
	ASSERT_STREQ(ieee802_1x_logon_nid_get_current(logon), "Third");

	/* Remove "Second" — "Third" shifts to index 1 */
	ieee802_1x_logon_nid_remove(logon, "Second");
	ASSERT_STREQ(ieee802_1x_logon_nid_get_current(logon), "Third");

	ieee802_1x_logon_deinit(logon);
}


TEST(nid_current_nid_policy_lookup)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&mock_ctx);
	struct ieee802_1x_nid_entry *e = ieee802_1x_logon_nid_add(logon, "CorpNet");
	e->use_eap = true;
	e->unauth_allowed = NID_ACCESS_NEVER;

	ieee802_1x_logon_nid_set_current(logon, "CorpNet");

	/* Verify we can look up the current NID and get its policy */
	const char *name = ieee802_1x_logon_nid_get_current(logon);
	ASSERT_NOT_NULL(name);
	struct ieee802_1x_nid_entry *current =
		ieee802_1x_logon_nid_lookup(logon, name);
	ASSERT_TRUE(current->use_eap);
	ASSERT_EQ(current->unauth_allowed, NID_ACCESS_NEVER);

	ieee802_1x_logon_deinit(logon);
}


int main(void)
{
	printf("NID Management Tests (Clause 12.5)\n");
	printf("==================================\n\n");

	RUN(nid_add_returns_entry);
	RUN(nid_add_null_logon_returns_null);
	RUN(nid_add_null_name_returns_null);
	RUN(nid_lookup_finds_existing);
	RUN(nid_lookup_missing_returns_null);
	RUN(nid_lookup_null_logon_returns_null);
	RUN(nid_remove_existing);
	RUN(nid_remove_missing_returns_error);
	RUN(nid_remove_null_logon_returns_error);
	RUN(nid_policy_use_eap);
	RUN(nid_policy_guest_unauth_immediate);
	RUN(nid_set_current);
	RUN(nid_set_current_missing_returns_error);
	RUN(nid_get_current_no_selection_returns_null);
	RUN(nid_multiple_entries);
	RUN(nid_count);
	RUN(nid_count_null_logon);
	RUN(nid_duplicate_add_returns_existing);
	RUN(nid_remove_shifts_current_nid);
	RUN(nid_current_nid_policy_lookup);

	printf("\nResults: %d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
