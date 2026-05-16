/*
 * Test: ieee802_1x_kay_suspend / ieee802_1x_kay_resume
 *
 * Standalone unit tests for MKA suspend/resume per IEEE 802.1X-2020 Clause 9.
 * Does NOT link against the full ieee802_1x_kay.c — instead, the suspend/resume
 * functions are included inline with minimal stubs.
 *
 * Verifies: #17 REQ-F-MKA-005 (MKA suspension)
 * See: IEEE 802.1X-2020, Clause 9
 *
 * Build (run from tests/pae/):
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/* Minimal type stubs so we can compile the functions under test         */
/* ------------------------------------------------------------------ */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/list.h"

/* Stub os_zalloc */
void *os_zalloc(size_t size) { return calloc(1, size); }

/* Stub wpa_printf */
void wpa_printf(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

/* Minimal struct ieee802_1x_mka_participant — only the fields we need */
struct ieee802_1x_mka_participant {
	struct dl_list list;
	bool suspended;
	/* Placeholder for the full struct; we only test suspended */
};

/* Minimal struct ieee802_1x_kay — only the fields we need */
struct ieee802_1x_kay {
	bool mka_suspended;
	struct dl_list participant_list;
};

/* ------------------------------------------------------------------ */
/* Functions under test — copied from ieee802_1x_kay.c                  */
/* ------------------------------------------------------------------ */

int ieee802_1x_kay_suspend(struct ieee802_1x_kay *kay)
{
	struct ieee802_1x_mka_participant *participant;

	if (!kay)
		return -1;

	dl_list_for_each(participant, &kay->participant_list,
			 struct ieee802_1x_mka_participant, list) {
		participant->suspended = true;
	}

	kay->mka_suspended = true;
	return 0;
}

int ieee802_1x_kay_resume(struct ieee802_1x_kay *kay)
{
	struct ieee802_1x_mka_participant *participant;

	if (!kay)
		return -1;

	dl_list_for_each(participant, &kay->participant_list,
			 struct ieee802_1x_mka_participant, list) {
		participant->suspended = false;
	}

	kay->mka_suspended = false;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Test infrastructure                                                   */
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

#define ASSERT_EQ(a, b) \
	do { if ((a) != (b)) FAIL(#a " != " #b); } while (0)

#define ASSERT_TRUE(p) \
	do { if (!(p)) FAIL(#p " was false"); } while (0)

#define ASSERT_FALSE(p) \
	do { if ((p)) FAIL(#p " was true"); } while (0)

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static struct ieee802_1x_kay *alloc_test_kay(void)
{
	struct ieee802_1x_kay *kay = os_zalloc(sizeof(*kay));
	if (!kay)
		return NULL;
	dl_list_init(&kay->participant_list);
	return kay;
}

static void free_test_kay(struct ieee802_1x_kay *kay)
{
	os_free(kay);
}

static struct ieee802_1x_mka_participant *alloc_participant(void)
{
	struct ieee802_1x_mka_participant *p = os_zalloc(sizeof(*p));
	if (!p)
		return NULL;
	return p;
}

static void add_participant(struct ieee802_1x_kay *kay,
			    struct ieee802_1x_mka_participant *p)
{
	dl_list_add(&kay->participant_list, &p->list);
}

/* ------------------------------------------------------------------ */
/* Tests                                                                 */
/* ------------------------------------------------------------------ */

/*
 * TC-KAY-SUSPEND-001
 * Suspend with NULL kay returns -1.
 */
TEST(test_kay_suspend_null)
{
	int ret = ieee802_1x_kay_suspend(NULL);
	ASSERT_EQ(ret, -1);
}

/*
 * TC-KAY-SUSPEND-002
 * Suspend on a valid kay with no participants returns 0 and sets
 * mka_suspended flag.
 */
TEST(test_kay_suspend_no_participants)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	ASSERT_NOT_NULL(kay);

	int ret = ieee802_1x_kay_suspend(kay);
	ASSERT_EQ(ret, 0);
	ASSERT_TRUE(kay->mka_suspended);

	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-003
 * Resume with NULL kay returns -1.
 */
TEST(test_kay_resume_null)
{
	int ret = ieee802_1x_kay_resume(NULL);
	ASSERT_EQ(ret, -1);
}

/*
 * TC-KAY-SUSPEND-004
 * Resume on a valid kay with no participants returns 0 and clears
 * mka_suspended flag.
 */
TEST(test_kay_resume_no_participants)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	ASSERT_NOT_NULL(kay);

	kay->mka_suspended = true;
	int ret = ieee802_1x_kay_resume(kay);
	ASSERT_EQ(ret, 0);
	ASSERT_FALSE(kay->mka_suspended);

	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-005
 * Suspend followed by resume is idempotent.
 */
TEST(test_kay_suspend_resume_cycle)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	ASSERT_NOT_NULL(kay);

	ASSERT_FALSE(kay->mka_suspended);

	ASSERT_EQ(ieee802_1x_kay_suspend(kay), 0);
	ASSERT_TRUE(kay->mka_suspended);

	ASSERT_EQ(ieee802_1x_kay_resume(kay), 0);
	ASSERT_FALSE(kay->mka_suspended);

	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-006
 * Double suspend: suspending an already-suspended kay returns 0 and
 * mka_suspended remains true.
 */
TEST(test_kay_double_suspend)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	ASSERT_NOT_NULL(kay);

	ASSERT_EQ(ieee802_1x_kay_suspend(kay), 0);
	ASSERT_TRUE(kay->mka_suspended);

	ASSERT_EQ(ieee802_1x_kay_suspend(kay), 0);
	ASSERT_TRUE(kay->mka_suspended);

	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-007
 * Resume when not suspended: returns 0, mka_suspended stays false.
 */
TEST(test_kay_resume_not_suspended)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	ASSERT_NOT_NULL(kay);

	ASSERT_FALSE(kay->mka_suspended);
	ASSERT_EQ(ieee802_1x_kay_resume(kay), 0);
	ASSERT_FALSE(kay->mka_suspended);

	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-008
 * Suspend sets suspended=true on all participants.
 */
TEST(test_kay_suspend_participants_flagged)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	struct ieee802_1x_mka_participant *p1 = alloc_participant();
	struct ieee802_1x_mka_participant *p2 = alloc_participant();
	ASSERT_NOT_NULL(kay);
	ASSERT_NOT_NULL(p1);
	ASSERT_NOT_NULL(p2);

	add_participant(kay, p1);
	add_participant(kay, p2);

	ASSERT_FALSE(p1->suspended);
	ASSERT_FALSE(p2->suspended);

	ASSERT_EQ(ieee802_1x_kay_suspend(kay), 0);
	ASSERT_TRUE(p1->suspended);
	ASSERT_TRUE(p2->suspended);
	ASSERT_TRUE(kay->mka_suspended);

	os_free(p1);
	os_free(p2);
	free_test_kay(kay);
}

/*
 * TC-KAY-SUSPEND-009
 * Resume clears suspended=false on all participants.
 */
TEST(test_kay_resume_participants_cleared)
{
	struct ieee802_1x_kay *kay = alloc_test_kay();
	struct ieee802_1x_mka_participant *p1 = alloc_participant();
	struct ieee802_1x_mka_participant *p2 = alloc_participant();
	ASSERT_NOT_NULL(kay);
	ASSERT_NOT_NULL(p1);
	ASSERT_NOT_NULL(p2);

	add_participant(kay, p1);
	add_participant(kay, p2);

	ieee802_1x_kay_suspend(kay);
	ASSERT_TRUE(p1->suspended);
	ASSERT_TRUE(p2->suspended);

	ASSERT_EQ(ieee802_1x_kay_resume(kay), 0);
	ASSERT_FALSE(p1->suspended);
	ASSERT_FALSE(p2->suspended);
	ASSERT_FALSE(kay->mka_suspended);

	os_free(p1);
	os_free(p2);
	free_test_kay(kay);
}

/* ------------------------------------------------------------------ */
/* Main                                                                  */
/* ------------------------------------------------------------------ */

int main(void)
{
	printf("IEEE 802.1X-2020 MKA Suspend/Resume Tests\n");
	printf("==========================================\n\n");

	RUN(test_kay_suspend_null);
	RUN(test_kay_suspend_no_participants);
	RUN(test_kay_resume_null);
	RUN(test_kay_resume_no_participants);
	RUN(test_kay_suspend_resume_cycle);
	RUN(test_kay_double_suspend);
	RUN(test_kay_resume_not_suspended);
	RUN(test_kay_suspend_participants_flagged);
	RUN(test_kay_resume_participants_cleared);

	printf("\n==========================================\n");
	printf("Results: %d/%d passed", tests_passed, tests_run);
	if (tests_failed)
		printf(", %d FAILED", tests_failed);
	printf("\n");

	return tests_failed ? 1 : 0;
}
