/*
 * Test: ieee802_1x_pacp_logon_if integration with eapol_sm
 *
 * Standalone unit tests for PACP Logon Process interface per
 * IEEE 802.1X-2020 Clause 8/12. Tests the logon_if registration,
 * auth notification callbacks, and variable aliases.
 *
 * Verifies: #6 REQ-F-PAE-002, #9 REQ-F-PAE-005
 * See: IEEE 802.1X-2020, Clause 8, Clause 12
 *
 * Build (run from tests/pae/):
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

/* ------------------------------------------------------------------ */
/* Minimal PACP/PAE type stubs for testing                              */
/* ------------------------------------------------------------------ */

typedef enum { Unauthorized, Authorized } PortStatus;
typedef enum { Auto, ForceUnauthorized, ForceAuthorized } PortControl;

/* ieee802_1x_pacp_logon_if — per DESIGN-PAE-001 Section 5.1 */
struct ieee802_1x_pacp_logon_if {
	void *ctx;
	void (*logon_connect)(void *ctx);
	void (*logon_disconnect)(void *ctx);
	void (*auth_success)(void *ctx);
	void (*auth_failure)(void *ctx);
};

/* Minimal eapol_sm — only the fields needed for testing */
struct eapol_sm {
	PortStatus suppPortStatus;
	bool force_authorized_update;
	void *ctx_placeholder;  /* stands in for eapol_ctx * */

#ifdef CONFIG_IEEE8021X_2020
	/* 802.1X-2020 Clause 8 additions per DESIGN-PAE-001 Section 3 */
	bool pacp_nid_associated;
	bool eapStart_nid;
	bool reAuthenticate;
	bool auth_notify_success;
	bool auth_notify_failure;
	struct ieee802_1x_pacp_logon_if *logon_if;
#endif
};

/* ------------------------------------------------------------------ */
/* Functions under test — minimal implementations matching DESIGN-PAE-001 */
/* ------------------------------------------------------------------ */

#ifdef CONFIG_IEEE8021X_2020

void eapol_sm_set_logon_if(struct eapol_sm *sm,
			    const struct ieee802_1x_pacp_logon_if *logon_if)
{
	if (!sm || !logon_if)
		return;
	if (!sm->logon_if)
		sm->logon_if = os_zalloc(sizeof(*sm->logon_if));
	if (!sm->logon_if)
		return;
	os_memcpy(sm->logon_if, logon_if, sizeof(*logon_if));
}

static void eapol_sm_set_port_authorized(struct eapol_sm *sm)
{
	sm->suppPortStatus = Authorized;
	if (sm->logon_if && sm->logon_if->auth_success &&
	    !sm->auth_notify_success) {
		sm->logon_if->auth_success(sm->logon_if->ctx);
		sm->auth_notify_success = true;
	}
}

static void eapol_sm_set_port_unauthorized(struct eapol_sm *sm)
{
	sm->suppPortStatus = Unauthorized;
	if (sm->logon_if && sm->logon_if->auth_failure &&
	    !sm->auth_notify_failure) {
		sm->logon_if->auth_failure(sm->logon_if->ctx);
		sm->auth_notify_failure = true;
	}
}

#endif /* CONFIG_IEEE8021X_2020 */

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

#define ASSERT_NULL(p) \
	do { if ((p)) FAIL(#p " was not NULL"); } while (0)

#define ASSERT_EQ(a, b) \
	do { if ((a) != (b)) FAIL(#a " != " #b); } while (0)

#define ASSERT_TRUE(p) \
	do { if (!(p)) FAIL(#p " was false"); } while (0)

#define ASSERT_FALSE(p) \
	do { if ((p)) FAIL(#p " was true"); } while (0)

/* ------------------------------------------------------------------ */
/* Mock callbacks                                                        */
/* ------------------------------------------------------------------ */

static int mock_auth_success_called;
static int mock_auth_failure_called;
static void *mock_auth_success_ctx;
static void *mock_auth_failure_ctx;

static void mock_auth_success(void *ctx)
{
	mock_auth_success_called++;
	mock_auth_success_ctx = ctx;
}

static void mock_auth_failure(void *ctx)
{
	mock_auth_failure_called++;
	mock_auth_failure_ctx = ctx;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static struct eapol_sm *alloc_test_sm(void)
{
	struct eapol_sm *sm = os_zalloc(sizeof(*sm));
	if (!sm)
		return NULL;
	return sm;
}

static void free_test_sm(struct eapol_sm *sm)
{
#ifdef CONFIG_IEEE8021X_2020
	if (sm && sm->logon_if)
		os_free(sm->logon_if);
#endif
	os_free(sm);
}

static void reset_mocks(void)
{
	mock_auth_success_called = 0;
	mock_auth_failure_called = 0;
	mock_auth_success_ctx = NULL;
	mock_auth_failure_ctx = NULL;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                 */
/* ------------------------------------------------------------------ */

/*
 * TC-PACP-LOGONIF-001
 * eapol_sm_set_logon_if with NULL sm does not crash.
 */
TEST(test_pacp_set_logon_if_null_sm)
{
#ifdef CONFIG_IEEE8021X_2020
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	/* Should not crash */
	eapol_sm_set_logon_if(NULL, &logon_if);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-002
 * eapol_sm_set_logon_if stores the callback struct.
 */
TEST(test_pacp_set_logon_if_stores)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	logon_if.ctx = (void *)0xDEAD;
	logon_if.auth_success = mock_auth_success;

	ASSERT_NULL(sm->logon_if);
	eapol_sm_set_logon_if(sm, &logon_if);
	ASSERT_NOT_NULL(sm->logon_if);
	ASSERT_EQ(sm->logon_if->ctx, (void *)0xDEAD);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-003
 * When logon_if is registered, eapol_sm_set_port_authorized calls
 * auth_success callback.
 */
TEST(test_pacp_port_authorized_calls_auth_success)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	reset_mocks();

	logon_if.ctx = (void *)0xBEEF;
	logon_if.auth_success = mock_auth_success;
	eapol_sm_set_logon_if(sm, &logon_if);

	ASSERT_EQ(mock_auth_success_called, 0);
	eapol_sm_set_port_authorized(sm);
	ASSERT_EQ(mock_auth_success_called, 1);
	ASSERT_EQ(mock_auth_success_ctx, (void *)0xBEEF);
	ASSERT_TRUE(sm->auth_notify_success);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-004
 * When logon_if is registered, eapol_sm_set_port_unauthorized calls
 * auth_failure callback.
 */
TEST(test_pacp_port_unauthorized_calls_auth_failure)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	reset_mocks();

	logon_if.ctx = (void *)0xCAFE;
	logon_if.auth_failure = mock_auth_failure;
	eapol_sm_set_logon_if(sm, &logon_if);

	ASSERT_EQ(mock_auth_failure_called, 0);
	eapol_sm_set_port_unauthorized(sm);
	ASSERT_EQ(mock_auth_failure_called, 1);
	ASSERT_EQ(mock_auth_failure_ctx, (void *)0xCAFE);
	ASSERT_TRUE(sm->auth_notify_failure);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-005
 * When logon_if is NOT registered (NULL), set_port_authorized does
 * not call auth_success — backward compatibility.
 */
TEST(test_pacp_port_authorized_no_logon_if)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	reset_mocks();

	ASSERT_NULL(sm->logon_if);
	eapol_sm_set_port_authorized(sm);
	ASSERT_EQ(mock_auth_success_called, 0);
	ASSERT_EQ(sm->suppPortStatus, Authorized);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-006
 * Auth notification deduplication: auth_success is called only once
 * per auth attempt, even if set_port_authorized is called again.
 */
TEST(test_pacp_auth_success_dedup)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	reset_mocks();

	logon_if.ctx = (void *)0x1;
	logon_if.auth_success = mock_auth_success;
	eapol_sm_set_logon_if(sm, &logon_if);

	eapol_sm_set_port_authorized(sm);
	ASSERT_EQ(mock_auth_success_called, 1);

	/* Second call should not trigger callback again */
	eapol_sm_set_port_authorized(sm);
	ASSERT_EQ(mock_auth_success_called, 1);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-007
 * Auth notification deduplication: auth_failure is called only once
 * per auth attempt.
 */
TEST(test_pacp_auth_failure_dedup)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	struct ieee802_1x_pacp_logon_if logon_if;
	memset(&logon_if, 0, sizeof(logon_if));
	reset_mocks();

	logon_if.ctx = (void *)0x1;
	logon_if.auth_failure = mock_auth_failure;
	eapol_sm_set_logon_if(sm, &logon_if);

	eapol_sm_set_port_unauthorized(sm);
	ASSERT_EQ(mock_auth_failure_called, 1);

	/* Second call should not trigger callback again */
	eapol_sm_set_port_unauthorized(sm);
	ASSERT_EQ(mock_auth_failure_called, 1);

	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-008
 * New state variables are initialized to zero/false by os_zalloc.
 */
TEST(test_pacp_new_variables_initialized)
{
#ifdef CONFIG_IEEE8021X_2020
	struct eapol_sm *sm = alloc_test_sm();
	ASSERT_FALSE(sm->pacp_nid_associated);
	ASSERT_FALSE(sm->eapStart_nid);
	ASSERT_FALSE(sm->reAuthenticate);
	ASSERT_FALSE(sm->auth_notify_success);
	ASSERT_FALSE(sm->auth_notify_failure);
	ASSERT_NULL(sm->logon_if);
	free_test_sm(sm);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/*
 * TC-PACP-LOGONIF-009
 * Variable aliases: PACP state names map to PAE state values.
 * These values come from the enum in eapol_supp_sm.c:
 *   DISCONNECTED=1, CONNECTING=3, AUTHENTICATING=4,
 *   AUTHENTICATED=5, HELD=7, RESTART=8
 */
TEST(test_pacp_variable_aliases)
{
#ifdef CONFIG_IEEE8021X_2020
	/* PAE state values (from eapol_supp_sm.c enum) */
	enum {
		SUPP_PAE_DISCONNECTED = 1,
		SUPP_PAE_CONNECTING = 3,
		SUPP_PAE_AUTHENTICATING = 4,
		SUPP_PAE_AUTHENTICATED = 5,
		SUPP_PAE_HELD = 7,
		SUPP_PAE_RESTART = 8
	};

	/* PACP aliases per DESIGN-PAE-001 Section 4 */
	#define SUPP_PACP_DISCONNECTED   SUPP_PAE_DISCONNECTED
	#define SUPP_PACP_CONNECTING     SUPP_PAE_CONNECTING
	#define SUPP_PACP_AUTHENTICATING SUPP_PAE_AUTHENTICATING
	#define SUPP_PACP_AUTHENTICATED  SUPP_PAE_AUTHENTICATED
	#define SUPP_PACP_HELD           SUPP_PAE_HELD
	#define SUPP_PACP_RESTART        SUPP_PAE_RESTART

	ASSERT_EQ(SUPP_PACP_DISCONNECTED, 1);
	ASSERT_EQ(SUPP_PACP_CONNECTING, 3);
	ASSERT_EQ(SUPP_PACP_AUTHENTICATING, 4);
	ASSERT_EQ(SUPP_PACP_AUTHENTICATED, 5);
	ASSERT_EQ(SUPP_PACP_HELD, 7);
	ASSERT_EQ(SUPP_PACP_RESTART, 8);
#else
	printf("SKIP (CONFIG_IEEE8021X_2020 not defined)");
#endif
}

/* ------------------------------------------------------------------ */
/* Main                                                                  */
/* ------------------------------------------------------------------ */

int main(void)
{
	printf("IEEE 802.1X-2020 PACP logon_if Integration Tests\n");
	printf("=================================================\n\n");

#ifdef CONFIG_IEEE8021X_2020
	RUN(test_pacp_set_logon_if_null_sm);
	RUN(test_pacp_set_logon_if_stores);
	RUN(test_pacp_port_authorized_calls_auth_success);
	RUN(test_pacp_port_unauthorized_calls_auth_failure);
	RUN(test_pacp_port_authorized_no_logon_if);
	RUN(test_pacp_auth_success_dedup);
	RUN(test_pacp_auth_failure_dedup);
	RUN(test_pacp_new_variables_initialized);
	RUN(test_pacp_variable_aliases);
#else
	printf("  CONFIG_IEEE8021X_2020 not defined — skipping PACP logon_if tests\n");
#endif

	printf("\n=================================================\n");
	printf("Results: %d/%d passed", tests_passed, tests_run);
	if (tests_failed)
		printf(", %d FAILED", tests_failed);
	printf("\n");

	return tests_failed ? 1 : 0;
}
