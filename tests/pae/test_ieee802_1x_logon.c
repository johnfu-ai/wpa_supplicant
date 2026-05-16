/*
 * Test: ieee802_1x_logon_init / ieee802_1x_logon_deinit
 *
 * TDD Red phase — this test file must compile but the implementation
 * functions (ieee802_1x_logon_init, ieee802_1x_logon_deinit) do not
 * exist yet; linking will fail until Green phase.
 *
 * Verifies: #19 REQ-F-LOGON-001 (Logon Process state machine initialization)
 * See: IEEE 802.1X-2020, Clause 12
 *
 * Build (run from tests/pae/):
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Stubs for wpa_supplicant utilities used by ieee802_1x_logon.c.
 * The real declarations come from the included wpa_supplicant headers;
 * we provide the definitions here so we can link without the full build.
 */

/*
 * utils/includes.h must come first — brings in stdbool.h and other
 * system headers that common.h and os.h depend on.
 */
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"

/*
 * os_zalloc stub — satisfies linker without os_unix.o.
 * os_free is a macro (free((p))) in os.h, so no stub needed.
 */
void *os_zalloc(size_t size) { return calloc(1, size); }

/* wpa_printf stub — suppress output during unit tests */
void wpa_printf(int level, const char *fmt, ...)
{
	(void)level;
	(void)fmt;
}

/* Component under test */
#include "pae/ieee802_1x_logon.h"

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

/* ------------------------------------------------------------------ */
/* Mock callbacks — record whether they were called                     */
/* ------------------------------------------------------------------ */

static int mock_logon_connect_called;
static int mock_logon_disconnect_called;
static int mock_cp_connect_authenticated_called;
static int mock_cp_connect_unauthenticated_called;
static int mock_cp_connect_secure_called;
static int mock_cp_connect_pending_called;

static void mock_logon_connect(void *ctx) {
	(void)ctx;
	mock_logon_connect_called = 1;
}

static void mock_logon_disconnect(void *ctx) {
	(void)ctx;
	mock_logon_disconnect_called = 1;
}
static void mock_cp_connect_authenticated(void *ctx)  { (void)ctx; mock_cp_connect_authenticated_called = 1; }
static void mock_cp_connect_secure(void *ctx)         { (void)ctx; mock_cp_connect_secure_called = 1; }
static void mock_cp_connect_pending(void *ctx)        { (void)ctx; mock_cp_connect_pending_called = 1; }
static void mock_cp_connect_unauthenticated(void *ctx){ (void)ctx; mock_cp_connect_unauthenticated_called = 1; }

static struct ieee802_1x_logon_ctx make_valid_ctx(void *opaque)
{
	struct ieee802_1x_logon_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.ctx                      = opaque;
	ctx.logon_connect            = mock_logon_connect;
	ctx.logon_disconnect         = mock_logon_disconnect;
	ctx.cp_connect_authenticated = mock_cp_connect_authenticated;
	ctx.cp_connect_secure        = mock_cp_connect_secure;
	ctx.cp_connect_pending       = mock_cp_connect_pending;
	ctx.cp_connect_unauthenticated = mock_cp_connect_unauthenticated;
	return ctx;
}

/* ------------------------------------------------------------------ */
/* Tests                                                                 */
/* ------------------------------------------------------------------ */

/*
 * TC-LOGON-INIT-001
 * Given a fully populated ctx, ieee802_1x_logon_init() returns non-NULL.
 *
 * Verifies: REQ-F-LOGON-001 (Logon Process SM can be instantiated)
 */
TEST(test_logon_init_valid_ctx_returns_nonnull)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx((void *)0xdeadbeef);
	struct ieee802_1x_logon *logon;

	logon = ieee802_1x_logon_init(&ctx);
	ASSERT_NOT_NULL(logon);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-LOGON-INIT-002
 * Given NULL ctx, ieee802_1x_logon_init() returns NULL.
 *
 * Verifies: REQ-F-LOGON-001 (guard: no SM created without a valid ctx)
 */
TEST(test_logon_init_null_ctx_returns_null)
{
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(NULL);
	ASSERT_NULL(logon);
}

/*
 * TC-LOGON-DEINIT-001
 * Calling ieee802_1x_logon_deinit(NULL) must not crash.
 *
 * Verifies: defensive programming — safe teardown path
 */
TEST(test_logon_deinit_null_is_safe)
{
	ieee802_1x_logon_deinit(NULL); /* must not crash */
}

/*
 * TC-LOGON-INIT-003
 * The state machine must start in LOGON_DISCONNECTED state.
 *
 * Verifies: REQ-F-LOGON-001 (initial state is DISCONNECTED per Clause 12)
 */
TEST(test_logon_init_initial_state_is_disconnected)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon;
	enum ieee802_1x_logon_state state;

	logon = ieee802_1x_logon_init(&ctx);
	ASSERT_NOT_NULL(logon);

	state = ieee802_1x_logon_get_state(logon);
	ASSERT_EQ(state, LOGON_DISCONNECTED);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-LOGON-INIT-004
 * The stored ctx pointer must equal the one supplied at init.
 *
 * Verifies: DI contract — callbacks are reachable from the SM (ADR-PAE-002 #35)
 */
TEST(test_logon_init_stores_ctx_pointer)
{
	int sentinel = 42;
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(&sentinel);
	struct ieee802_1x_logon *logon;

	logon = ieee802_1x_logon_init(&ctx);
	ASSERT_NOT_NULL(logon);

	/* The SM must store the ctx so it can invoke callbacks later */
	ASSERT_EQ(ieee802_1x_logon_get_ctx(logon), &ctx);

	ieee802_1x_logon_deinit(logon);
}

/* ------------------------------------------------------------------ */
/* port_enabled tests                                                    */
/* ------------------------------------------------------------------ */

/*
 * TC-PORT-ENABLE-001
 * port_enabled(true) on a DISCONNECTED SM must transition to LOGON state.
 *
 * Verifies: REQ-F-LOGON-003 (PACP authentication initiation)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_port_enabled_true_transitions_to_logon)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_DISCONNECTED);

	ieee802_1x_logon_port_enabled(logon, true);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-PORT-ENABLE-002
 * port_enabled(true) must invoke the logon_connect callback.
 *
 * Verifies: REQ-F-LOGON-003 (PACP authentication initiation via callback)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_port_enabled_true_calls_logon_connect)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	mock_logon_connect_called = 0;

	ieee802_1x_logon_port_enabled(logon, true);

	if (!mock_logon_connect_called)
		FAIL("logon_connect callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-PORT-ENABLE-003
 * port_enabled(false) from LOGON state must transition back to DISCONNECTED.
 *
 * Verifies: REQ-F-LOGON-003 (port teardown returns SM to DISCONNECTED)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_port_enabled_false_transitions_to_disconnected)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	ieee802_1x_logon_port_enabled(logon, false);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_DISCONNECTED);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-PORT-ENABLE-004
 * port_enabled(false) must invoke the logon_disconnect callback.
 *
 * Verifies: REQ-F-LOGON-003 (PACP termination via callback)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_port_enabled_false_calls_logon_disconnect)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);

	mock_logon_disconnect_called = 0;
	ieee802_1x_logon_port_enabled(logon, false);

	if (!mock_logon_disconnect_called)
		FAIL("logon_disconnect callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-PORT-ENABLE-005
 * port_enabled(NULL) must not crash.
 *
 * Verifies: defensive NULL guard
 */
TEST(test_port_enabled_null_is_safe)
{
	ieee802_1x_logon_port_enabled(NULL, true);  /* must not crash */
}

/* ------------------------------------------------------------------ */
/* auth_success tests                                                    */
/* ------------------------------------------------------------------ */

/*
 * TC-AUTH-SUCCESS-001
 * auth_success from LOGON state transitions to AUTHENTICATED.
 *
 * Verifies: #21 REQ-F-LOGON-003 (PACP authentication success state transition)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_auth_success_from_logon_transitions_to_authenticated)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	ieee802_1x_logon_auth_success(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_AUTHENTICATED);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-AUTH-SUCCESS-002
 * auth_success must invoke the cp_connect_authenticated callback.
 *
 * Verifies: #22 REQ-F-LOGON-004 (CP connectivity signalling on success)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_auth_success_calls_cp_connect_authenticated)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);

	mock_cp_connect_authenticated_called = 0;
	ieee802_1x_logon_auth_success(logon);

	if (!mock_cp_connect_authenticated_called)
		FAIL("cp_connect_authenticated callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/* ------------------------------------------------------------------ */
/* auth_failure tests                                                    */
/* ------------------------------------------------------------------ */

/*
 * TC-AUTH-FAILURE-001
 * auth_failure from LOGON state transitions to DISCONNECTED.
 *
 * Verifies: #21 REQ-F-LOGON-003 (PACP authentication failure state transition)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_auth_failure_from_logon_transitions_to_disconnected)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	ieee802_1x_logon_auth_failure(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_DISCONNECTED);

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-AUTH-FAILURE-002
 * auth_failure must invoke the logon_disconnect callback.
 *
 * Verifies: #21 REQ-F-LOGON-003 (PACP termination on failure)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_auth_failure_calls_logon_disconnect)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);

	mock_logon_disconnect_called = 0;
	ieee802_1x_logon_auth_failure(logon);

	if (!mock_logon_disconnect_called)
		FAIL("logon_disconnect callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-AUTH-FAILURE-003
 * auth_failure must invoke the cp_connect_unauthenticated callback.
 *
 * Verifies: #22 REQ-F-LOGON-004 (CP connectivity signalling on failure)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_auth_failure_calls_cp_connect_unauthenticated)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);

	mock_cp_connect_unauthenticated_called = 0;
	ieee802_1x_logon_auth_failure(logon);

	if (!mock_cp_connect_unauthenticated_called)
		FAIL("cp_connect_unauthenticated callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/* ------------------------------------------------------------------ */
/* NULL guard tests                                                      */
/* ------------------------------------------------------------------ */

/*
 * TC-AUTH-NULL-001
 * auth_success(NULL) and auth_failure(NULL) must not crash.
 *
 * Verifies: defensive NULL guard on auth entry points
 */
TEST(test_auth_null_is_safe)
{
	ieee802_1x_logon_auth_success(NULL);  /* must not crash */
	ieee802_1x_logon_auth_failure(NULL);  /* must not crash */
}

/* ------------------------------------------------------------------ */
/* SECURED state tests                                                   */
/* ------------------------------------------------------------------ */

/*
 * TC-SECURED-001
 * After auth_success, if cp_connect_secure is available, calling
 * ieee802_1x_logon_secured() transitions from AUTHENTICATED to SECURED.
 *
 * Verifies: #22 REQ-F-LOGON-004 (CP connectivity signalling — secure)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_secured_from_authenticated_transitions_to_secured)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	/* Drive to AUTHENTICATED */
	ieee802_1x_logon_port_enabled(logon, true);
	ieee802_1x_logon_auth_success(logon);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_AUTHENTICATED);

	/* Now MACsec key establishment succeeds */
	ieee802_1x_logon_secured(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_SECURED);
	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-SECURED-002
 * ieee802_1x_logon_secured() must invoke cp_connect_secure callback.
 *
 * Verifies: #22 REQ-F-LOGON-004 (CP secure connectivity signal)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_secured_calls_cp_connect_secure)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ieee802_1x_logon_auth_success(logon);

	mock_cp_connect_secure_called = 0;
	ieee802_1x_logon_secured(logon);

	if (!mock_cp_connect_secure_called)
		FAIL("cp_connect_secure callback was not called");

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-SECURED-003
 * ieee802_1x_logon_secured(NULL) must not crash.
 */
TEST(test_secured_null_is_safe)
{
	ieee802_1x_logon_secured(NULL);  /* must not crash */
}

/* ------------------------------------------------------------------ */
/* sm_step tests                                                         */
/* ------------------------------------------------------------------ */

/*
 * TC-SM-STEP-001
 * sm_step(NULL) must not crash.
 */
TEST(test_sm_step_null_is_safe)
{
	ieee802_1x_logon_sm_step(NULL);  /* must not crash */
}

/*
 * TC-SM-STEP-002
 * sm_step on a DISCONNECTED SM with port_enabled=false stays DISCONNECTED.
 */
TEST(test_sm_step_disconnected_stays_disconnected)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_DISCONNECTED);

	ieee802_1x_logon_sm_step(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_DISCONNECTED);
	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-SM-STEP-003
 * sm_step on a LOGON SM signals cp_connect_pending.
 *
 * Verifies: #22 REQ-F-LOGON-004 (CP pending signal during authentication)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_sm_step_logon_signals_cp_pending)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	mock_cp_connect_pending_called = 0;
	ieee802_1x_logon_sm_step(logon);

	if (!mock_cp_connect_pending_called)
		FAIL("cp_connect_pending was not called in LOGON sm_step");

	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-SM-STEP-004
 * sm_step on a LOGON SM transitions to AUTHENTICATING.
 *
 * Verifies: #19 REQ-F-LOGON-001 (state machine progression)
 * See: IEEE 802.1X-2020, Clause 12
 */
TEST(test_sm_step_logon_transitions_to_authenticating)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_LOGON);

	ieee802_1x_logon_sm_step(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_AUTHENTICATING);
	ieee802_1x_logon_deinit(logon);
}

/*
 * TC-SM-STEP-005
 * sm_step on AUTHENTICATED or SECURED SM is a no-op (stable states).
 */
TEST(test_sm_step_authenticated_is_stable)
{
	struct ieee802_1x_logon_ctx ctx = make_valid_ctx(NULL);
	struct ieee802_1x_logon *logon = ieee802_1x_logon_init(&ctx);

	ASSERT_NOT_NULL(logon);
	ieee802_1x_logon_port_enabled(logon, true);
	ieee802_1x_logon_auth_success(logon);
	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_AUTHENTICATED);

	ieee802_1x_logon_sm_step(logon);

	ASSERT_EQ(ieee802_1x_logon_get_state(logon), LOGON_AUTHENTICATED);
	ieee802_1x_logon_deinit(logon);
}

/* ------------------------------------------------------------------ */
/* Main                                                                  */
/* ------------------------------------------------------------------ */

int main(void)
{
	printf("ieee802_1x_logon — TDD unit tests\n");
	printf("================================================\n");

	RUN(test_logon_init_valid_ctx_returns_nonnull);
	RUN(test_logon_init_null_ctx_returns_null);
	RUN(test_logon_deinit_null_is_safe);
	RUN(test_logon_init_initial_state_is_disconnected);
	RUN(test_logon_init_stores_ctx_pointer);

	printf("-- port_enabled --\n");
	RUN(test_port_enabled_true_transitions_to_logon);
	RUN(test_port_enabled_true_calls_logon_connect);
	RUN(test_port_enabled_false_transitions_to_disconnected);
	RUN(test_port_enabled_false_calls_logon_disconnect);
	RUN(test_port_enabled_null_is_safe);

	printf("-- auth_success --\n");
	RUN(test_auth_success_from_logon_transitions_to_authenticated);
	RUN(test_auth_success_calls_cp_connect_authenticated);

	printf("-- auth_failure --\n");
	RUN(test_auth_failure_from_logon_transitions_to_disconnected);
	RUN(test_auth_failure_calls_logon_disconnect);
	RUN(test_auth_failure_calls_cp_connect_unauthenticated);

	printf("-- auth NULL guards --\n");
	RUN(test_auth_null_is_safe);

	printf("-- secured (MACsec) --\n");
	RUN(test_secured_from_authenticated_transitions_to_secured);
	RUN(test_secured_calls_cp_connect_secure);
	RUN(test_secured_null_is_safe);

	printf("-- sm_step --\n");
	RUN(test_sm_step_null_is_safe);
	RUN(test_sm_step_disconnected_stays_disconnected);
	RUN(test_sm_step_logon_signals_cp_pending);
	RUN(test_sm_step_logon_transitions_to_authenticating);
	RUN(test_sm_step_authenticated_is_stable);

	printf("------------------------------------------------\n");
	printf("Results: %d/%d passed", tests_passed, tests_run);
	if (tests_failed)
		printf(", %d FAILED", tests_failed);
	printf("\n");

	return tests_failed ? 1 : 0;
}
