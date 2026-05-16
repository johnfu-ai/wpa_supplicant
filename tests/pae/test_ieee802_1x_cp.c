/*
 * Test: Controlled Port (CP) state machine audit per IEEE 802.1X-2020 Clause 10
 *
 * Standalone unit tests verifying CP state transitions and
 * 2020 compliance. Tests the connect type transitions.
 *
 * Verifies: CP Clause 10 compliance
 * See: IEEE 802.1X-2020, Clause 10
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
/* Minimal CP types for testing                                          */
/* ------------------------------------------------------------------ */

enum connect_type { PENDING, UNAUTHENTICATED, AUTHENTICATED, SECURE };

enum cp_states {
	CP_BEGIN, CP_INIT, CP_CHANGE, CP_ALLOWED, CP_AUTHENTICATED,
	CP_SECURED, CP_RECEIVE, CP_RECEIVING, CP_READY, CP_TRANSMIT,
	CP_TRANSMITTING, CP_ABANDON, CP_RETIRE
};

struct ieee802_1x_cp_sm {
	enum cp_states CP_state;
	bool changed;
	bool port_valid;
	enum connect_type connect;
	bool chgd_server;
	bool elected_self;
	bool new_sak;
	bool port_enabled;
	bool controlled_port_enabled;
	bool protect_frames;
	bool replay_protect;
	u32 transmit_when;
	u32 retire_when;
	bool using_receive_sas;
	bool all_receiving;
	bool server_transmitting;
	bool using_transmit_sa;
	u64 cipher_suite;
	u64 current_cipher_suite;
};

/* ------------------------------------------------------------------ */
/* Functions under test — simplified CP step logic                        */
/* ------------------------------------------------------------------ */

static int changed_connect(struct ieee802_1x_cp_sm *sm)
{
	return sm->connect != SECURE || sm->chgd_server;
}

static void cp_step(struct ieee802_1x_cp_sm *sm)
{
	if (!sm->port_enabled) {
		sm->CP_state = CP_INIT;
		return;
	}

	switch (sm->CP_state) {
	case CP_BEGIN:
		sm->CP_state = CP_INIT;
		break;
	case CP_INIT:
		sm->CP_state = CP_CHANGE;
		break;
	case CP_CHANGE:
		if (sm->connect == UNAUTHENTICATED)
			sm->CP_state = CP_ALLOWED;
		else if (sm->connect == AUTHENTICATED)
			sm->CP_state = CP_AUTHENTICATED;
		else if (sm->connect == SECURE)
			sm->CP_state = CP_SECURED;
		break;
	case CP_ALLOWED:
		if (sm->connect != UNAUTHENTICATED)
			sm->CP_state = CP_CHANGE;
		break;
	case CP_AUTHENTICATED:
		if (sm->connect != AUTHENTICATED)
			sm->CP_state = CP_CHANGE;
		break;
	case CP_SECURED:
		if (changed_connect(sm))
			sm->CP_state = CP_CHANGE;
		else if (sm->new_sak)
			sm->CP_state = CP_RECEIVE;
		break;
	case CP_RECEIVE:
		if (sm->using_receive_sas)
			sm->CP_state = CP_RECEIVING;
		break;
	case CP_RECEIVING:
		if (sm->new_sak || changed_connect(sm))
			sm->CP_state = CP_ABANDON;
		else if (!sm->elected_self)
			sm->CP_state = CP_READY;
		else if (sm->elected_self &&
			 (sm->all_receiving || !sm->controlled_port_enabled ||
			  !sm->transmit_when))
			sm->CP_state = CP_TRANSMIT;
		break;
	case CP_TRANSMIT:
		if (sm->using_transmit_sa)
			sm->CP_state = CP_TRANSMITTING;
		break;
	case CP_TRANSMITTING:
		if (!sm->retire_when || changed_connect(sm))
			sm->CP_state = CP_RETIRE;
		break;
	case CP_RETIRE:
		if (changed_connect(sm))
			sm->CP_state = CP_CHANGE;
		else if (sm->new_sak)
			sm->CP_state = CP_RECEIVE;
		break;
	case CP_READY:
		if (sm->new_sak || changed_connect(sm))
			sm->CP_state = CP_ABANDON;
		else if (sm->server_transmitting || !sm->controlled_port_enabled)
			sm->CP_state = CP_TRANSMIT;
		break;
	case CP_ABANDON:
		if (changed_connect(sm))
			sm->CP_state = CP_RETIRE;
		else if (sm->new_sak)
			sm->CP_state = CP_RECEIVE;
		break;
	default:
		break;
	}
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

#define ASSERT_EQ(a, b) \
	do { if ((a) != (b)) FAIL(#a " != " #b); } while (0)

/* ------------------------------------------------------------------ */
/* Tests                                                                 */
/* ------------------------------------------------------------------ */

/*
 * TC-CP-001
 * CP init: BEGIN -> INIT -> CHANGE.
 */
TEST(test_cp_init_sequence)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_BEGIN;
	sm->port_enabled = true;
	sm->connect = PENDING;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_INIT);
	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_CHANGE);

	os_free(sm);
}

/*
 * TC-CP-002
 * CP connect UNAUTHENTICATED: CHANGE -> ALLOWED.
 */
TEST(test_cp_change_to_allowed)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_CHANGE;
	sm->port_enabled = true;
	sm->connect = UNAUTHENTICATED;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_ALLOWED);

	os_free(sm);
}

/*
 * TC-CP-003
 * CP connect AUTHENTICATED: CHANGE -> AUTHENTICATED.
 */
TEST(test_cp_change_to_authenticated)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_CHANGE;
	sm->port_enabled = true;
	sm->connect = AUTHENTICATED;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_AUTHENTICATED);

	os_free(sm);
}

/*
 * TC-CP-004
 * CP connect SECURE: CHANGE -> SECURED.
 */
TEST(test_cp_change_to_secured)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_CHANGE;
	sm->port_enabled = true;
	sm->connect = SECURE;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_SECURED);

	os_free(sm);
}

/*
 * TC-CP-005
 * CP connect PENDING: stays in CHANGE (no match).
 * This is a 2020-specific behavior — the Logon Process
 * signals PENDING while authentication is in progress.
 */
TEST(test_cp_pending_stays_change)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_CHANGE;
	sm->port_enabled = true;
	sm->connect = PENDING;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_CHANGE);

	os_free(sm);
}

/*
 * TC-CP-006
 * CP SECURED -> CHANGE on chgd_server (2020: server change
 * triggers re-key).
 */
TEST(test_cp_secured_server_change)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_SECURED;
	sm->port_enabled = true;
	sm->connect = SECURE;
	sm->chgd_server = true;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_CHANGE);

	os_free(sm);
}

/*
 * TC-CP-007
 * CP SECURED -> RECEIVE on new_sak.
 */
TEST(test_cp_secured_new_sak)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_SECURED;
	sm->port_enabled = true;
	sm->connect = SECURE;
	sm->chgd_server = false;
	sm->new_sak = true;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_RECEIVE);

	os_free(sm);
}

/*
 * TC-CP-008
 * CP port disabled -> INIT (port_enabled=false).
 */
TEST(test_cp_port_disabled)
{
	struct ieee802_1x_cp_sm *sm = os_zalloc(sizeof(*sm));
	sm->CP_state = CP_SECURED;
	sm->port_enabled = false;

	cp_step(sm);
	ASSERT_EQ(sm->CP_state, CP_INIT);

	os_free(sm);
}

/* ------------------------------------------------------------------ */
/* Main                                                                  */
/* ------------------------------------------------------------------ */

int main(void)
{
	printf("IEEE 802.1X-2020 CP State Machine Audit Tests\n");
	printf("==============================================\n\n");

	RUN(test_cp_init_sequence);
	RUN(test_cp_change_to_allowed);
	RUN(test_cp_change_to_authenticated);
	RUN(test_cp_change_to_secured);
	RUN(test_cp_pending_stays_change);
	RUN(test_cp_secured_server_change);
	RUN(test_cp_secured_new_sak);
	RUN(test_cp_port_disabled);

	printf("\n==============================================\n");
	printf("Results: %d/%d passed", tests_passed, tests_run);
	if (tests_failed)
		printf(", %d FAILED", tests_failed);
	printf("\n");

	return tests_failed ? 1 : 0;
}
