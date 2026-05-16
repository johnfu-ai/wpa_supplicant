/*
 * IEEE 802.1X-2020 Logon Process state machine
 *
 * Implements IEEE 802.1X-2020 Clause 12 — Logon Process.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Note: This implementation is based on understanding of the IEEE 802.1X-2020
 * specification. No copyrighted content from the standard is reproduced.
 *
 * Implements: #19 REQ-F-LOGON-001 (Logon Process state machine per Clause 12)
 * Implements: #20 REQ-F-LOGON-002 (NID selection — stub for Wave 1)
 * Implements: #21 REQ-F-LOGON-003 (PACP authentication initiation)
 * Implements: #22 REQ-F-LOGON-004 (CP connectivity signalling)
 * See: ADR-LOGON-001 (#37), ADR-PAE-002 (#35)
 */

#ifdef CONFIG_IEEE8021X_2020_LOGON

#include "utils/includes.h"
#include "utils/common.h"
#include "ieee802_1x_logon.h"

/**
 * struct ieee802_1x_logon - Logon Process state machine (opaque to callers)
 *
 * Per IEEE 802.1X-2020 Clause 12 — Logon Process.
 * All fields are private; callers use the accessor functions.
 */
struct ieee802_1x_logon {
	struct ieee802_1x_logon_ctx *ctx;
	enum ieee802_1x_logon_state state;
	bool port_enabled;
};


/**
 * ieee802_1x_logon_init - Initialize the Logon Process state machine
 * @ctx: Dependency-injection context; must not be NULL.
 * Returns: Pointer to state machine, or NULL on failure.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — Logon Process initialization.
 *
 * @implements #19 REQ-F-LOGON-001: Logon Process state machine per Clause 12
 * @see ADR-LOGON-001 (#37)
 */
struct ieee802_1x_logon *
ieee802_1x_logon_init(struct ieee802_1x_logon_ctx *ctx)
{
	struct ieee802_1x_logon *logon;

	if (!ctx) {
		wpa_printf(MSG_ERROR, "LOGON: ctx must not be NULL");
		return NULL;
	}

	logon = os_zalloc(sizeof(*logon));
	if (!logon)
		return NULL;

	/* IEEE 802.1X-2020 Clause 12 — initialize Logon Process state */
	logon->ctx   = ctx;
	logon->state = LOGON_DISCONNECTED;

	wpa_printf(MSG_DEBUG, "LOGON: initialized (state=DISCONNECTED)");
	return logon;
}


/**
 * ieee802_1x_logon_deinit - Free the Logon Process state machine
 * @logon: State machine pointer; no-op if NULL.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — Logon Process teardown.
 */
void ieee802_1x_logon_deinit(struct ieee802_1x_logon *logon)
{
	/* IEEE 802.1X-2020 Clause 12 — release Logon Process resources */
	if (!logon)
		return;
	os_free(logon);
}


/**
 * ieee802_1x_logon_sm_step - Run one step of the Logon Process state machine
 * @logon: State machine pointer.
 *
 * Evaluates state transitions per IEEE 802.1X-2020 Clause 12.
 * In LOGON state: signals CP pending and transitions to AUTHENTICATING.
 * AUTHENTICATED and SECURED are stable states (no automatic transition).
 * DISCONNECTED is idle (no action).
 *
 * @implements #19 REQ-F-LOGON-001: Logon Process state machine step
 * @implements #22 REQ-F-LOGON-004: CP connectivity signalling — pending
 */
void ieee802_1x_logon_sm_step(struct ieee802_1x_logon *logon)
{
	if (!logon)
		return;

	switch (logon->state) {
	case LOGON_LOGON:
		/* IEEE 802.1X-2020 Clause 12 — LOGON: signal pending, advance */
		if (logon->ctx->cp_connect_pending)
			logon->ctx->cp_connect_pending(logon->ctx->ctx);
		logon->state = LOGON_AUTHENTICATING;
		wpa_printf(MSG_DEBUG, "LOGON: sm_step LOGON -> AUTHENTICATING");
		break;
	case LOGON_AUTHENTICATING:
		/* Waiting for auth_success or auth_failure event — no auto transition */
		break;
	case LOGON_AUTHENTICATED:
	case LOGON_SECURED:
	case LOGON_DISCONNECTED:
		/* Stable states — no automatic transition */
		break;
	}
}


/**
 * ieee802_1x_logon_port_enabled - Notify of port enable/disable event
 * @logon: State machine pointer.
 * @enabled: true if the physical port is operationally up.
 *
 * When the port becomes enabled the Logon Process transitions to the LOGON
 * state and signals PACP to begin authentication.  When the port is disabled
 * the process tears down and returns to DISCONNECTED.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — Logon Process port events.
 */
void ieee802_1x_logon_port_enabled(struct ieee802_1x_logon *logon,
				    bool enabled)
{
	if (!logon)
		return;

	logon->port_enabled = enabled;

	if (enabled) {
		/* IEEE 802.1X-2020 Clause 12 — port up: begin logon */
		wpa_printf(MSG_DEBUG, "LOGON: port enabled -> LOGON");
		logon->state = LOGON_LOGON;
		if (logon->ctx->logon_connect)
			logon->ctx->logon_connect(logon->ctx->ctx);
	} else {
		/* IEEE 802.1X-2020 Clause 12 — port down: disconnect */
		wpa_printf(MSG_DEBUG, "LOGON: port disabled -> DISCONNECTED");
		if (logon->ctx->logon_disconnect)
			logon->ctx->logon_disconnect(logon->ctx->ctx);
		logon->state = LOGON_DISCONNECTED;
	}
}


/**
 * ieee802_1x_logon_auth_success - Notify of PACP authentication success
 * @logon: State machine pointer.
 *
 * When the Logon Process is in LOGON or AUTHENTICATING state, a successful
 * PACP authentication transitions the SM to AUTHENTICATED and signals CP
 * to set port connectivity to AUTHENTICATED.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — auth success notification.
 *
 * @implements #21 REQ-F-LOGON-003: PACP authentication success handling
 * @implements #22 REQ-F-LOGON-004: CP connectivity signalling on success
 * @see ADR-LOGON-001 (#37)
 */
void ieee802_1x_logon_auth_success(struct ieee802_1x_logon *logon)
{
	if (!logon)
		return;

	/* IEEE 802.1X-2020 Clause 12 — auth success transitions */
	if (logon->state == LOGON_LOGON ||
	    logon->state == LOGON_AUTHENTICATING) {
		wpa_printf(MSG_DEBUG,
			   "LOGON: auth success -> AUTHENTICATED (from state %d)",
			   logon->state);
		logon->state = LOGON_AUTHENTICATED;
		if (logon->ctx->cp_connect_authenticated)
			logon->ctx->cp_connect_authenticated(logon->ctx->ctx);
	}
}


/**
 * ieee802_1x_logon_auth_failure - Notify of PACP authentication failure
 * @logon: State machine pointer.
 *
 * When the Logon Process is not in DISCONNECTED state, an authentication
 * failure tears down the session: PACP is signalled to disconnect, CP is
 * signalled to set port connectivity to UNAUTHENTICATED, and the SM
 * transitions to DISCONNECTED.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — auth failure notification.
 *
 * @implements #21 REQ-F-LOGON-003: PACP authentication failure handling
 * @implements #22 REQ-F-LOGON-004: CP connectivity signalling on failure
 * @see ADR-LOGON-001 (#37)
 */
void ieee802_1x_logon_auth_failure(struct ieee802_1x_logon *logon)
{
	if (!logon)
		return;

	/* IEEE 802.1X-2020 Clause 12 — auth failure teardown */
	if (logon->state != LOGON_DISCONNECTED) {
		wpa_printf(MSG_DEBUG,
			   "LOGON: auth failure -> DISCONNECTED (from state %d)",
			   logon->state);
		if (logon->ctx->logon_disconnect)
			logon->ctx->logon_disconnect(logon->ctx->ctx);
		if (logon->ctx->cp_connect_unauthenticated)
			logon->ctx->cp_connect_unauthenticated(
				logon->ctx->ctx);
		logon->state = LOGON_DISCONNECTED;
	}
}


/**
 * ieee802_1x_logon_secured - Notify that MACsec key establishment is complete
 * @logon: State machine pointer.
 *
 * When in AUTHENTICATED state, transitions to SECURED and signals CP
 * to set port connectivity to SECURE. Per IEEE 802.1X-2020 Clause 12.
 *
 * @implements #22 REQ-F-LOGON-004: CP connectivity signalling — secure
 */
void ieee802_1x_logon_secured(struct ieee802_1x_logon *logon)
{
	if (!logon)
		return;

	/* IEEE 802.1X-2020 Clause 12 — MACsec established */
	if (logon->state == LOGON_AUTHENTICATED) {
		wpa_printf(MSG_DEBUG, "LOGON: secured -> SECURED");
		logon->state = LOGON_SECURED;
		if (logon->ctx->cp_connect_secure)
			logon->ctx->cp_connect_secure(logon->ctx->ctx);
	}
}


/**
 * ieee802_1x_logon_get_state - Return current Logon Process state
 * @logon: State machine pointer.
 * Returns: Current state enum value.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — state query accessor.
 */
enum ieee802_1x_logon_state
ieee802_1x_logon_get_state(const struct ieee802_1x_logon *logon)
{
	/* IEEE 802.1X-2020 Clause 12 — query current Logon Process state */
	return logon->state;
}


/**
 * ieee802_1x_logon_get_ctx - Return stored DI context pointer
 * @logon: State machine pointer.
 * Returns: The ieee802_1x_logon_ctx pointer passed to ieee802_1x_logon_init().
 *
 * Note: Per ADR-PAE-002 (#35) — DI context accessor for testing.
 */
struct ieee802_1x_logon_ctx *
ieee802_1x_logon_get_ctx(const struct ieee802_1x_logon *logon)
{
	/* IEEE 802.1X-2020 Clause 12 — return DI context pointer */
	return logon->ctx;
}

#endif /* CONFIG_IEEE8021X_2020_LOGON */
