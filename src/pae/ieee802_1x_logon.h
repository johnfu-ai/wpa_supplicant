/*
 * IEEE 802.1X-2020 Logon Process state machine
 *
 * Implements IEEE 802.1X-2020 Clause 12 — Logon Process.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Note: This implementation is based on understanding of IEEE 802.1X-2020
 * specification. No copyrighted content from the standard is reproduced.
 */

#ifndef IEEE802_1X_LOGON_H
#define IEEE802_1X_LOGON_H

#include <stdbool.h>
#include "common/defs.h"
#include "common/ieee802_1x_defs.h"

struct ieee802_1x_logon;
struct ieee802_1x_mka_sci;
struct mka_key_name;
struct mka_key;
enum mka_created_mode;

/**
 * enum ieee802_1x_logon_state - Logon Process connectivity states
 *
 * Per IEEE 802.1X-2020 Clause 12 Logon Process state machine.
 */
enum ieee802_1x_logon_state {
	LOGON_DISCONNECTED,
	LOGON_LOGON,
	LOGON_AUTHENTICATING,
	LOGON_AUTHENTICATED,
	LOGON_SECURED,
};

/**
 * struct ieee802_1x_logon_ctx - Dependency-injection context for Logon Process
 *
 * All cross-component calls go through these function pointers.
 * Concrete implementations are wired in wpa_supplicant/wpas_logon.c.
 * Per ADR-PAE-002 (#35) — function-pointer DI pattern.
 */
struct ieee802_1x_logon_ctx {
	/** Caller-supplied opaque context pointer, passed back to all callbacks */
	void *ctx;

	/** Signal PACP to initiate authentication for the selected NID */
	void (*logon_connect)(void *ctx);

	/** Signal PACP to terminate authentication */
	void (*logon_disconnect)(void *ctx);

	/** Signal CP to set port connectivity to AUTHENTICATED */
	void (*cp_connect_authenticated)(void *ctx);

	/** Signal CP to set port connectivity to SECURE */
	void (*cp_connect_secure)(void *ctx);

	/** Signal CP to set port connectivity to PENDING */
	void (*cp_connect_pending)(void *ctx);

	/** Signal CP to set port connectivity to UNAUTHENTICATED */
	void (*cp_connect_unauthenticated)(void *ctx);
};

/**
 * ieee802_1x_logon_init - Initialize the Logon Process state machine
 * @ctx: Dependency-injection context with all inter-SM callbacks populated.
 *       Must not be NULL.
 * Returns: Pointer to Logon Process state machine, or NULL on failure.
 *
 * Note: Implements IEEE 802.1X-2020 Clause 12 — Logon Process initialization.
 *
 * @implements #19 REQ-F-LOGON-001: Logon Process state machine per Clause 12
 * @see ADR-LOGON-001 (#37)
 */
struct ieee802_1x_logon *
ieee802_1x_logon_init(struct ieee802_1x_logon_ctx *ctx);

/**
 * ieee802_1x_logon_deinit - Deinitialize and free the Logon Process SM
 * @logon: State machine pointer; no-op if NULL.
 */
void ieee802_1x_logon_deinit(struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_sm_step - Run one step of the Logon Process state machine
 * @logon: State machine pointer.
 *
 * Called by the event loop on each relevant event.
 */
void ieee802_1x_logon_sm_step(struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_port_enabled - Notify the Logon Process of port enable/disable
 * @logon: State machine pointer.
 * @enabled: true if the physical port is operationally up.
 */
void ieee802_1x_logon_port_enabled(struct ieee802_1x_logon *logon,
				    bool enabled);

/**
 * ieee802_1x_logon_auth_success - Notify Logon Process of PACP authentication success
 * @logon: State machine pointer.
 */
void ieee802_1x_logon_auth_success(struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_auth_failure - Notify Logon Process of PACP authentication failure
 * @logon: State machine pointer.
 */
void ieee802_1x_logon_auth_failure(struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_secured - Notify Logon Process that MACsec is now established
 * @logon: State machine pointer.
 *
 * Transitions from AUTHENTICATED to SECURED and signals CP to set port
 * connectivity to SECURE. Per IEEE 802.1X-2020 Clause 12.
 *
 * @implements #22 REQ-F-LOGON-004: CP connectivity signalling — secure
 */
void ieee802_1x_logon_secured(struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_get_state - Return current Logon Process state (for testing)
 * @logon: State machine pointer.
 * Returns: Current state enum value.
 */
enum ieee802_1x_logon_state
ieee802_1x_logon_get_state(const struct ieee802_1x_logon *logon);

/**
 * ieee802_1x_logon_get_ctx - Return stored ctx pointer (for testing)
 * @logon: State machine pointer.
 * Returns: The ieee802_1x_logon_ctx pointer passed to ieee802_1x_logon_init().
 */
struct ieee802_1x_logon_ctx *
ieee802_1x_logon_get_ctx(const struct ieee802_1x_logon *logon);

#endif /* IEEE802_1X_LOGON_H */
