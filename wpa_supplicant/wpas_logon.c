/*
 * wpas_logon - Bridge between Logon Process (Clause 12) and wpa_supplicant
 *
 * Implements: #9 REQ-F-PAE-005, #19 REQ-F-LOGON-001
 * Governed:   #35 ADR-PAE-002
 * See:        IEEE 802.1X-2020, Clause 12
 */

#include "includes.h"
#include "common.h"
#include "wpa_supplicant_i.h"
#include "pae/ieee802_1x_logon.h"
#include "eapol_supp/eapol_supp_sm.h"
#include "wpas_logon.h"

#ifdef CONFIG_IEEE8021X_2020_LOGON

/*
 * Concrete callback implementations for the Logon Process SM.
 * These bridge the abstract function-pointer interface to
 * the actual wpa_supplicant / PACP / KaY functions.
 */

static void wpas_logon_connect_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "LOGON: connect -> eapol_sm_notify_portEnabled");
	if (wpa_s->eapol)
		eapol_sm_notify_portEnabled(wpa_s->eapol, true);
}


static void wpas_logon_disconnect_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "LOGON: disconnect -> eapol_sm_notify_portEnabled(false)");
	if (wpa_s->eapol)
		eapol_sm_notify_portEnabled(wpa_s->eapol, false);
}


static void wpas_cp_connect_authenticated_cb(void *ctx)
{
	(void)ctx;
	wpa_printf(MSG_DEBUG, "LOGON: cp_connect_authenticated");
}


static void wpas_cp_connect_secure_cb(void *ctx)
{
	(void)ctx;
	wpa_printf(MSG_DEBUG, "LOGON: cp_connect_secure (MACsec established)");
}


static void wpas_cp_connect_pending_cb(void *ctx)
{
	(void)ctx;
	wpa_printf(MSG_DEBUG, "LOGON: cp_connect_pending (auth in progress)");
}


static void wpas_cp_connect_unauthenticated_cb(void *ctx)
{
	(void)ctx;
	wpa_printf(MSG_DEBUG, "LOGON: cp_connect_unauthenticated");
}


/*
 * PACP auth_success callback — called from eapol_sm_set_port_authorized
 * via the logon_if interface.
 */
static void wpas_pacp_auth_success_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "LOGON: PACP auth_success");
	ieee802_1x_logon_auth_success(wpa_s->logon);
}


/*
 * PACP auth_failure callback — called from eapol_sm_set_port_unauthorized
 * via the logon_if interface.
 */
static void wpas_pacp_auth_failure_cb(void *ctx)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_printf(MSG_DEBUG, "LOGON: PACP auth_failure");
	ieee802_1x_logon_auth_failure(wpa_s->logon);
}


int wpas_logon_init(struct wpa_supplicant *wpa_s)
{
	struct ieee802_1x_logon_ctx logon_ctx;
	struct ieee802_1x_pacp_logon_if logon_if;

	if (!wpa_s)
		return -1;

	os_memset(&logon_ctx, 0, sizeof(logon_ctx));
	logon_ctx.ctx = wpa_s;
	logon_ctx.logon_connect = wpas_logon_connect_cb;
	logon_ctx.logon_disconnect = wpas_logon_disconnect_cb;
	logon_ctx.cp_connect_authenticated = wpas_cp_connect_authenticated_cb;
	logon_ctx.cp_connect_secure = wpas_cp_connect_secure_cb;
	logon_ctx.cp_connect_pending = wpas_cp_connect_pending_cb;
	logon_ctx.cp_connect_unauthenticated = wpas_cp_connect_unauthenticated_cb;

	wpa_s->logon = ieee802_1x_logon_init(&logon_ctx);
	if (!wpa_s->logon) {
		wpa_printf(MSG_ERROR, "LOGON: Failed to initialize Logon Process");
		return -1;
	}

	/* Register PACP logon_if with EAPOL SM */
	if (wpa_s->eapol) {
		os_memset(&logon_if, 0, sizeof(logon_if));
		logon_if.ctx = wpa_s;
		logon_if.auth_success = wpas_pacp_auth_success_cb;
		logon_if.auth_failure = wpas_pacp_auth_failure_cb;
		eapol_sm_set_logon_if(wpa_s->eapol, &logon_if);
	}

	wpa_printf(MSG_DEBUG, "LOGON: initialized");
	return 0;
}


void wpas_logon_deinit(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s)
		return;

	if (wpa_s->eapol)
		eapol_sm_set_logon_if(wpa_s->eapol, NULL);

	ieee802_1x_logon_deinit(wpa_s->logon);
	wpa_s->logon = NULL;
	wpa_printf(MSG_DEBUG, "LOGON: deinitialized");
}


void wpas_logon_notify_port_enabled(struct wpa_supplicant *wpa_s,
				     bool enabled)
{
	if (!wpa_s || !wpa_s->logon)
		return;

	ieee802_1x_logon_port_enabled(wpa_s->logon, enabled);
}


void wpas_logon_notify_auth_result(struct wpa_supplicant *wpa_s,
				    bool success)
{
	if (!wpa_s || !wpa_s->logon)
		return;

	if (success)
		ieee802_1x_logon_auth_success(wpa_s->logon);
	else
		ieee802_1x_logon_auth_failure(wpa_s->logon);
}


void wpas_logon_notify_secured(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s || !wpa_s->logon)
		return;

	ieee802_1x_logon_secured(wpa_s->logon);
}

#endif /* CONFIG_IEEE8021X_2020_LOGON */
