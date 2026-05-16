/*
 * wpas_logon - Bridge between Logon Process (Clause 12) and wpa_supplicant
 *
 * Implements: #9 REQ-F-PAE-005, #19 REQ-F-LOGON-001
 * Governed:   #35 ADR-PAE-002
 * See:        IEEE 802.1X-2020, Clause 12
 *
 * This module wires the abstract Logon Process SM callbacks
 * to concrete wpa_supplicant, PACP, and KaY functions.
 * Guarded by #ifdef CONFIG_IEEE8021X_2020_LOGON.
 */

#ifndef WPAS_LOGON_H
#define WPAS_LOGON_H

#ifdef CONFIG_IEEE8021X_2020_LOGON

struct wpa_supplicant;

/**
 * wpas_logon_init - Initialize Logon Process for a wpa_supplicant interface
 * @wpa_s: wpa_supplicant context
 * Returns: 0 on success, -1 on failure
 *
 * Creates the Logon Process SM, wires callbacks to concrete functions,
 * and registers the logon_if with the EAPOL state machine.
 */
int wpas_logon_init(struct wpa_supplicant *wpa_s);

/**
 * wpas_logon_deinit - Deinitialize Logon Process for a wpa_supplicant interface
 * @wpa_s: wpa_supplicant context
 */
void wpas_logon_deinit(struct wpa_supplicant *wpa_s);

/**
 * wpas_logon_notify_port_enabled - Notify Logon Process of port status change
 * @wpa_s: wpa_supplicant context
 * @enabled: True if port is enabled
 */
void wpas_logon_notify_port_enabled(struct wpa_supplicant *wpa_s,
				     bool enabled);

/**
 * wpas_logon_notify_auth_result - Notify Logon Process of auth result
 * @wpa_s: wpa_supplicant context
 * @success: True if authentication succeeded
 */
void wpas_logon_notify_auth_result(struct wpa_supplicant *wpa_s,
				    bool success);

/**
 * wpas_logon_notify_secured - Notify Logon Process that MACsec is secured
 * @wpa_s: wpa_supplicant context
 */
void wpas_logon_notify_secured(struct wpa_supplicant *wpa_s);

#endif /* CONFIG_IEEE8021X_2020_LOGON */

#endif /* WPAS_LOGON_H */
