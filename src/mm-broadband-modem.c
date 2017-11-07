/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details:
 *
 * Copyright (C) 2008 - 2009 Novell, Inc.
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 * Copyright (C) 2011 - 2012 Google, Inc.
 * Copyright (C) 2015 - Marco Bascetta <marco.bascetta@sadel.it>
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

#include <ModemManager.h>
#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-base-modem-at.h"
#include "mm-broadband-modem.h"
#include "mm-iface-modem.h"
#include "mm-iface-modem-3gpp.h"
#include "mm-iface-modem-3gpp-ussd.h"
#include "mm-iface-modem-cdma.h"
#include "mm-iface-modem-simple.h"
#include "mm-iface-modem-location.h"
#include "mm-iface-modem-messaging.h"
#include "mm-iface-modem-voice.h"
#include "mm-iface-modem-time.h"
#include "mm-iface-modem-firmware.h"
#include "mm-iface-modem-signal.h"
#include "mm-iface-modem-oma.h"
#include "mm-broadband-bearer.h"
#include "mm-bearer-list.h"
#include "mm-sms-list.h"
#include "mm-sms-part-3gpp.h"
#include "mm-call-list.h"
#include "mm-base-sim.h"
#include "mm-log.h"
#include "mm-modem-helpers.h"
#include "mm-error-helpers.h"
#include "mm-port-serial-qcdm.h"
#include "libqcdm/src/errors.h"
#include "libqcdm/src/commands.h"
#include "libqcdm/src/logs.h"
#include "libqcdm/src/log-items.h"
#include "mm-helper-enums-types.h"

static void iface_modem_init (MMIfaceModem *iface);
static void iface_modem_3gpp_init (MMIfaceModem3gpp *iface);
static void iface_modem_3gpp_ussd_init (MMIfaceModem3gppUssd *iface);
static void iface_modem_cdma_init (MMIfaceModemCdma *iface);
static void iface_modem_simple_init (MMIfaceModemSimple *iface);
static void iface_modem_location_init (MMIfaceModemLocation *iface);
static void iface_modem_messaging_init (MMIfaceModemMessaging *iface);
static void iface_modem_voice_init (MMIfaceModemVoice *iface);
static void iface_modem_time_init (MMIfaceModemTime *iface);
static void iface_modem_signal_init (MMIfaceModemSignal *iface);
static void iface_modem_oma_init (MMIfaceModemOma *iface);
static void iface_modem_firmware_init (MMIfaceModemFirmware *iface);

G_DEFINE_TYPE_EXTENDED (MMBroadbandModem, mm_broadband_modem, MM_TYPE_BASE_MODEM, 0,
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM, iface_modem_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_3GPP, iface_modem_3gpp_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_3GPP_USSD, iface_modem_3gpp_ussd_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_CDMA, iface_modem_cdma_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_SIMPLE, iface_modem_simple_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_LOCATION, iface_modem_location_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_MESSAGING, iface_modem_messaging_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_VOICE, iface_modem_voice_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_TIME, iface_modem_time_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_SIGNAL, iface_modem_signal_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_OMA, iface_modem_oma_init)
                        G_IMPLEMENT_INTERFACE (MM_TYPE_IFACE_MODEM_FIRMWARE, iface_modem_firmware_init))

enum {
    PROP_0,
    PROP_MODEM_DBUS_SKELETON,
    PROP_MODEM_3GPP_DBUS_SKELETON,
    PROP_MODEM_3GPP_USSD_DBUS_SKELETON,
    PROP_MODEM_CDMA_DBUS_SKELETON,
    PROP_MODEM_SIMPLE_DBUS_SKELETON,
    PROP_MODEM_LOCATION_DBUS_SKELETON,
    PROP_MODEM_MESSAGING_DBUS_SKELETON,
    PROP_MODEM_VOICE_DBUS_SKELETON,
    PROP_MODEM_TIME_DBUS_SKELETON,
    PROP_MODEM_SIGNAL_DBUS_SKELETON,
    PROP_MODEM_OMA_DBUS_SKELETON,
    PROP_MODEM_FIRMWARE_DBUS_SKELETON,
    PROP_MODEM_SIM,
    PROP_MODEM_BEARER_LIST,
    PROP_MODEM_STATE,
    PROP_MODEM_3GPP_REGISTRATION_STATE,
    PROP_MODEM_3GPP_CS_NETWORK_SUPPORTED,
    PROP_MODEM_3GPP_PS_NETWORK_SUPPORTED,
    PROP_MODEM_3GPP_EPS_NETWORK_SUPPORTED,
    PROP_MODEM_3GPP_IGNORED_FACILITY_LOCKS,
    PROP_MODEM_CDMA_CDMA1X_REGISTRATION_STATE,
    PROP_MODEM_CDMA_EVDO_REGISTRATION_STATE,
    PROP_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED,
    PROP_MODEM_CDMA_EVDO_NETWORK_SUPPORTED,
    PROP_MODEM_MESSAGING_SMS_LIST,
    PROP_MODEM_MESSAGING_SMS_PDU_MODE,
    PROP_MODEM_MESSAGING_SMS_DEFAULT_STORAGE,
    PROP_MODEM_VOICE_CALL_LIST,
    PROP_MODEM_SIMPLE_STATUS,
    PROP_MODEM_SIM_HOT_SWAP_SUPPORTED,
    PROP_MODEM_SIM_HOT_SWAP_CONFIGURED,
    PROP_FLOW_CONTROL,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

/* When CIND is supported, invalid indicators are marked with this value */
#define CIND_INDICATOR_INVALID 255
#define CIND_INDICATOR_IS_VALID(u) (u != CIND_INDICATOR_INVALID)

typedef struct _PortsContext PortsContext;

struct _MMBroadbandModemPrivate {
    /* Broadband modem specific implementation */
    PortsContext *enabled_ports_ctx;
    PortsContext *sim_hot_swap_ports_ctx;
    gboolean modem_init_run;
    gboolean sim_hot_swap_supported;
    gboolean sim_hot_swap_configured;

    /*<--- Modem interface --->*/
    /* Properties */
    GObject *modem_dbus_skeleton;
    MMBaseSim *modem_sim;
    MMBearerList *modem_bearer_list;
    MMModemState modem_state;
    /* Implementation helpers */
    MMModemCharset modem_current_charset;
    gboolean modem_cind_support_checked;
    gboolean modem_cind_supported;
    guint modem_cind_indicator_signal_quality;
    guint modem_cind_min_signal_quality;
    guint modem_cind_max_signal_quality;
    guint modem_cind_indicator_roaming;
    guint modem_cind_indicator_service;
    MM3gppCmerMode modem_cmer_enable_mode;
    MM3gppCmerMode modem_cmer_disable_mode;
    MM3gppCmerInd modem_cmer_ind;
    MMFlowControl flow_control;

    /*<--- Modem 3GPP interface --->*/
    /* Properties */
    GObject *modem_3gpp_dbus_skeleton;
    MMModem3gppRegistrationState modem_3gpp_registration_state;
    gboolean modem_3gpp_cs_network_supported;
    gboolean modem_3gpp_ps_network_supported;
    gboolean modem_3gpp_eps_network_supported;
    /* Implementation helpers */
    GPtrArray *modem_3gpp_registration_regex;
    MMModem3gppFacility modem_3gpp_ignored_facility_locks;

    /*<--- Modem 3GPP USSD interface --->*/
    /* Properties */
    GObject *modem_3gpp_ussd_dbus_skeleton;
    /* Implementation helpers */
    gboolean use_unencoded_ussd;
    GSimpleAsyncResult *pending_ussd_action;

    /*<--- Modem CDMA interface --->*/
    /* Properties */
    GObject *modem_cdma_dbus_skeleton;
    MMModemCdmaRegistrationState modem_cdma_cdma1x_registration_state;
    MMModemCdmaRegistrationState modem_cdma_evdo_registration_state;
    gboolean modem_cdma_cdma1x_network_supported;
    gboolean modem_cdma_evdo_network_supported;
    GCancellable *modem_cdma_pending_registration_cancellable;
    /* Implementation helpers */
    gboolean checked_sprint_support;
    gboolean has_spservice;
    gboolean has_speri;
    gint evdo_pilot_rssi;

    /*<--- Modem Simple interface --->*/
    /* Properties */
    GObject *modem_simple_dbus_skeleton;
    MMSimpleStatus *modem_simple_status;

    /*<--- Modem Location interface --->*/
    /* Properties */
    GObject *modem_location_dbus_skeleton;

    /*<--- Modem Messaging interface --->*/
    /* Properties */
    GObject *modem_messaging_dbus_skeleton;
    MMSmsList *modem_messaging_sms_list;
    gboolean modem_messaging_sms_pdu_mode;
    MMSmsStorage modem_messaging_sms_default_storage;
    /* Implementation helpers */
    gboolean sms_supported_modes_checked;
    gboolean mem1_storage_locked;
    MMSmsStorage current_sms_mem1_storage;
    gboolean mem2_storage_locked;
    MMSmsStorage current_sms_mem2_storage;

    /*<--- Modem Voice interface --->*/
    /* Properties */
    GObject *modem_voice_dbus_skeleton;
    MMCallList *modem_voice_call_list;

    /*<--- Modem Time interface --->*/
    /* Properties */
    GObject *modem_time_dbus_skeleton;

    /*<--- Modem Signal interface --->*/
    /* Properties */
    GObject *modem_signal_dbus_skeleton;

    /*<--- Modem OMA interface --->*/
    /* Properties */
    GObject *modem_oma_dbus_skeleton;

    /*<--- Modem Firmware interface --->*/
    /* Properties */
    GObject *modem_firmware_dbus_skeleton;
};

/*****************************************************************************/

static gboolean
response_processor_string_ignore_at_errors (MMBaseModem *self,
                                            gpointer none,
                                            const gchar *command,
                                            const gchar *response,
                                            gboolean last_command,
                                            const GError *error,
                                            GVariant **result,
                                            GError **result_error)
{
    if (error) {
        /* Ignore AT errors (ie, ERROR or CMx ERROR) */
        if (error->domain != MM_MOBILE_EQUIPMENT_ERROR || last_command)
            *result_error = g_error_copy (error);

        return FALSE;
    }

    *result = g_variant_new_string (response);
    return TRUE;
}

/*****************************************************************************/
/* Create Bearer (Modem interface) */

static MMBaseBearer *
modem_create_bearer_finish (MMIfaceModem *self,
                            GAsyncResult *res,
                            GError **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
broadband_bearer_new_ready (GObject *source,
                            GAsyncResult *res,
                            GTask *task)
{
    MMBaseBearer *bearer = NULL;
    GError *error = NULL;

    bearer = mm_broadband_bearer_new_finish (res, &error);
    if (!bearer)
        g_task_return_error (task, error);
    else
        g_task_return_pointer (task, bearer, g_object_unref);
    g_object_unref (task);
}

static void
modem_create_bearer (MMIfaceModem *self,
                     MMBearerProperties *properties,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* We just create a MMBroadbandBearer */
    mm_dbg ("Creating Broadband bearer in broadband modem");
    mm_broadband_bearer_new (MM_BROADBAND_MODEM (self),
                             properties,
                             NULL, /* cancellable */
                             (GAsyncReadyCallback)broadband_bearer_new_ready,
                             task);
}

/*****************************************************************************/
/* Create SIM (Modem interface) */

static MMBaseSim *
modem_create_sim_finish (MMIfaceModem *self,
                         GAsyncResult *res,
                         GError **error)
{
    return mm_base_sim_new_finish (res, error);
}

static void
modem_create_sim (MMIfaceModem *self,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
    /* New generic SIM */
    mm_base_sim_new (MM_BASE_MODEM (self),
                     NULL, /* cancellable */
                     callback,
                     user_data);
}

/*****************************************************************************/
/* Capabilities loading (Modem interface) */

typedef struct {
    MMModemCapability caps;
    MMPortSerialQcdm *qcdm_port;
} LoadCapabilitiesContext;

static void
load_capabilities_context_free (LoadCapabilitiesContext *ctx)
{
    if (ctx->qcdm_port) {
        mm_port_serial_close (MM_PORT_SERIAL (ctx->qcdm_port));
        g_object_unref (ctx->qcdm_port);
    }
    g_slice_free (LoadCapabilitiesContext, ctx);
}

static MMModemCapability
modem_load_current_capabilities_finish (MMIfaceModem *self,
                                        GAsyncResult *res,
                                        GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_CAPABILITY_NONE;
    }
    return (MMModemCapability)value;
}

static void
current_capabilities_ws46_test_ready (MMBaseModem *self,
                                      GAsyncResult *res,
                                      GTask *task)
{
    LoadCapabilitiesContext *ctx;
    const gchar *response;
    GArray      *modes;
    guint        i;

    ctx = g_task_get_task_data (task);

    /* Completely ignore errors in AT+WS46=? */
    response = mm_base_modem_at_command_finish (self, res, NULL);
    if (!response)
        goto out;

    modes = mm_3gpp_parse_ws46_test_response (response, NULL);
    if (!modes)
        goto out;

    /* Add LTE caps if any of the reported modes supports 4G */
    for (i = 0; i < modes->len; i++) {
        if (g_array_index (modes, MMModemMode, i) & MM_MODEM_MODE_4G) {
            ctx->caps |= MM_MODEM_CAPABILITY_LTE;
            break;
        }
    }

    /* The +CGSM capability is saying that the modem is a 3GPP modem, but that
     * doesn't necessarily mean it's a GSM/UMTS modem, it could be a LTE-only
     * device. We did add the GSM_UMTS capability when +CGSM was found, so now
     * we'll check if the device only reports 4G-only mode, and remove the
     * capability if so.
     *
     * Note that we don't change the default +CGSM -> GSM/UMTS logic, we just
     * fix it up.
     */
    if ((modes->len == 1) && (g_array_index (modes, MMModemMode, 0) == MM_MODEM_MODE_4G)) {
        g_assert (ctx->caps & MM_MODEM_CAPABILITY_LTE);
        ctx->caps &= ~MM_MODEM_CAPABILITY_GSM_UMTS;
    }

    g_array_unref (modes);

out:
    g_task_return_int (task, ctx->caps);
    g_object_unref (task);
}

typedef struct {
    gchar *name;
    MMModemCapability bits;
} ModemCaps;

static const ModemCaps modem_caps[] = {
    { "+CGSM",     MM_MODEM_CAPABILITY_GSM_UMTS  },
    { "+CLTE2",    MM_MODEM_CAPABILITY_LTE       }, /* Novatel */
    { "+CLTE1",    MM_MODEM_CAPABILITY_LTE       }, /* Novatel */
    { "+CLTE",     MM_MODEM_CAPABILITY_LTE       },
    { "+CIS707-A", MM_MODEM_CAPABILITY_CDMA_EVDO },
    { "+CIS707A",  MM_MODEM_CAPABILITY_CDMA_EVDO }, /* Cmotech */
    { "+CIS707",   MM_MODEM_CAPABILITY_CDMA_EVDO },
    { "CIS707",    MM_MODEM_CAPABILITY_CDMA_EVDO }, /* Qualcomm Gobi */
    { "+CIS707P",  MM_MODEM_CAPABILITY_CDMA_EVDO },
    { "CIS-856",   MM_MODEM_CAPABILITY_CDMA_EVDO },
    { "+IS-856",   MM_MODEM_CAPABILITY_CDMA_EVDO }, /* Cmotech */
    { "CIS-856-A", MM_MODEM_CAPABILITY_CDMA_EVDO },
    { "CIS-856A",  MM_MODEM_CAPABILITY_CDMA_EVDO }, /* Kyocera KPC680 */
    { "+WIRIDIUM", MM_MODEM_CAPABILITY_IRIDIUM   }, /* Iridium satellite modems */
    { "CDMA 1x",   MM_MODEM_CAPABILITY_CDMA_EVDO }, /* Huawei Data07, ATI reply */
    /* TODO: FCLASS, MS, ES, DS? */
    { NULL }
};

static gboolean
parse_caps_gcap (MMBaseModem *self,
                 gpointer none,
                 const gchar *command,
                 const gchar *response,
                 gboolean last_command,
                 const GError *error,
                 GVariant **variant,
                 GError **result_error)
{
    const ModemCaps *cap = modem_caps;
    guint32 ret = 0;

    if (!response)
        return FALSE;

    /* Some modems (Huawei E160g) won't respond to +GCAP with no SIM, but
     * will respond to ATI.  Ignore the error and continue.
     */
    if (strstr (response, "+CME ERROR:"))
        return FALSE;

    while (cap->name) {
        if (strstr (response, cap->name))
            ret |= cap->bits;
        cap++;
    }

    /* No result built? */
    if (ret == 0)
        return FALSE;

    *variant = g_variant_new_uint32 (ret);
    return TRUE;
}

static gboolean
parse_caps_cpin (MMBaseModem *self,
                 gpointer none,
                 const gchar *command,
                 const gchar *response,
                 gboolean last_command,
                 const GError *error,
                 GVariant **result,
                 GError **result_error)
{
    if (!response) {
        if (error &&
            (g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_NOT_INSERTED) ||
             g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_FAILURE) ||
             g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_BUSY) ||
             g_error_matches (error, MM_MOBILE_EQUIPMENT_ERROR, MM_MOBILE_EQUIPMENT_ERROR_SIM_WRONG))) {
            /* At least, it's a GSM modem */
            *result = g_variant_new_uint32 (MM_MODEM_CAPABILITY_GSM_UMTS);
            return TRUE;
        }
        return FALSE;
    }

    if (strcasestr (response, "SIM PIN") ||
        strcasestr (response, "SIM PUK") ||
        strcasestr (response, "PH-SIM PIN") ||
        strcasestr (response, "PH-FSIM PIN") ||
        strcasestr (response, "PH-FSIM PUK") ||
        strcasestr (response, "SIM PIN2") ||
        strcasestr (response, "SIM PUK2") ||
        strcasestr (response, "PH-NET PIN") ||
        strcasestr (response, "PH-NET PUK") ||
        strcasestr (response, "PH-NETSUB PIN") ||
        strcasestr (response, "PH-NETSUB PUK") ||
        strcasestr (response, "PH-SP PIN") ||
        strcasestr (response, "PH-SP PUK") ||
        strcasestr (response, "PH-CORP PIN") ||
        strcasestr (response, "PH-CORP PUK") ||
        strcasestr (response, "READY")) {
        /* At least, it's a GSM modem */
        *result = g_variant_new_uint32 (MM_MODEM_CAPABILITY_GSM_UMTS);
        return TRUE;
    }
    return FALSE;
}

static gboolean
parse_caps_cgmm (MMBaseModem *self,
                 gpointer none,
                 const gchar *command,
                 const gchar *response,
                 gboolean last_command,
                 const GError *error,
                 GVariant **result,
                 GError **result_error)
{
    if (!response)
        return FALSE;

    /* This check detects some really old Motorola GPRS dongles and phones */
    if (strstr (response, "GSM900") ||
        strstr (response, "GSM1800") ||
        strstr (response, "GSM1900") ||
        strstr (response, "GSM850")) {
        /* At least, it's a GSM modem */
        *result = g_variant_new_uint32 (MM_MODEM_CAPABILITY_GSM_UMTS);
        return TRUE;
    }
    return FALSE;
}

static const MMBaseModemAtCommand capabilities[] = {
    { "+GCAP",  2, TRUE,  parse_caps_gcap },
    { "I",      1, TRUE,  parse_caps_gcap }, /* yes, really parse as +GCAP */
    { "+CPIN?", 1, FALSE, parse_caps_cpin },
    { "+CGMM",  1, TRUE,  parse_caps_cgmm },
    { NULL }
};

static void
capabilities_sequence_ready (MMBaseModem *self,
                             GAsyncResult *res,
                             GTask *task)
{
    LoadCapabilitiesContext *ctx;
    GError *error = NULL;
    GVariant *result;

    ctx = g_task_get_task_data (task);

    result = mm_base_modem_at_sequence_finish (self, res, NULL, &error);
    if (!result) {
        if (error)
            g_task_return_error (task, error);
        else
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "%s",
                                     "Failed to determine modem capabilities.");
        g_object_unref (task);
        return;
    }

    ctx->caps = (MMModemCapability)g_variant_get_uint32 (result);

    /* Some modems (e.g. Sierra Wireless MC7710 or ZTE MF820D) won't report LTE
     * capabilities even if they have them. So just run AT+WS46=? as well to see
     * if the current supported modes includes any LTE-specific mode.
     * This is not a big deal, as the AT+WS46=? command is a test command with a
     * cache-able result.
     *
     * E.g.:
     *  AT+WS46=?
     *   +WS46: (12,22,25,28,29)
     *   OK
     *
     */
    if (ctx->caps & MM_MODEM_CAPABILITY_GSM_UMTS &&
        !(ctx->caps & MM_MODEM_CAPABILITY_LTE)) {
        mm_base_modem_at_command (
            self,
            "+WS46=?",
            3,
            TRUE, /* allow caching, it's a test command */
            (GAsyncReadyCallback)current_capabilities_ws46_test_ready,
            task);
        return;
    }

    /* Otherwise, just set the already retrieved capabilities */
    g_task_return_int (task, ctx->caps);
    g_object_unref (task);
}

static void
load_current_capabilities_at (GTask *task)
{
    MMBroadbandModem *self;

    self = g_task_get_source_object (task);

    /* Launch sequence, we will expect a "u" GVariant */
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        capabilities,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        (GAsyncReadyCallback)capabilities_sequence_ready,
        task);
}

static void
mode_pref_qcdm_ready (MMPortSerialQcdm *port,
                      GAsyncResult *res,
                      GTask *task)
{
    LoadCapabilitiesContext *ctx;
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    uint8_t pref = 0;
    GError *error = NULL;
    GByteArray *response;

    ctx = g_task_get_task_data (task);

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        /* Fall back to AT checking */
        mm_dbg ("Failed to load NV ModePref: %s", error->message);
        g_error_free (error);
        goto at_caps;
    }

    /* Parse the response */
    result = qcdm_cmd_nv_get_mode_pref_result ((const gchar *)response->data,
                                               response->len,
                                               &err);
    g_byte_array_unref (response);
    if (!result) {
        mm_dbg ("Failed to parse NV ModePref result: %d", err);
        g_byte_array_unref (response);
        goto at_caps;
    }

    err = qcdm_result_get_u8 (result, QCDM_CMD_NV_GET_MODE_PREF_ITEM_MODE_PREF, &pref);
    qcdm_result_unref (result);
    if (err) {
        mm_dbg ("Failed to read NV ModePref: %d", err);
        goto at_caps;
    }

    /* Only parse explicit modes; for 'auto' just fall back to whatever
     * the AT current capabilities probing figures out.
     */
    switch (pref) {
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_1X_HDR_LTE_ONLY:
        ctx->caps |= MM_MODEM_CAPABILITY_LTE;
        /* Fall through */
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_1X_ONLY:
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_HDR_ONLY:
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_1X_HDR_ONLY:
        ctx->caps |= MM_MODEM_CAPABILITY_CDMA_EVDO;
        break;
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_GSM_UMTS_LTE_ONLY:
        ctx->caps |= MM_MODEM_CAPABILITY_LTE;
        /* Fall through */
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_GPRS_ONLY:
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_UMTS_ONLY:
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_GSM_UMTS_ONLY:
        ctx->caps |= MM_MODEM_CAPABILITY_GSM_UMTS;
        break;
    case QCDM_CMD_NV_MODE_PREF_ITEM_MODE_PREF_LTE_ONLY:
        ctx->caps |= MM_MODEM_CAPABILITY_LTE;
        break;
    default:
        break;
    }

    if (ctx->caps != MM_MODEM_CAPABILITY_NONE) {
        g_task_return_int (task, ctx->caps);
        g_object_unref (task);
        return;
    }

at_caps:
    load_current_capabilities_at (task);
}

static void
load_current_capabilities_qcdm (GTask *task)
{
    MMBroadbandModem *self;
    LoadCapabilitiesContext *ctx;
    GByteArray *cmd;
    GError *error = NULL;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    ctx->qcdm_port = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    g_assert (ctx->qcdm_port);

    if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->qcdm_port), &error)) {
        mm_dbg ("Failed to open QCDM port for NV ModePref request: %s",
                error->message);
        g_error_free (error);
        ctx->qcdm_port = NULL;
        load_current_capabilities_at (task);
        return;
    }

    g_object_ref (ctx->qcdm_port);

    cmd = g_byte_array_sized_new (300);
    cmd->len = qcdm_cmd_nv_get_mode_pref_new ((char *) cmd->data, 300, 0);
    g_assert (cmd->len);

    mm_port_serial_qcdm_command (ctx->qcdm_port,
                                 cmd,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)mode_pref_qcdm_ready,
                                 task);
    g_byte_array_unref (cmd);
}

static void
modem_load_current_capabilities (MMIfaceModem *self,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
    LoadCapabilitiesContext *ctx;
    GTask *task;

    mm_dbg ("loading current capabilities...");

    ctx = g_slice_new0 (LoadCapabilitiesContext);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)load_capabilities_context_free);

    if (mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self)))
        load_current_capabilities_qcdm (task);
    else
        load_current_capabilities_at (task);
}

/*****************************************************************************/
/* Manufacturer loading (Modem interface) */

static gchar *
sanitize_info_reply (GVariant *v, const char *prefix)
{
    const gchar *reply, *p;
    gchar *sanitized;

    /* Strip any leading command reply */
    reply = g_variant_get_string (v, NULL);
    p = strstr (reply, prefix);
    if (p)
        reply = p + strlen (prefix);
    sanitized = g_strdup (reply);
    return mm_strip_quotes (g_strstrip (sanitized));
}

static gchar *
modem_load_manufacturer_finish (MMIfaceModem *self,
                                GAsyncResult *res,
                                GError **error)
{
    GVariant *result;
    gchar *manufacturer = NULL;

    result = mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, error);
    if (result) {
        manufacturer = sanitize_info_reply (result, "GMI:");
        mm_dbg ("loaded manufacturer: %s", manufacturer);
    }
    return manufacturer;
}

static const MMBaseModemAtCommand manufacturers[] = {
    { "+CGMI",  3, TRUE, response_processor_string_ignore_at_errors },
    { "+GMI",   3, TRUE, response_processor_string_ignore_at_errors },
    { NULL }
};

static void
modem_load_manufacturer (MMIfaceModem *self,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
    mm_dbg ("loading manufacturer...");
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        manufacturers,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        callback,
        user_data);
}

/*****************************************************************************/
/* Model loading (Modem interface) */

static gchar *
modem_load_model_finish (MMIfaceModem *self,
                         GAsyncResult *res,
                         GError **error)
{
    GVariant *result;
    gchar *model = NULL;

    result = mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, error);
    if (result) {
        model = sanitize_info_reply (result, "GMM:");
        mm_dbg ("loaded model: %s", model);
    }
    return model;
}

static const MMBaseModemAtCommand models[] = {
    { "+CGMM",  3, TRUE, response_processor_string_ignore_at_errors },
    { "+GMM",   3, TRUE, response_processor_string_ignore_at_errors },
    { NULL }
};

static void
modem_load_model (MMIfaceModem *self,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
    mm_dbg ("loading model...");
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        models,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        callback,
        user_data);
}

/*****************************************************************************/
/* Revision loading */

static gchar *
modem_load_revision_finish (MMIfaceModem *self,
                            GAsyncResult *res,
                            GError **error)
{
    GVariant *result;
    gchar *revision = NULL;

    result = mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, error);
    if (result) {
        revision = sanitize_info_reply (result, "GMR:");
        mm_dbg ("loaded revision: %s", revision);
    }
    return revision;
}

static const MMBaseModemAtCommand revisions[] = {
    { "+CGMR",  3, TRUE, response_processor_string_ignore_at_errors },
    { "+GMR",   3, TRUE, response_processor_string_ignore_at_errors },
    { NULL }
};

static void
modem_load_revision (MMIfaceModem *self,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
    mm_dbg ("loading revision...");
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        revisions,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        callback,
        user_data);
}

/*****************************************************************************/
/* Equipment ID loading (Modem interface) */

static gchar *
modem_load_equipment_identifier_finish (MMIfaceModem *self,
                                        GAsyncResult *res,
                                        GError **error)
{
    GVariant *result;
    gchar *equip_id = NULL, *esn = NULL, *meid = NULL, *imei = NULL;

    result = mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, error);
    if (result) {
        equip_id = sanitize_info_reply (result, "GSN:");

        /* Modems put all sorts of things into the GSN response; sanitize it */
        if (mm_parse_gsn (equip_id, &imei, &meid, &esn)) {
            g_clear_pointer (&equip_id, g_free);

            if (imei)
                equip_id = g_strdup (imei);
            else if (meid)
                equip_id = g_strdup (meid);
            else if (esn)
                equip_id = g_strdup (esn);
            else
                g_assert_not_reached ();

            g_free (esn);
            g_free (meid);
            g_free (imei);
        } else {
            /* Leave whatever the modem returned alone */
        }
        mm_dbg ("loaded equipment identifier: %s", equip_id);
    }
    return equip_id;
}

static const MMBaseModemAtCommand equipment_identifiers[] = {
    { "+CGSN",  3, TRUE, response_processor_string_ignore_at_errors },
    { "+GSN",   3, TRUE, response_processor_string_ignore_at_errors },
    { NULL }
};

static void
modem_load_equipment_identifier (MMIfaceModem *self,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data)
{
    const MMBaseModemAtCommand *commands = equipment_identifiers;

    mm_dbg ("loading equipment identifier...");

    /* On CDMA-only (non-3GPP) modems, just try +GSN */
    if (mm_iface_modem_is_cdma_only (self))
        commands++;

    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        commands,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        callback,
        user_data);
}

/*****************************************************************************/
/* Device identifier loading (Modem interface) */

typedef struct {
    gchar *ati;
    gchar *ati1;
} DeviceIdentifierContext;

static void
device_identifier_context_free (DeviceIdentifierContext *ctx)
{
    g_free (ctx->ati);
    g_free (ctx->ati1);
    g_free (ctx);
}

static gchar *
modem_load_device_identifier_finish (MMIfaceModem *self,
                                     GAsyncResult *res,
                                     GError **error)
{
    GError *inner_error = NULL;
    gpointer ctx = NULL;
    gchar *device_identifier;

    mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, &ctx, &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return NULL;
    }

    g_assert (ctx != NULL);
    device_identifier = (mm_broadband_modem_create_device_identifier (
                             MM_BROADBAND_MODEM (self),
                             ((DeviceIdentifierContext *)ctx)->ati,
                             ((DeviceIdentifierContext *)ctx)->ati1));
    mm_dbg ("loaded device identifier: %s", device_identifier);
    return device_identifier;
}

static gboolean
parse_ati_reply (MMBaseModem *self,
                 DeviceIdentifierContext *ctx,
                 const gchar *command,
                 const gchar *response,
                 gboolean last_command,
                 const GError *error,
                 GVariant **result,
                 GError **result_error)
{
    /* Store the proper string in the proper place */
    if (!error) {
        if (g_str_equal (command, "ATI1"))
            ctx->ati1 = g_strdup (response);
        else
            ctx->ati = g_strdup (response);
    }

    /* Always keep on, this is a sequence where all the steps should be taken */
    return TRUE;
}

static const MMBaseModemAtCommand device_identifier_steps[] = {
    { "ATI",  3, TRUE, (MMBaseModemAtResponseProcessor)parse_ati_reply },
    { "ATI1", 3, TRUE, (MMBaseModemAtResponseProcessor)parse_ati_reply },
    { NULL }
};

static void
modem_load_device_identifier (MMIfaceModem *self,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
    mm_dbg ("loading device identifier...");
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        device_identifier_steps,
        g_new0 (DeviceIdentifierContext, 1),
        (GDestroyNotify)device_identifier_context_free,
        callback,
        user_data);
}

/*****************************************************************************/
/* Load own numbers (Modem interface) */

typedef struct {
    MMPortSerialQcdm *qcdm;
} OwnNumbersContext;

static void
own_numbers_context_free (OwnNumbersContext *ctx)
{
    if (ctx->qcdm) {
        mm_port_serial_close (MM_PORT_SERIAL (ctx->qcdm));
        g_object_unref (ctx->qcdm);
    }
    g_free (ctx);
}

static GStrv
modem_load_own_numbers_finish (MMIfaceModem *self,
                               GAsyncResult *res,
                               GError **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
mdn_qcdm_ready (MMPortSerialQcdm *port,
                GAsyncResult *res,
                GTask *task)
{
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    const char *numbers[2] = { NULL, NULL };
    GByteArray *response;
    GError *error = NULL;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_nv_get_mdn_result ((const gchar *) response->data,
                                         response->len,
                                         &err);
    g_byte_array_unref (response);
    if (!result) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Failed to parse NV MDN command result: %d",
                                 err);
        g_object_unref (task);
        return;
    }

    if (qcdm_result_get_string (result, QCDM_CMD_NV_GET_MDN_ITEM_MDN, &numbers[0]) >= 0) {
        gboolean valid = TRUE;
        const char *p = numbers[0];

        /* Returned NV item data is read directly out of NV memory on the card,
         * so minimally verify it.
         */
        if (strlen (numbers[0]) < 6 || strlen (numbers[0]) > 15)
            valid = FALSE;

        /* MDN is always decimal digits; allow + for good measure */
        while (p && *p && valid)
            valid = g_ascii_isdigit (*p++) || (*p == '+');

        if (valid) {
            g_task_return_pointer (task,
                                   g_strdupv ((gchar **) numbers),
                                   (GDestroyNotify)g_strfreev);
        } else {
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "%s",
                                     "MDN from NV memory appears invalid");
        }
    } else {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "%s",
                                 "Failed retrieve MDN");
    }
    g_object_unref (task);

    qcdm_result_unref (result);
}

static void
modem_load_own_numbers_done (MMIfaceModem *self,
                             GAsyncResult *res,
                             GTask *task)
{
    OwnNumbersContext *ctx;
    const gchar *result;
    GError *error = NULL;
    GStrv numbers;

    ctx = g_task_get_task_data (task);

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (!result) {
        /* try QCDM */
        if (ctx->qcdm) {
            GByteArray *mdn;

            g_clear_error (&error);

            mdn = g_byte_array_sized_new (200);
            mdn->len = qcdm_cmd_nv_get_mdn_new ((char *) mdn->data, 200, 0);
            g_assert (mdn->len);

            mm_port_serial_qcdm_command (ctx->qcdm,
                                         mdn,
                                         3,
                                         NULL,
                                         (GAsyncReadyCallback)mdn_qcdm_ready,
                                         task);
            g_byte_array_unref (mdn);
            return;
        }
        g_task_return_error (task, error);
    } else {
        numbers = mm_3gpp_parse_cnum_exec_response (result);
        g_task_return_pointer (task, numbers, (GDestroyNotify)g_strfreev);
    }
    g_object_unref (task);
}

static void
modem_load_own_numbers (MMIfaceModem *self,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    OwnNumbersContext *ctx;
    GError *error = NULL;
    GTask *task;

    ctx = g_new0 (OwnNumbersContext, 1);
    ctx->qcdm = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (ctx->qcdm) {
        if (mm_port_serial_open (MM_PORT_SERIAL (ctx->qcdm), &error)) {
            ctx->qcdm = g_object_ref (ctx->qcdm);
        } else {
            mm_dbg ("Couldn't open QCDM port: (%d) %s",
                    error ? error->code : -1,
                    error ? error->message : "(unknown)");
            ctx->qcdm = NULL;
        }
    }

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)own_numbers_context_free);

    mm_dbg ("loading own numbers...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CNUM",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)modem_load_own_numbers_done,
                              task);
}

/*****************************************************************************/
/* Check if unlock required (Modem interface) */

typedef struct {
    const gchar *result;
    MMModemLock code;
} CPinResult;

static CPinResult unlock_results[] = {
    /* Longer entries first so we catch the correct one with strcmp() */
    { "READY",         MM_MODEM_LOCK_NONE           },
    { "SIM PIN2",      MM_MODEM_LOCK_SIM_PIN2       },
    { "SIM PUK2",      MM_MODEM_LOCK_SIM_PUK2       },
    { "SIM PIN",       MM_MODEM_LOCK_SIM_PIN        },
    { "SIM PUK",       MM_MODEM_LOCK_SIM_PUK        },
    { "PH-NETSUB PIN", MM_MODEM_LOCK_PH_NETSUB_PIN  },
    { "PH-NETSUB PUK", MM_MODEM_LOCK_PH_NETSUB_PUK  },
    { "PH-FSIM PIN",   MM_MODEM_LOCK_PH_FSIM_PIN    },
    { "PH-FSIM PUK",   MM_MODEM_LOCK_PH_FSIM_PUK    },
    { "PH-CORP PIN",   MM_MODEM_LOCK_PH_CORP_PIN    },
    { "PH-CORP PUK",   MM_MODEM_LOCK_PH_CORP_PUK    },
    { "PH-SIM PIN",    MM_MODEM_LOCK_PH_SIM_PIN     },
    { "PH-NET PIN",    MM_MODEM_LOCK_PH_NET_PIN     },
    { "PH-NET PUK",    MM_MODEM_LOCK_PH_NET_PUK     },
    { "PH-SP PIN",     MM_MODEM_LOCK_PH_SP_PIN      },
    { "PH-SP PUK",     MM_MODEM_LOCK_PH_SP_PUK      },
    { NULL }
};

static MMModemLock
modem_load_unlock_required_finish (MMIfaceModem *self,
                                   GAsyncResult *res,
                                   GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_LOCK_UNKNOWN;
    }
    return (MMModemLock)value;
}

static void
cpin_query_ready (MMIfaceModem *self,
                  GAsyncResult *res,
                  GTask *task)
{

    MMModemLock lock = MM_MODEM_LOCK_UNKNOWN;
    const gchar *result;
    GError *error = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    if (result &&
        strstr (result, "+CPIN:")) {
        CPinResult *iter = &unlock_results[0];
        const gchar *str;

        str = strstr (result, "+CPIN:") + 6;
        /* Skip possible whitespaces after '+CPIN:' and before the response */
        while (*str == ' ')
            str++;

        /* Some phones (Motorola EZX models) seem to quote the response */
        if (str[0] == '"')
            str++;

        /* Translate the reply */
        while (iter->result) {
            if (g_str_has_prefix (str, iter->result)) {
                lock = iter->code;
                break;
            }
            iter++;
        }
    }

    g_task_return_int (task, lock);
    g_object_unref (task);
}

static void
modem_load_unlock_required (MMIfaceModem *self,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* CDMA-only modems don't need this */
    if (mm_iface_modem_is_cdma_only (self)) {
        mm_dbg ("Skipping unlock check in CDMA-only modem...");
        g_task_return_int (task, MM_MODEM_LOCK_NONE);
        g_object_unref (task);
        return;
    }

    mm_dbg ("checking if unlock required...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CPIN?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)cpin_query_ready,
                              task);
}

/*****************************************************************************/
/* Supported modes loading (Modem interface) */

typedef struct {
    MMModemMode mode;
    gboolean run_cnti;
    gboolean run_ws46;
    gboolean run_gcap;
} LoadSupportedModesContext;

static GArray *
modem_load_supported_modes_finish (MMIfaceModem *self,
                                   GAsyncResult *res,
                                   GError **error)
{
    GError *inner_error = NULL;
    gssize value;
    GArray *modes;
    MMModemModeCombination mode;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return NULL;
    }

    /* Build a mask with all supported modes */
    modes = g_array_sized_new (FALSE, FALSE, sizeof (MMModemModeCombination), 1);
    mode.allowed = (MMModemMode) value;
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (modes, mode);

    return modes;
}

static void load_supported_modes_step (GTask *task);

static void
supported_modes_gcap_ready (MMBaseModem *_self,
                            GAsyncResult *res,
                            GTask *task)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    LoadSupportedModesContext *ctx;
    const gchar *response;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (_self, res, &error);
    if (!error) {
        MMModemMode mode = MM_MODEM_MODE_NONE;

        if (strstr (response, "IS")) {
            /* IS-856 is the EV-DO family */
            if (strstr (response, "856")) {
                if (!self->priv->modem_cdma_evdo_network_supported) {
                    self->priv->modem_cdma_evdo_network_supported = TRUE;
                    g_object_notify (G_OBJECT (self), MM_IFACE_MODEM_CDMA_EVDO_NETWORK_SUPPORTED);
                }
                mm_dbg ("Device allows (CDMA) 3G network mode");
                mode |= MM_MODEM_MODE_3G;
            }
            /* IS-707 is the 1xRTT family, which we consider as 2G */
            if (strstr (response, "707")) {
                if (!self->priv->modem_cdma_cdma1x_network_supported) {
                    self->priv->modem_cdma_cdma1x_network_supported = TRUE;
                    g_object_notify (G_OBJECT (self), MM_IFACE_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED);
                }
                mm_dbg ("Device allows (CDMA) 2G network mode");
                mode |= MM_MODEM_MODE_2G;
            }
        }

        /* If no expected mode found, error */
        if (mode == MM_MODEM_MODE_NONE) {
            /* This should really never happen in the default implementation. */
            error = g_error_new (MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Couldn't find specific CDMA mode in capabilities string: '%s'",
                                 response);
        } else {
            /* Keep our results */
            ctx->mode |= mode;
        }
    }

    if (error) {
        mm_dbg ("Generic query of supported CDMA networks failed: '%s'", error->message);
        g_error_free (error);

        /* Use defaults */
        if (self->priv->modem_cdma_cdma1x_network_supported) {
            mm_dbg ("Assuming device allows (CDMA) 2G network mode");
            ctx->mode |= MM_MODEM_MODE_2G;
        }
        if (self->priv->modem_cdma_evdo_network_supported) {
            mm_dbg ("Assuming device allows (CDMA) 3G network mode");
            ctx->mode |= MM_MODEM_MODE_3G;
        }
    }

    /* Now keep on with the loading, we're probably finishing now */
    ctx->run_gcap = FALSE;
    load_supported_modes_step (task);
}

static void
supported_modes_ws46_test_ready (MMBroadbandModem *self,
                                 GAsyncResult *res,
                                 GTask *task)
{
    LoadSupportedModesContext *ctx;
    const gchar *response;
    GArray      *modes;
    GError      *error = NULL;
    guint        i;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        mm_dbg ("Generic query of supported 3GPP networks with WS46=? failed: '%s'", error->message);
        g_error_free (error);
        goto out;
    }

    modes = mm_3gpp_parse_ws46_test_response (response, &error);
    if (!modes) {
        mm_dbg ("Parsing WS46=? response failed: '%s'", error->message);
        g_error_free (error);
        goto out;
    }

    for (i = 0; i < modes->len; i++) {
        MMModemMode  mode;
        gchar       *str;

        mode = g_array_index (modes, MMModemMode, i);

        ctx->mode |= mode;

        str = mm_modem_mode_build_string_from_mask (mode);
        mm_dbg ("Device allows (3GPP) mode combination: %s", str);
        g_free (str);
    }

    g_array_unref (modes);

out:
    /* Now keep on with the loading, we may need CDMA-specific checks */
    ctx->run_ws46 = FALSE;
    load_supported_modes_step (task);
}

static void
supported_modes_cnti_ready (MMBroadbandModem *self,
                            GAsyncResult *res,
                            GTask *task)
{
    LoadSupportedModesContext *ctx;
    const gchar *response;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (!error) {
        MMModemMode mode = MM_MODEM_MODE_NONE;
        gchar *lower;

        lower = g_ascii_strdown (response, -1);

        if (g_strstr_len (lower, -1, "gsm") ||
            g_strstr_len (lower, -1, "gprs") ||
            g_strstr_len (lower, -1, "edge")) {
            mm_dbg ("Device allows (3GPP) 2G networks");
            mode |= MM_MODEM_MODE_2G;
        }

        if (g_strstr_len (lower, -1, "umts") ||
            g_strstr_len (lower, -1, "hsdpa") ||
            g_strstr_len (lower, -1, "hsupa") ||
            g_strstr_len (lower, -1, "hspa+")) {
            mm_dbg ("Device allows (3GPP) 3G networks");
            mode |= MM_MODEM_MODE_3G;
        }

        if (g_strstr_len (lower, -1, "lte")) {
            mm_dbg ("Device allows (3GPP) 4G networks");
            mode |= MM_MODEM_MODE_4G;
        }

        g_free (lower);

        /* If no expected ID found, log error */
        if (mode == MM_MODEM_MODE_NONE)
            mm_dbg ("Invalid list of supported networks reported by *CNTI: '%s'", response);
        else
            ctx->mode |= mode;
    } else {
        mm_dbg ("Generic query of supported 3GPP networks with *CNTI failed: '%s'", error->message);
        g_error_free (error);
    }

    /* Now keep on with the loading */
    ctx->run_cnti = FALSE;
    load_supported_modes_step (task);
}

static void
load_supported_modes_step (GTask *task)
{
    MMBroadbandModem *self;
    LoadSupportedModesContext *ctx;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    if (ctx->run_cnti) {
        mm_base_modem_at_command (
            MM_BASE_MODEM (self),
            "*CNTI=2",
            3,
            FALSE,
            (GAsyncReadyCallback)supported_modes_cnti_ready,
            task);
        return;
    }

    if (ctx->run_ws46) {
        mm_base_modem_at_command (
            MM_BASE_MODEM (self),
            "+WS46=?",
            3,
            TRUE, /* allow caching, it's a test command */
            (GAsyncReadyCallback)supported_modes_ws46_test_ready,
            task);
        return;
    }

    if (ctx->run_gcap) {
        mm_base_modem_at_command (
            MM_BASE_MODEM (self),
            "+GCAP",
            3,
            TRUE, /* allow caching */
            (GAsyncReadyCallback)supported_modes_gcap_ready,
            task);
        return;
    }

    /* All done.
     * If no mode found, error */
    if (ctx->mode == MM_MODEM_MODE_NONE)
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Couldn't retrieve supported modes");
    else
        g_task_return_int (task, ctx->mode);

    g_object_unref (task);
}

static void
modem_load_supported_modes (MMIfaceModem *self,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
    LoadSupportedModesContext *ctx;
    GTask *task;

    mm_dbg ("loading supported modes...");
    ctx = g_new0 (LoadSupportedModesContext, 1);
    ctx->mode = MM_MODEM_MODE_NONE;

    if (mm_iface_modem_is_3gpp (self)) {
        /* Run +WS46=? and *CNTI=2 */
        ctx->run_ws46 = TRUE;
        ctx->run_cnti = TRUE;
    }

    if (mm_iface_modem_is_cdma (self)) {
        /* Run +GCAP in order to know if the modem is CDMA1x only or CDMA1x/EV-DO */
        ctx->run_gcap = TRUE;
    }

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, g_free);

    load_supported_modes_step (task);
}

/*****************************************************************************/
/* Supported IP families loading (Modem interface) */

static MMBearerIpFamily
modem_load_supported_ip_families_finish (MMIfaceModem *self,
                                         GAsyncResult *res,
                                         GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_BEARER_IP_FAMILY_NONE;
    }
    return (MMBearerIpFamily)value;
}

static void
supported_ip_families_cgdcont_test_ready (MMBaseModem *self,
                                          GAsyncResult *res,
                                          GTask *task)
{
    const gchar *response;
    GError *error = NULL;
    MMBearerIpFamily mask = MM_BEARER_IP_FAMILY_NONE;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (response) {
        GList *formats, *l;

        formats = mm_3gpp_parse_cgdcont_test_response (response, &error);
        for (l = formats; l; l = g_list_next (l))
            mask |= ((MM3gppPdpContextFormat *)(l->data))->pdp_type;

        mm_3gpp_pdp_context_format_list_free (formats);
    }

    if (error)
        g_task_return_error (task, error);
    else
        g_task_return_int (task, mask);

    g_object_unref (task);
}

static void
modem_load_supported_ip_families (MMIfaceModem *self,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
    GTask *task;

    mm_dbg ("loading supported IP families...");
    task = g_task_new (self, NULL, callback, user_data);

    if (mm_iface_modem_is_cdma_only (self)) {
        g_task_return_int (task, MM_BEARER_IP_FAMILY_IPV4);
        g_object_unref (task);
        return;
    }

    /* Query with CGDCONT=? */
    mm_base_modem_at_command (
        MM_BASE_MODEM (self),
        "+CGDCONT=?",
        3,
        TRUE, /* allow caching, it's a test command */
        (GAsyncReadyCallback)supported_ip_families_cgdcont_test_ready,
        task);
}

/*****************************************************************************/
/* Signal quality loading (Modem interface) */

static void
qcdm_evdo_pilot_sets_log_handle (MMPortSerialQcdm *port,
                                 GByteArray *log_buffer,
                                 gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (user_data);
    QcdmResult *result;
    uint32_t num_active = 0;
    uint32_t pilot_pn = 0;
    uint32_t pilot_energy = 0;
    int32_t rssi_dbm = 0;

    result = qcdm_log_item_evdo_pilot_sets_v2_new ((const char *) log_buffer->data,
                                                   log_buffer->len,
                                                   NULL);
    if (!result)
        return;

    if (!qcdm_log_item_evdo_pilot_sets_v2_get_num (result,
                                                   QCDM_LOG_ITEM_EVDO_PILOT_SETS_V2_TYPE_ACTIVE,
                                                   &num_active)) {
        qcdm_result_unref (result);
        return;
    }

    if (num_active > 0 &&
        qcdm_log_item_evdo_pilot_sets_v2_get_pilot (result,
                                                    QCDM_LOG_ITEM_EVDO_PILOT_SETS_V2_TYPE_ACTIVE,
                                                    0,
                                                    &pilot_pn,
                                                    &pilot_energy,
                                                    &rssi_dbm)) {
        mm_dbg ("EVDO active pilot RSSI: %ddBm", rssi_dbm);
        self->priv->evdo_pilot_rssi = rssi_dbm;
    }

    qcdm_result_unref (result);
}

typedef struct {
    MMPortSerial *at_port;
    MMPortSerial *qcdm_port;
} SignalQualityContext;

static void
signal_quality_context_free (SignalQualityContext *ctx)
{
    g_clear_object (&ctx->at_port);
    if (ctx->qcdm_port) {
        mm_port_serial_close (ctx->qcdm_port);
        g_object_unref (ctx->qcdm_port);
    }
    g_free (ctx);
}

static guint
modem_load_signal_quality_finish (MMIfaceModem *self,
                                  GAsyncResult *res,
                                  GError **error)
{
    gssize value;

    value = g_task_propagate_int (G_TASK (res), error);
    return value < 0 ? 0 : value;
}

static guint
signal_quality_evdo_pilot_sets (MMBroadbandModem *self)
{
    gint dbm;

    if (self->priv->modem_cdma_evdo_registration_state == MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)
        return 0;

    if (self->priv->evdo_pilot_rssi >= 0)
        return 0;

    dbm = CLAMP (self->priv->evdo_pilot_rssi, -113, -51);
    return 100 - ((dbm + 51) * 100 / (-113 + 51));
}

static void
signal_quality_csq_ready (MMBroadbandModem *self,
                          GAsyncResult *res,
                          GTask *task)
{
    GError *error = NULL;
    GVariant *result;
    const gchar *result_str;

    result = mm_base_modem_at_sequence_full_finish (MM_BASE_MODEM (self), res, NULL, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    result_str = g_variant_get_string (result, NULL);
    if (result_str) {
        /* Got valid reply */
        int quality;
        int ber;

        result_str = mm_strip_tag (result_str, "+CSQ:");
        if (sscanf (result_str, "%d, %d", &quality, &ber)) {
            if (quality == 99) {
                /* 99 can mean unknown, no service, etc.  But the modem may
                 * also only report CDMA 1x quality in CSQ, so try EVDO via
                 * QCDM log messages too.
                 */
                quality = signal_quality_evdo_pilot_sets (self);
            } else {
                /* Normalize the quality */
                quality = CLAMP (quality, 0, 31) * 100 / 31;
            }
            g_task_return_int (task, quality);
            g_object_unref (task);
            return;
        }
    }

    g_task_return_new_error (task,
                             MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Could not parse signal quality results");
    g_object_unref (task);
}

/* Some modems want +CSQ, others want +CSQ?, and some of both types
 * will return ERROR if they don't get the command they want.  So
 * try the other command if the first one fails.
 */
static const MMBaseModemAtCommand signal_quality_csq_sequence[] = {
    { "+CSQ",  3, TRUE, response_processor_string_ignore_at_errors },
    { "+CSQ?", 3, TRUE, response_processor_string_ignore_at_errors },
    { NULL }
};

static void
signal_quality_csq (GTask *task)
{
    MMBroadbandModem *self;
    SignalQualityContext *ctx;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    mm_base_modem_at_sequence_full (
        MM_BASE_MODEM (self),
        MM_PORT_SERIAL_AT (ctx->at_port),
        signal_quality_csq_sequence,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        NULL, /* cancellable */
        (GAsyncReadyCallback)signal_quality_csq_ready,
        task);
}

static guint
normalize_ciev_cind_signal_quality (guint quality,
                                    guint min,
                                    guint max)
{
    if (!max) {
        /* If we didn't get a max, assume it was 5. Note that we do allow
         * 0, meaning no signal at all. */
        return (quality <= 5) ? (quality * 20) : 100;
    }

    if (quality >= min &&
        quality <= max)
        return ((100 * (quality - min)) / (max - min));

    /* Value out of range, assume no signal here. Some modems (Cinterion
     * for example) will send out-of-range values when they cannot get
     * the signal strength. */
    return 0;
}

static void
signal_quality_cind_ready (MMBroadbandModem *self,
                           GAsyncResult *res,
                           GTask *task)
{
    SignalQualityContext *ctx;
    GError *error = NULL;
    const gchar *result;
    GByteArray *indicators;
    guint quality = 0;

    ctx = g_task_get_task_data (task);

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_clear_error (&error);
        goto try_csq;
    }

    indicators = mm_3gpp_parse_cind_read_response (result, &error);
    if (!indicators) {
        mm_dbg ("(%s) Could not parse CIND signal quality results: %s",
                mm_port_get_device (MM_PORT (ctx->at_port)),
                error->message);
        g_clear_error (&error);
        goto try_csq;
    }

    if (indicators->len < self->priv->modem_cind_indicator_signal_quality) {
        mm_dbg ("(%s) Could not parse CIND signal quality results; signal "
                "index (%u) outside received range (0-%u)",
                mm_port_get_device (MM_PORT (ctx->at_port)),
                self->priv->modem_cind_indicator_signal_quality,
                indicators->len);
    } else {
        quality = g_array_index (indicators,
                                 guint8,
                                 self->priv->modem_cind_indicator_signal_quality);
        quality = normalize_ciev_cind_signal_quality (quality,
                                                      self->priv->modem_cind_min_signal_quality,
                                                      self->priv->modem_cind_max_signal_quality);
    }
    g_byte_array_free (indicators, TRUE);

    if (quality > 0) {
        /* +CIND success */
        g_task_return_int (task, quality);
        g_object_unref (task);
        return;
    }

try_csq:
    /* Always fall back to +CSQ if for whatever reason +CIND failed.  Also,
     * some QMI-based devices say they support signal via CIND, but always
     * report zero even though they have signal.  So if we get zero signal
     * from +CIND, try CSQ too.  (bgo #636040)
     */
    signal_quality_csq (task);
}

static void
signal_quality_cind (GTask *task)
{
    MMBroadbandModem *self;
    SignalQualityContext *ctx;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                   MM_PORT_SERIAL_AT (ctx->at_port),
                                   "+CIND?",
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   NULL, /* cancellable */
                                   (GAsyncReadyCallback)signal_quality_cind_ready,
                                   task);
}

static void
signal_quality_qcdm_ready (MMPortSerialQcdm *port,
                           GAsyncResult *res,
                           GTask *task)
{
    QcdmResult *result;
    guint32 num = 0, quality = 0, i;
    gfloat best_db = -28;
    gint err = QCDM_SUCCESS;
    GByteArray *response;
    GError *error = NULL;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_pilot_sets_result ((const gchar *) response->data,
                                         response->len,
                                         &err);
    g_byte_array_unref (response);
    if (!result) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Failed to parse pilot sets command result: %d",
                                 err);
        g_object_unref (task);
        return;
    }

    qcdm_cmd_pilot_sets_result_get_num (result, QCDM_CMD_PILOT_SETS_TYPE_ACTIVE, &num);
    for (i = 0; i < num; i++) {
        guint32 pn_offset = 0, ecio = 0;
        gfloat db = 0;

        qcdm_cmd_pilot_sets_result_get_pilot (result,
                                              QCDM_CMD_PILOT_SETS_TYPE_ACTIVE,
                                              i,
                                              &pn_offset,
                                              &ecio,
                                              &db);
        best_db = MAX (db, best_db);
    }
    qcdm_result_unref (result);

    if (num > 0) {
        #define BEST_ECIO 3
        #define WORST_ECIO 25

        /* EC/IO dB ranges from roughly 0 to -31 dB.  Lower == worse.  We
         * really only care about -3 to -25 dB though, since that's about what
         * you'll see in real-world usage.
         */
        best_db = CLAMP (ABS (best_db), BEST_ECIO, WORST_ECIO) - BEST_ECIO;
        quality = (guint32) (100 - (best_db * 100 / (WORST_ECIO - BEST_ECIO)));
    }

    g_task_return_int (task, quality);
    g_object_unref (task);
}

static void
signal_quality_qcdm (GTask *task)
{
    MMBroadbandModem *self;
    SignalQualityContext *ctx;
    GByteArray *pilot_sets;
    guint quality;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    /* If EVDO is active try that signal strength first */
    quality = signal_quality_evdo_pilot_sets (self);
    if (quality > 0) {
        g_task_return_int (task, quality);
        g_object_unref (task);
        return;
    }

    /* Use CDMA1x pilot EC/IO if we can */
    pilot_sets = g_byte_array_sized_new (25);
    pilot_sets->len = qcdm_cmd_pilot_sets_new ((char *) pilot_sets->data, 25);
    g_assert (pilot_sets->len);

    mm_port_serial_qcdm_command (MM_PORT_SERIAL_QCDM (ctx->qcdm_port),
                                 pilot_sets,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)signal_quality_qcdm_ready,
                                 task);
    g_byte_array_unref (pilot_sets);
}

static void
modem_load_signal_quality (MMIfaceModem *_self,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    SignalQualityContext *ctx;
    GError *error = NULL;
    GTask *task;

    mm_dbg ("loading signal quality...");
    ctx = g_new0 (SignalQualityContext, 1);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)signal_quality_context_free);

    /* Check whether we can get a non-connected AT port */
    ctx->at_port = (MMPortSerial *)mm_base_modem_get_best_at_port (MM_BASE_MODEM (self), &error);
    if (ctx->at_port) {
        if (self->priv->modem_cind_supported &&
            CIND_INDICATOR_IS_VALID (self->priv->modem_cind_indicator_signal_quality))
            signal_quality_cind (task);
        else
            signal_quality_csq (task);
        return;
    }

    /* If no best AT port available (all connected), try with QCDM ports */
    ctx->qcdm_port = (MMPortSerial *)mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (ctx->qcdm_port) {
        g_clear_error (&error);

        /* Need to open QCDM port as it may be closed/blocked */
        if (mm_port_serial_open (MM_PORT_SERIAL (ctx->qcdm_port), &error)) {
            g_object_ref (ctx->qcdm_port);
            signal_quality_qcdm (task);
            return;
        }

        ctx->qcdm_port = NULL;
        mm_dbg ("Couldn't open QCDM port: %s", error->message);
    }

    /* Return the error we got when getting best AT port */
    g_task_return_error (task, error);
    g_object_unref (task);
}

/*****************************************************************************/
/* Load access technology (Modem interface) */

typedef struct {
    MMModemAccessTechnology access_technologies;
    guint mask;
} AccessTechAndMask;

static gboolean
modem_load_access_technologies_finish (MMIfaceModem *self,
                                       GAsyncResult *res,
                                       MMModemAccessTechnology *access_technologies,
                                       guint *mask,
                                       GError **error)
{
    AccessTechAndMask *tech;

    if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
        return FALSE;

    tech = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res));
    g_assert (tech);

    *access_technologies = tech->access_technologies;
    *mask = tech->mask;
    return TRUE;
}

typedef struct {
    MMBroadbandModem *self;
    GSimpleAsyncResult *result;
    MMPortSerialQcdm *port;

    guint32 opmode;
    guint32 sysmode;
    gboolean hybrid;

    gboolean wcdma_open;
    gboolean evdo_open;

    MMModemAccessTechnology fallback_act;
    guint fallback_mask;
} AccessTechContext;

static void
access_tech_context_complete_and_free (AccessTechContext *ctx,
                                       GError *error, /* takes ownership */
                                       gboolean idle)
{
    AccessTechAndMask *tech;
    MMModemAccessTechnology act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
    guint mask = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;

    if (error) {
        g_simple_async_result_take_error (ctx->result, error);
        goto done;
    }

    if (ctx->fallback_mask) {
        mm_dbg ("Fallback access technology: 0x%08x", ctx->fallback_act);
        act = ctx->fallback_act;
        mask = ctx->fallback_mask;
        goto done;
    }

    mm_dbg ("QCDM operating mode: %d", ctx->opmode);
    mm_dbg ("QCDM system mode: %d", ctx->sysmode);
    mm_dbg ("QCDM hybrid pref: %d", ctx->hybrid);
    mm_dbg ("QCDM WCDMA open: %d", ctx->wcdma_open);
    mm_dbg ("QCDM EVDO open: %d", ctx->evdo_open);

    if (ctx->opmode == QCDM_CMD_CM_SUBSYS_STATE_INFO_OPERATING_MODE_ONLINE) {
        switch (ctx->sysmode) {
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_CDMA:
            if (!ctx->hybrid || !ctx->evdo_open) {
                act = MM_MODEM_ACCESS_TECHNOLOGY_1XRTT;
                mask = MM_IFACE_MODEM_CDMA_ALL_ACCESS_TECHNOLOGIES_MASK;
                break;
            }
            /* Fall through */
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_HDR:
            /* Assume EVDOr0; can't yet determine r0 vs. rA with QCDM */
            if (ctx->evdo_open)
                act = MM_MODEM_ACCESS_TECHNOLOGY_EVDO0;
            mask = MM_IFACE_MODEM_CDMA_ALL_ACCESS_TECHNOLOGIES_MASK;
            break;
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_GSM:
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_GW:
            if (ctx->wcdma_open) {
                /* Assume UMTS; can't yet determine UMTS/HSxPA/HSPA+ with QCDM */
                act = MM_MODEM_ACCESS_TECHNOLOGY_UMTS;
            } else {
                /* Assume GPRS; can't yet determine GSM/GPRS/EDGE with QCDM */
                act = MM_MODEM_ACCESS_TECHNOLOGY_GPRS;
            }
            mask = MM_IFACE_MODEM_3GPP_ALL_ACCESS_TECHNOLOGIES_MASK;
            break;
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_WCDMA:
            if (ctx->wcdma_open) {
                /* Assume UMTS; can't yet determine UMTS/HSxPA/HSPA+ with QCDM */
                act = MM_MODEM_ACCESS_TECHNOLOGY_UMTS;
            }
            mask = MM_IFACE_MODEM_3GPP_ALL_ACCESS_TECHNOLOGIES_MASK;
            break;
        case QCDM_CMD_CM_SUBSYS_STATE_INFO_SYSTEM_MODE_LTE:
            act = MM_MODEM_ACCESS_TECHNOLOGY_LTE;
            mask = MM_IFACE_MODEM_3GPP_ALL_ACCESS_TECHNOLOGIES_MASK;
            break;
        }
    }

done:
    if (error == NULL) {
        tech = g_new0 (AccessTechAndMask, 1);
        tech->access_technologies = act;
        tech->mask = mask;
        g_simple_async_result_set_op_res_gpointer (ctx->result, tech, g_free);
    }

    if (idle)
        g_simple_async_result_complete_in_idle (ctx->result);
    else
        g_simple_async_result_complete (ctx->result);

    g_object_unref (ctx->result);
    g_object_unref (ctx->self);
    if (ctx->port) {
        mm_port_serial_close (MM_PORT_SERIAL (ctx->port));
        g_object_unref (ctx->port);
    }
    g_free (ctx);
}

static void
access_tech_qcdm_wcdma_ready (MMPortSerialQcdm *port,
                              GAsyncResult *res,
                              AccessTechContext *ctx)
{
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    guint8 l1;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_wcdma_subsys_state_info_result ((const gchar *) response->data,
                                                      response->len,
                                                      &err);
    g_byte_array_unref (response);
    if (result) {
        qcdm_result_get_u8 (result, QCDM_CMD_WCDMA_SUBSYS_STATE_INFO_ITEM_L1_STATE, &l1);
        qcdm_result_unref (result);

        if (l1 == QCDM_WCDMA_L1_STATE_PCH ||
            l1 == QCDM_WCDMA_L1_STATE_FACH ||
            l1 == QCDM_WCDMA_L1_STATE_DCH ||
            l1 == QCDM_WCDMA_L1_STATE_PCH_SLEEP)
            ctx->wcdma_open = TRUE;
    }

    access_tech_context_complete_and_free (ctx, NULL, FALSE);
}

static void
access_tech_qcdm_gsm_ready (MMPortSerialQcdm *port,
                            GAsyncResult *res,
                            AccessTechContext *ctx)
{
    GByteArray *cmd;
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    guint8 opmode = 0;
    guint8 sysmode = 0;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_gsm_subsys_state_info_result ((const gchar *) response->data,
                                                    response->len,
                                                    &err);
    g_byte_array_unref (response);
    if (!result) {
        error = g_error_new (MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Failed to parse GSM subsys command result: %d",
                             err);
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    qcdm_result_get_u8 (result, QCDM_CMD_GSM_SUBSYS_STATE_INFO_ITEM_CM_OP_MODE, &opmode);
    qcdm_result_get_u8 (result, QCDM_CMD_GSM_SUBSYS_STATE_INFO_ITEM_CM_SYS_MODE, &sysmode);
    qcdm_result_unref (result);

    ctx->opmode = opmode;
    ctx->sysmode = sysmode;

    /* WCDMA subsystem state */
    cmd = g_byte_array_sized_new (50);
    cmd->len = qcdm_cmd_wcdma_subsys_state_info_new ((char *) cmd->data, 50);
    g_assert (cmd->len);

    mm_port_serial_qcdm_command (port,
                                 cmd,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)access_tech_qcdm_wcdma_ready,
                                 ctx);
    g_byte_array_unref (cmd);
}

static void
access_tech_qcdm_hdr_ready (MMPortSerialQcdm *port,
                            GAsyncResult *res,
                            AccessTechContext *ctx)
{
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    guint8 session = 0;
    guint8 almp = 0;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_hdr_subsys_state_info_result ((const gchar *) response->data,
                                                    response->len,
                                                    &err);
    g_byte_array_unref (response);
    if (result) {
        qcdm_result_get_u8 (result, QCDM_CMD_HDR_SUBSYS_STATE_INFO_ITEM_SESSION_STATE, &session);
        qcdm_result_get_u8 (result, QCDM_CMD_HDR_SUBSYS_STATE_INFO_ITEM_ALMP_STATE, &almp);
        qcdm_result_unref (result);

        if (session == QCDM_CMD_HDR_SUBSYS_STATE_INFO_SESSION_STATE_OPEN &&
            (almp == QCDM_CMD_HDR_SUBSYS_STATE_INFO_ALMP_STATE_IDLE ||
             almp == QCDM_CMD_HDR_SUBSYS_STATE_INFO_ALMP_STATE_CONNECTED))
            ctx->evdo_open = TRUE;
    }

    access_tech_context_complete_and_free (ctx, NULL, FALSE);
}

static void
access_tech_qcdm_cdma_ready (MMPortSerialQcdm *port,
                             GAsyncResult *res,
                             AccessTechContext *ctx)
{
    GByteArray *cmd;
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    guint32 hybrid;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_cm_subsys_state_info_result ((const gchar *) response->data,
                                                   response->len,
                                                   &err);
    g_byte_array_unref (response);
    if (!result) {
        error = g_error_new (MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Failed to parse CM subsys command result: %d",
                             err);
        access_tech_context_complete_and_free (ctx, error, FALSE);
        return;
    }

    qcdm_result_get_u32 (result, QCDM_CMD_CM_SUBSYS_STATE_INFO_ITEM_OPERATING_MODE, &ctx->opmode);
    qcdm_result_get_u32 (result, QCDM_CMD_CM_SUBSYS_STATE_INFO_ITEM_SYSTEM_MODE, &ctx->sysmode);
    qcdm_result_get_u32 (result, QCDM_CMD_CM_SUBSYS_STATE_INFO_ITEM_HYBRID_PREF, &hybrid);
    qcdm_result_unref (result);

    ctx->hybrid = !!hybrid;

    /* HDR subsystem state */
    cmd = g_byte_array_sized_new (50);
    cmd->len = qcdm_cmd_hdr_subsys_state_info_new ((char *) cmd->data, 50);
    g_assert (cmd->len);

    mm_port_serial_qcdm_command (port,
                                 cmd,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)access_tech_qcdm_hdr_ready,
                                 ctx);
    g_byte_array_unref (cmd);
}

static void
access_tech_from_cdma_registration_state (MMBroadbandModem *self,
                                          AccessTechContext *ctx)
{
    gboolean cdma1x_registered = FALSE;
    gboolean evdo_registered = FALSE;

    if (self->priv->modem_cdma_evdo_registration_state > MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)
        evdo_registered = TRUE;

    if (self->priv->modem_cdma_cdma1x_registration_state > MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)
        cdma1x_registered = TRUE;

    if (self->priv->modem_cdma_evdo_network_supported && evdo_registered) {
        ctx->fallback_act = MM_MODEM_ACCESS_TECHNOLOGY_EVDO0;
        ctx->fallback_mask = MM_IFACE_MODEM_CDMA_ALL_ACCESS_TECHNOLOGIES_MASK;
    } else if (self->priv->modem_cdma_cdma1x_network_supported && cdma1x_registered) {
        ctx->fallback_act = MM_MODEM_ACCESS_TECHNOLOGY_1XRTT;
        ctx->fallback_mask = MM_IFACE_MODEM_CDMA_ALL_ACCESS_TECHNOLOGIES_MASK;
    }

    mm_dbg ("EVDO registration: %d", self->priv->modem_cdma_evdo_registration_state);
    mm_dbg ("CDMA1x registration: %d", self->priv->modem_cdma_cdma1x_registration_state);
    mm_dbg ("Fallback access tech: 0x%08x", ctx->fallback_act);
}

static void
modem_load_access_technologies (MMIfaceModem *self,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
    AccessTechContext *ctx;
    GByteArray *cmd;
    GError *error = NULL;

    /* For modems where only QCDM provides detailed information, try to
     * get access technologies via the various QCDM subsystems or from
     * registration state
     */
    ctx = g_new0 (AccessTechContext, 1);
    ctx->self = g_object_ref (self);
    ctx->result = g_simple_async_result_new (G_OBJECT (self),
                                             callback,
                                             user_data,
                                             modem_load_access_technologies);

    ctx->port = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (ctx->port) {
        /* Need to open QCDM port as it may be closed/blocked */
        if (mm_port_serial_open (MM_PORT_SERIAL (ctx->port), &error)) {
            g_object_ref (ctx->port);

            mm_dbg ("loading access technologies via QCDM...");

            /* FIXME: we may want to run both the CDMA and 3GPP in sequence to ensure
             * that a multi-mode device that's in CDMA-mode but still has 3GPP capabilities
             * will get the correct access tech, since the 3GPP check is run first.
             */

            if (mm_iface_modem_is_3gpp (self)) {
                cmd = g_byte_array_sized_new (50);
                cmd->len = qcdm_cmd_gsm_subsys_state_info_new ((char *) cmd->data, 50);
                g_assert (cmd->len);

                mm_port_serial_qcdm_command (ctx->port,
                                             cmd,
                                             3,
                                             NULL,
                                             (GAsyncReadyCallback)access_tech_qcdm_gsm_ready,
                                             ctx);
                g_byte_array_unref (cmd);
                return;
            }

            if (mm_iface_modem_is_cdma (self)) {
                cmd = g_byte_array_sized_new (50);
                cmd->len = qcdm_cmd_cm_subsys_state_info_new ((char *) cmd->data, 50);
                g_assert (cmd->len);

                mm_port_serial_qcdm_command (ctx->port,
                                             cmd,
                                             3,
                                             NULL,
                                             (GAsyncReadyCallback)access_tech_qcdm_cdma_ready,
                                             ctx);
                g_byte_array_unref (cmd);
                return;
            }

            g_assert_not_reached ();
        }

        ctx->port = NULL;
        mm_dbg ("Couldn't open QCDM port: %s", error->message);
        g_clear_error (&error);
    }

    /* Fall back if we don't have a QCDM port or it couldn't be opened */
    if (mm_iface_modem_is_cdma (self)) {
        /* If we don't have a QCDM port but the modem is CDMA-only, then
         * guess access technologies from the registration information.
         */
        access_tech_from_cdma_registration_state (MM_BROADBAND_MODEM (self), ctx);
    } else {
        error = g_error_new_literal (MM_CORE_ERROR,
                                     MM_CORE_ERROR_UNSUPPORTED,
                                     "Cannot get 3GPP access technology without a QCDM port");
    }
    access_tech_context_complete_and_free (ctx, error, TRUE);
}

/*****************************************************************************/
/* Setup/Cleanup unsolicited events (3GPP interface) */

static gboolean
modem_3gpp_setup_cleanup_unsolicited_events_finish (MMIfaceModem3gpp *self,
                                                    GAsyncResult *res,
                                                    GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
ciev_received (MMPortSerialAt *port,
               GMatchInfo *info,
               MMBroadbandModem *self)
{
    gint ind = 0;
    gchar *item;

    item = g_match_info_fetch (info, 1);
    if (item)
        ind = atoi (item);

    /* Handle signal quality change indication */
    if (ind == self->priv->modem_cind_indicator_signal_quality ||
        g_str_equal (item, "signal")) {
        gchar *value;

        value = g_match_info_fetch (info, 2);
        if (value) {
            gint quality = 0;

            quality = atoi (value);

            mm_iface_modem_update_signal_quality (
                MM_IFACE_MODEM (self),
                normalize_ciev_cind_signal_quality (quality,
                                                    self->priv->modem_cind_min_signal_quality,
                                                    self->priv->modem_cind_max_signal_quality));
            g_free (value);
        }
    }

    g_free (item);

    /* FIXME: handle roaming and service indicators.
     * ... wait, arent these already handle by unsolicited CREG responses? */
}

static void
set_unsolicited_events_handlers (MMBroadbandModem *self,
                                 gboolean enable)
{
    MMPortSerialAt *ports[2];
    GRegex *ciev_regex;
    guint i;

    ciev_regex = mm_3gpp_ciev_regex_get ();
    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Enable unsolicited events in given port */
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        /* Set/unset unsolicited CIEV event handler */
        mm_dbg ("(%s) %s 3GPP unsolicited events handlers",
                mm_port_get_device (MM_PORT (ports[i])),
                enable ? "Setting" : "Removing");
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            ciev_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) ciev_received : NULL,
            enable ? self : NULL,
            NULL);
    }

    g_regex_unref (ciev_regex);
}

static void
cmer_format_check_ready (MMBroadbandModem   *self,
                         GAsyncResult       *res,
                         GTask *task)
{
    MM3gppCmerMode  supported_modes = MM_3GPP_CMER_MODE_NONE;
    MM3gppCmerInd   supported_inds = MM_3GPP_CMER_IND_NONE;
    GError         *error = NULL;
    const gchar    *result;
    gchar          *aux;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error || !mm_3gpp_parse_cmer_test_response (result, &supported_modes, &supported_inds, &error)) {
        mm_dbg ("+CMER check failed, marking indications as unsupported: '%s'", error->message);
        g_error_free (error);
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    aux = mm_3gpp_cmer_mode_build_string_from_mask (supported_modes);
    mm_dbg ("Supported +CMER modes: %s", aux);
    g_free (aux);

    aux = mm_3gpp_cmer_ind_build_string_from_mask (supported_inds);
    mm_dbg ("Supported +CMER indication settings: %s", aux);
    g_free (aux);

    /* Flag +CMER supported values */

    if (supported_modes & MM_3GPP_CMER_MODE_FORWARD_URCS)
        self->priv->modem_cmer_enable_mode = MM_3GPP_CMER_MODE_FORWARD_URCS;
    else if (supported_modes & MM_3GPP_CMER_MODE_BUFFER_URCS_IF_LINK_RESERVED)
        self->priv->modem_cmer_enable_mode = MM_3GPP_CMER_MODE_BUFFER_URCS_IF_LINK_RESERVED;
    else if (supported_modes & MM_3GPP_CMER_MODE_DISCARD_URCS_IF_LINK_RESERVED)
        self->priv->modem_cmer_enable_mode = MM_3GPP_CMER_MODE_DISCARD_URCS_IF_LINK_RESERVED;

    aux = mm_3gpp_cmer_mode_build_string_from_mask (self->priv->modem_cmer_enable_mode);
    mm_dbg ("+CMER enable mode: %s", aux);
    g_free (aux);

    if (supported_modes & MM_3GPP_CMER_MODE_DISCARD_URCS)
        self->priv->modem_cmer_disable_mode = MM_3GPP_CMER_MODE_DISCARD_URCS;

    aux = mm_3gpp_cmer_mode_build_string_from_mask (self->priv->modem_cmer_disable_mode);
    mm_dbg ("+CMER disable mode: %s", aux);
    g_free (aux);

    if (supported_inds & MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND)
        self->priv->modem_cmer_ind = MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND;
    else if (supported_inds & MM_3GPP_CMER_IND_ENABLE_ALL)
        self->priv->modem_cmer_ind = MM_3GPP_CMER_IND_ENABLE_ALL;

    aux = mm_3gpp_cmer_ind_build_string_from_mask (self->priv->modem_cmer_ind);
    mm_dbg ("+CMER indication setting: %s", aux);
    g_free (aux);

    /* Now, keep on setting up the ports */
    set_unsolicited_events_handlers (self, TRUE);

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
cind_format_check_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    GHashTable *indicators = NULL;
    GError *error = NULL;
    const gchar *result;
    MM3gppCindResponse *r;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error ||
        !(indicators = mm_3gpp_parse_cind_test_response (result, &error))) {
        /* unsupported indications */
        mm_dbg ("+CIND check failed, marking indications as unsupported: '%s'", error->message);
        g_error_free (error);
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    /* Mark CIND as being supported and find the proper indexes for the
     * indicators. */
    self->priv->modem_cind_supported = TRUE;

    /* Check if we support signal quality indications */
    r = g_hash_table_lookup (indicators, "signal");
    if (r) {
        self->priv->modem_cind_indicator_signal_quality = mm_3gpp_cind_response_get_index (r);
        self->priv->modem_cind_min_signal_quality = mm_3gpp_cind_response_get_min (r);
        self->priv->modem_cind_max_signal_quality = mm_3gpp_cind_response_get_max (r);

        mm_dbg ("Modem supports signal quality indications via CIND at index '%u'"
                "(min: %u, max: %u)",
                self->priv->modem_cind_indicator_signal_quality,
                self->priv->modem_cind_min_signal_quality,
                self->priv->modem_cind_max_signal_quality);
    } else
        self->priv->modem_cind_indicator_signal_quality = CIND_INDICATOR_INVALID;

    /* Check if we support roaming indications */
    r = g_hash_table_lookup (indicators, "roam");
    if (r) {
        self->priv->modem_cind_indicator_roaming = mm_3gpp_cind_response_get_index (r);
        mm_dbg ("Modem supports roaming indications via CIND at index '%u'",
                self->priv->modem_cind_indicator_roaming);
    } else
        self->priv->modem_cind_indicator_roaming = CIND_INDICATOR_INVALID;

    /* Check if we support service indications */
    r = g_hash_table_lookup (indicators, "service");
    if (r) {
        self->priv->modem_cind_indicator_service = mm_3gpp_cind_response_get_index (r);
        mm_dbg ("Modem supports service indications via CIND at index '%u'",
                self->priv->modem_cind_indicator_service);
    } else
        self->priv->modem_cind_indicator_service = CIND_INDICATOR_INVALID;

    g_hash_table_destroy (indicators);

    /* Check +CMER required format */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CMER=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cmer_format_check_ready,
                              task);
}

static void
modem_3gpp_setup_unsolicited_events (MMIfaceModem3gpp *_self,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Load supported indicators */
    if (!self->priv->modem_cind_support_checked) {
        mm_dbg ("Checking indicator support...");
        self->priv->modem_cind_support_checked = TRUE;
        mm_base_modem_at_command (MM_BASE_MODEM (self),
                                  "+CIND=?",
                                  3,
                                  TRUE,
                                  (GAsyncReadyCallback)cind_format_check_ready,
                                  task);
        return;
    }

    /* If supported, go on */
    if (self->priv->modem_cind_supported)
        set_unsolicited_events_handlers (self, TRUE);

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_cleanup_unsolicited_events (MMIfaceModem3gpp *_self,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* If supported, go on */
    if (self->priv->modem_cind_support_checked && self->priv->modem_cind_supported)
        set_unsolicited_events_handlers (self, FALSE);

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Enabling/disabling unsolicited events (3GPP interface) */

typedef struct {
    gchar *command;
    gboolean enable;
    gboolean cmer_primary_done;
    gboolean cmer_secondary_done;
} UnsolicitedEventsContext;

static void
unsolicited_events_context_free (UnsolicitedEventsContext *ctx)
{
    g_free (ctx->command);
    g_free (ctx);
}

static gboolean
modem_3gpp_enable_disable_unsolicited_events_finish (MMIfaceModem3gpp *self,
                                                     GAsyncResult *res,
                                                     GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void run_unsolicited_events_setup (GTask *task);

static void
unsolicited_events_setup_ready (MMBroadbandModem *self,
                                GAsyncResult *res,
                                GTask *task)
{
    UnsolicitedEventsContext *ctx;
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (!error) {
        /* Run on next port, if any */
        run_unsolicited_events_setup (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    mm_dbg ("Couldn't %s event reporting: '%s'",
            ctx->enable ? "enable" : "disable",
            error->message);
    g_error_free (error);
    /* Consider this operation complete, ignoring errors */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
run_unsolicited_events_setup (GTask *task)
{
    MMBroadbandModem *self;
    UnsolicitedEventsContext *ctx;
    MMPortSerialAt *port = NULL;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    if (!ctx->cmer_primary_done) {
        ctx->cmer_primary_done = TRUE;
        port = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    } else if (!ctx->cmer_secondary_done) {
        ctx->cmer_secondary_done = TRUE;
        port = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));
    }

    /* Enable unsolicited events in given port */
    if (port) {
        mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                       port,
                                       ctx->command,
                                       3,
                                       FALSE,
                                       FALSE, /* raw */
                                       NULL, /* cancellable */
                                       (GAsyncReadyCallback)unsolicited_events_setup_ready,
                                       task);
        return;
    }

    /* If no more ports, we're fully done now */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_enable_unsolicited_events (MMIfaceModem3gpp *_self,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* If supported, go on */
    if (self->priv->modem_cind_support_checked && self->priv->modem_cind_supported) {
        gchar *cmd;

        /* If CMER command available, launch it */
        cmd = mm_3gpp_build_cmer_set_request (self->priv->modem_cmer_enable_mode, self->priv->modem_cmer_ind);
        if (cmd) {
            UnsolicitedEventsContext *ctx;

            ctx = g_new0 (UnsolicitedEventsContext, 1);
            ctx->enable = TRUE;
            ctx->command = cmd;

            g_task_set_task_data (task, ctx, (GDestroyNotify)unsolicited_events_context_free);

            run_unsolicited_events_setup (task);
            return;
        }
        mm_dbg ("Skipping +CMER enable command: not supported");
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_disable_unsolicited_events (MMIfaceModem3gpp *_self,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* If CIND supported, go on */
    if (self->priv->modem_cind_support_checked && self->priv->modem_cind_supported) {
        gchar *cmd;

        /* If CMER command available, launch it */
        cmd = mm_3gpp_build_cmer_set_request (self->priv->modem_cmer_disable_mode, MM_3GPP_CMER_IND_NONE);
        if (cmd) {
            UnsolicitedEventsContext *ctx;

            ctx = g_new0 (UnsolicitedEventsContext, 1);
            ctx->command = cmd;

            g_task_set_task_data (task, ctx, (GDestroyNotify)unsolicited_events_context_free);

            run_unsolicited_events_setup (task);
            return;
        }
        mm_dbg ("Skipping +CMER disable command: not supported");
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Setting modem charset (Modem interface) */

typedef struct {
    MMModemCharset charset;
    /* Commands to try in the sequence:
     *  First one with quotes
     *  Second without.
     *  + last NUL */
    MMBaseModemAtCommand charset_commands[3];
} SetupCharsetContext;

static void
setup_charset_context_free (SetupCharsetContext *ctx)
{
    g_free (ctx->charset_commands[0].command);
    g_free (ctx->charset_commands[1].command);
    g_free (ctx);
}

static gboolean
modem_setup_charset_finish (MMIfaceModem *self,
                            GAsyncResult *res,
                            GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
current_charset_query_ready (MMBroadbandModem *self,
                             GAsyncResult *res,
                             GTask *task)
{
    SetupCharsetContext *ctx;
    GError *error = NULL;
    const gchar *response;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (!response)
        g_task_return_error (task, error);
    else {
        MMModemCharset current;
        const gchar *p;

        p = response;
        if (g_str_has_prefix (p, "+CSCS:"))
            p += 6;
        while (*p == ' ')
            p++;

        current = mm_modem_charset_from_string (p);
        if (ctx->charset != current)
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "Modem failed to change character set to %s",
                                     mm_modem_charset_to_string (ctx->charset));
        else {
            /* We'll keep track ourselves of the current charset.
             * TODO: Make this a property so that plugins can also store it. */
            self->priv->modem_current_charset = current;
            g_task_return_boolean (task, TRUE);
        }
    }

    g_object_unref (task);
}

static void
charset_change_ready (MMBroadbandModem *self,
                      GAsyncResult *res,
                      GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Check whether we did properly set the charset */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CSCS?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)current_charset_query_ready,
                              task);
}

static void
modem_setup_charset (MMIfaceModem *self,
                     MMModemCharset charset,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
    SetupCharsetContext *ctx;
    const gchar *charset_str;
    GTask *task;

    /* NOTE: we already notified that CDMA-only modems couldn't load supported
     * charsets, so we'll never get here in such a case */
    g_assert (mm_iface_modem_is_cdma_only (self) == FALSE);

    /* Build charset string to use */
    charset_str = mm_modem_charset_to_string (charset);
    if (!charset_str) {
        g_task_report_new_error (self,
                                 callback,
                                 user_data,
                                 modem_setup_charset,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Unhandled character set 0x%X",
                                 charset);
        return;
    }

    /* Setup context, including commands to try */
    ctx = g_new0 (SetupCharsetContext, 1);
    ctx->charset = charset;
    /* First try, with quotes */
    ctx->charset_commands[0].command = g_strdup_printf ("+CSCS=\"%s\"", charset_str);
    ctx->charset_commands[0].timeout = 3;
    ctx->charset_commands[0].allow_cached = FALSE;
    ctx->charset_commands[0].response_processor = mm_base_modem_response_processor_no_result;
    /* Second try.
     * Some modems puke if you include the quotes around the character
     * set name, so lets try it again without them.
     */
    ctx->charset_commands[1].command = g_strdup_printf ("+CSCS=%s", charset_str);
    ctx->charset_commands[1].timeout = 3;
    ctx->charset_commands[1].allow_cached = FALSE;
    ctx->charset_commands[1].response_processor = mm_base_modem_response_processor_no_result;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)setup_charset_context_free);

    /* Launch sequence */
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        ctx->charset_commands,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        (GAsyncReadyCallback)charset_change_ready,
        task);
}

/*****************************************************************************/
/* Loading supported charsets (Modem interface) */

static MMModemCharset
modem_load_supported_charsets_finish (MMIfaceModem *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_CHARSET_UNKNOWN;
    }
    return (MMModemCharset)value;
}

static void
cscs_format_check_ready (MMBaseModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    MMModemCharset charsets = MM_MODEM_CHARSET_UNKNOWN;
    const gchar *response;
    GError *error = NULL;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (error)
        g_task_return_error (task, error);
    else if (!mm_3gpp_parse_cscs_test_response (response, &charsets))
        g_task_return_new_error (
            task,
            MM_CORE_ERROR,
            MM_CORE_ERROR_FAILED,
            "Failed to parse the supported character sets response");
    else
        g_task_return_int (task, charsets);

    g_object_unref (task);
}

static void
modem_load_supported_charsets (MMIfaceModem *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* CDMA-only modems don't need this */
    if (mm_iface_modem_is_cdma_only (self)) {
        mm_dbg ("Skipping supported charset loading in CDMA-only modem...");
        g_task_return_int (task, MM_MODEM_CHARSET_UNKNOWN);
        g_object_unref (task);
        return;
    }

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CSCS=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cscs_format_check_ready,
                              task);
}

/*****************************************************************************/
/* configuring flow control (Modem interface) */

static gboolean
modem_setup_flow_control_finish (MMIfaceModem  *self,
                                 GAsyncResult  *res,
                                 GError       **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
ifc_test_ready (MMBaseModem  *_self,
                GAsyncResult *res,
                GTask        *task)
{
    MMBroadbandModem *self;
    GError           *error = NULL;
    const gchar      *response;
    MMFlowControl     mask;
    const gchar      *cmd;

    self = MM_BROADBAND_MODEM (_self);

    /* Completely ignore errors in AT+IFC=? */
    response = mm_base_modem_at_command_finish (_self, res, &error);
    if (!response)
        goto out;

    /* Parse response */
    mask = mm_parse_ifc_test_response (response, &error);
    if (mask == MM_FLOW_CONTROL_UNKNOWN)
        goto out;

    /* We prefer the methods in this order:
     *  RTS/CTS
     *  XON/XOFF
     *  None.
     */
    if (mask & MM_FLOW_CONTROL_RTS_CTS) {
        self->priv->flow_control = MM_FLOW_CONTROL_RTS_CTS;
        cmd = "+IFC=2,2";
    } else if (mask & MM_FLOW_CONTROL_XON_XOFF) {
        self->priv->flow_control = MM_FLOW_CONTROL_XON_XOFF;
        cmd = "+IFC=1,1";
    } else if (mask & MM_FLOW_CONTROL_NONE) {
        self->priv->flow_control = MM_FLOW_CONTROL_NONE;
        cmd = "+IFC=0,0";
    } else
        g_assert_not_reached ();

    /* Notify the flow control property update */
    g_object_notify_by_pspec (G_OBJECT (self), properties[PROP_FLOW_CONTROL]);

    /* Set flow control settings and ignore result */
    mm_base_modem_at_command (_self, cmd, 3, FALSE, NULL, NULL);

out:
    /* Ignore errors */
    if (error) {
        mm_dbg ("couldn't load supported flow control methods: %s", error->message);
        g_error_free (error);
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_setup_flow_control (MMIfaceModem *self,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Query supported flow control methods */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+IFC=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)ifc_test_ready,
                              task);
}

/*****************************************************************************/
/* Power state loading (Modem interface) */

static MMModemPowerState
modem_load_power_state_finish (MMIfaceModem *self,
                               GAsyncResult *res,
                               GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_POWER_STATE_UNKNOWN;
    }
    return (MMModemPowerState)value;
}

static void
cfun_query_ready (MMBaseModem *self,
                  GAsyncResult *res,
                  GTask *task)
{
    const gchar *result;
    MMModemPowerState state;
    GError *error = NULL;

    result = mm_base_modem_at_command_finish (self, res, &error);
    if (!result || !mm_3gpp_parse_cfun_query_generic_response (result, &state, &error))
        g_task_return_error (task, error);
    else
        g_task_return_int (task, state);;

    g_object_unref (task);
}

static void
modem_load_power_state (MMIfaceModem *self,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* CDMA-only modems don't need this */
    if (mm_iface_modem_is_cdma_only (self)) {
        mm_dbg ("Assuming full power state in CDMA-only modem...");
        g_task_return_int (task, MM_MODEM_POWER_STATE_ON);
        g_object_unref (task);
        return;
    }

    mm_dbg ("loading power state...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CFUN?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)cfun_query_ready,
                              task);
}

/*****************************************************************************/
/* Powering up the modem (Modem interface) */

static gboolean
modem_power_up_finish (MMIfaceModem *self,
                       GAsyncResult *res,
                       GError **error)
{
    /* By default, errors in the power up command are ignored.
     * Plugins wanting to treat power up errors should subclass the power up
     * handling. */
    return TRUE;
}

static void
modem_power_up (MMIfaceModem *self,
                GAsyncReadyCallback callback,
                gpointer user_data)
{
    GTask *task;

    /* CDMA-only modems don't need this */
    if (mm_iface_modem_is_cdma_only (self))
        mm_dbg ("Skipping Power-up in CDMA-only modem...");
    else
        mm_base_modem_at_command (MM_BASE_MODEM (self),
                                  "+CFUN=1",
                                  5,
                                  FALSE,
                                  NULL,
                                  NULL);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Sending a command to the modem (Modem interface) */

static const gchar *
modem_command_finish (MMIfaceModem *self,
                      GAsyncResult *res,
                      GError **error)
{
    return mm_base_modem_at_command_finish (MM_BASE_MODEM (self),
                                            res,
                                            error);
}

static void
modem_command (MMIfaceModem *self,
               const gchar *cmd,
               guint timeout,
               GAsyncReadyCallback callback,
               gpointer user_data)
{

    mm_base_modem_at_command (MM_BASE_MODEM (self), cmd, timeout,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* IMEI loading (3GPP interface) */

static gchar *
modem_3gpp_load_imei_finish (MMIfaceModem3gpp *self,
                             GAsyncResult *res,
                             GError **error)
{
    const gchar *result;
    gchar *imei = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    result = mm_strip_tag (result, "+CGSN:");
    mm_parse_gsn (result, &imei, NULL, NULL);
    mm_dbg ("loaded IMEI: %s", imei);
    return imei;
}

static void
modem_3gpp_load_imei (MMIfaceModem3gpp *self,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    mm_dbg ("loading IMEI...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CGSN",
                              3,
                              TRUE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Facility locks status loading (3GPP interface) */

typedef struct {
    guint current;
    MMModem3gppFacility facilities;
    MMModem3gppFacility locks;
} LoadEnabledFacilityLocksContext;

static void get_next_facility_lock_status (GTask *task);

static MMModem3gppFacility
modem_3gpp_load_enabled_facility_locks_finish (MMIfaceModem3gpp *self,
                                               GAsyncResult *res,
                                               GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_3GPP_FACILITY_NONE;
    }
    return (MMModem3gppFacility)value;
}

static void
clck_single_query_ready (MMBaseModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    LoadEnabledFacilityLocksContext *ctx;
    const gchar *response;
    gboolean enabled = FALSE;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (self, res, NULL);
    if (response &&
        mm_3gpp_parse_clck_write_response (response, &enabled) &&
        enabled) {
        ctx->locks |= (1 << ctx->current);
    } else {
        /* On errors, we'll just assume disabled */
        ctx->locks &= ~(1 << ctx->current);
    }

    /* And go on with the next one */
    ctx->current++;
    get_next_facility_lock_status (task);
}

static void
get_next_facility_lock_status (GTask *task)
{
    MMBroadbandModem *self;
    LoadEnabledFacilityLocksContext *ctx;
    guint i;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    for (i = ctx->current; i < sizeof (MMModem3gppFacility) * 8; i++) {
        guint32 facility = 1u << i;

        /* Found the next one to query! */
        if (ctx->facilities & facility) {
            gchar *cmd;

            /* Keep the current one */
            ctx->current = i;

            /* Query current */
            cmd = g_strdup_printf ("+CLCK=\"%s\",2",
                                   mm_3gpp_facility_to_acronym (facility));
            mm_base_modem_at_command (MM_BASE_MODEM (self),
                                      cmd,
                                      3,
                                      FALSE,
                                      (GAsyncReadyCallback)clck_single_query_ready,
                                      task);
            g_free (cmd);
            return;
        }
    }

    /* No more facilities to query, all done */
    g_task_return_int (task, ctx->locks);
    g_object_unref (task);
}

static void
clck_test_ready (MMBaseModem *self,
                 GAsyncResult *res,
                 GTask *task)
{
    LoadEnabledFacilityLocksContext *ctx;
    const gchar *response;
    GError *error = NULL;

    response = mm_base_modem_at_command_finish (self, res, &error);
    if (!response) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    if (!mm_3gpp_parse_clck_test_response (response, &ctx->facilities)) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Couldn't parse list of available lock facilities: '%s'",
                                 response);
        g_object_unref (task);
        return;
    }

    /* Ignore facility locks specified by the plugins */
    if (MM_BROADBAND_MODEM (self)->priv->modem_3gpp_ignored_facility_locks) {
        gchar *str;

        str = mm_modem_3gpp_facility_build_string_from_mask (MM_BROADBAND_MODEM (self)->priv->modem_3gpp_ignored_facility_locks);
        mm_dbg ("Ignoring facility locks: '%s'", str);
        g_free (str);

        ctx->facilities &= ~MM_BROADBAND_MODEM (self)->priv->modem_3gpp_ignored_facility_locks;
    }

    /* Go on... */
    get_next_facility_lock_status (task);
}

static void
modem_3gpp_load_enabled_facility_locks (MMIfaceModem3gpp *self,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
    LoadEnabledFacilityLocksContext *ctx;
    GTask *task;

    ctx = g_new (LoadEnabledFacilityLocksContext, 1);
    ctx->facilities = MM_MODEM_3GPP_FACILITY_NONE;
    ctx->locks = MM_MODEM_3GPP_FACILITY_NONE;
    ctx->current = 0;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, g_free);

    mm_dbg ("loading enabled facility locks...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CLCK=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)clck_test_ready,
                              task);
}

/*****************************************************************************/
/* Operator Code loading (3GPP interface) */

static gchar *
modem_3gpp_load_operator_code_finish (MMIfaceModem3gpp *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    const gchar *result;
    gchar *operator_code = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    if (!mm_3gpp_parse_cops_read_response (result,
                                           NULL, /* mode */
                                           NULL, /* format */
                                           &operator_code,
                                           NULL, /* act */
                                           error))
        return NULL;

    mm_3gpp_normalize_operator (&operator_code, MM_BROADBAND_MODEM (self)->priv->modem_current_charset);
    if (operator_code)
        mm_dbg ("loaded Operator Code: %s", operator_code);
    return operator_code;
}

static void
modem_3gpp_load_operator_code (MMIfaceModem3gpp *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    mm_dbg ("loading Operator Code...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+COPS=3,2;+COPS?",
                              3,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Operator Name loading (3GPP interface) */

static gchar *
modem_3gpp_load_operator_name_finish (MMIfaceModem3gpp *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    const gchar *result;
    gchar *operator_name = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    if (!mm_3gpp_parse_cops_read_response (result,
                                           NULL, /* mode */
                                           NULL, /* format */
                                           &operator_name,
                                           NULL, /* act */
                                           error))
        return NULL;

    mm_3gpp_normalize_operator (&operator_name, MM_BROADBAND_MODEM (self)->priv->modem_current_charset);
    if (operator_name)
        mm_dbg ("loaded Operator Name: %s", operator_name);
    return operator_name;
}

static void
modem_3gpp_load_operator_name (MMIfaceModem3gpp *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    mm_dbg ("loading Operator Name...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+COPS=3,0;+COPS?",
                              3,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Subscription State Loading (3GPP interface) */

static MMModem3gppSubscriptionState
modem_3gpp_load_subscription_state_finish (MMIfaceModem3gpp *self,
                                           GAsyncResult *res,
                                           GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_3GPP_SUBSCRIPTION_STATE_UNKNOWN;
    }
    return (MMModem3gppSubscriptionState)value;
}

static void
modem_3gpp_load_subscription_state (MMIfaceModem3gpp *self,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_int (task, MM_MODEM_3GPP_SUBSCRIPTION_STATE_UNKNOWN);
    g_object_unref (task);
}

/*****************************************************************************/
/* Unsolicited registration messages handling (3GPP interface) */

static gboolean
modem_3gpp_setup_unsolicited_registration_events_finish (MMIfaceModem3gpp *self,
                                                         GAsyncResult *res,
                                                         GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
registration_state_changed (MMPortSerialAt *port,
                            GMatchInfo *match_info,
                            MMBroadbandModem *self)
{
    MMModem3gppRegistrationState state = MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;
    gulong lac = 0, cell_id = 0;
    MMModemAccessTechnology act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
    gboolean cgreg = FALSE;
    gboolean cereg = FALSE;
    GError *error = NULL;

    if (!mm_3gpp_parse_creg_response (match_info,
                                      &state,
                                      &lac,
                                      &cell_id,
                                      &act,
                                      &cgreg,
                                      &cereg,
                                      &error)) {
        mm_warn ("error parsing unsolicited registration: %s",
                 error && error->message ? error->message : "(unknown)");
        g_clear_error (&error);
        return;
    }

    /* Report new registration state */
    if (cgreg)
        mm_iface_modem_3gpp_update_ps_registration_state (MM_IFACE_MODEM_3GPP (self), state);
    else if (cereg)
        mm_iface_modem_3gpp_update_eps_registration_state (MM_IFACE_MODEM_3GPP (self), state);
    else
        mm_iface_modem_3gpp_update_cs_registration_state (MM_IFACE_MODEM_3GPP (self), state);

    /* Only update access technologies from CREG/CGREG response if the modem
     * doesn't have custom commands for access technology loading, otherwise
     * we fight with the custom commands.  Plus CREG/CGREG access technologies
     * don't have fine-grained distinction between HSxPA or GPRS/EDGE, etc.
     */
    if (MM_IFACE_MODEM_GET_INTERFACE (self)->load_access_technologies == modem_load_access_technologies ||
        MM_IFACE_MODEM_GET_INTERFACE (self)->load_access_technologies == NULL)
        mm_iface_modem_3gpp_update_access_technologies (MM_IFACE_MODEM_3GPP (self), act);

    mm_iface_modem_3gpp_update_location (MM_IFACE_MODEM_3GPP (self), lac, cell_id);
}

static void
modem_3gpp_setup_unsolicited_registration_events (MMIfaceModem3gpp *self,
                                                  GAsyncReadyCallback callback,
                                                  gpointer user_data)
{
    MMPortSerialAt *ports[2];
    GPtrArray *array;
    guint i;
    guint j;
    GTask *task;

    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Set up CREG unsolicited message handlers in both ports */
    array = mm_3gpp_creg_regex_get (FALSE);
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        mm_dbg ("(%s) setting up 3GPP unsolicited registration messages handlers",
                mm_port_get_device (MM_PORT (ports[i])));
        for (j = 0; j < array->len; j++) {
            mm_port_serial_at_add_unsolicited_msg_handler (
                MM_PORT_SERIAL_AT (ports[i]),
                (GRegex *) g_ptr_array_index (array, j),
                (MMPortSerialAtUnsolicitedMsgFn)registration_state_changed,
                self,
                NULL);
        }
    }
    mm_3gpp_creg_regex_destroy (array);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Unsolicited registration messages cleaning up (3GPP interface) */

static gboolean
modem_3gpp_cleanup_unsolicited_registration_events_finish (MMIfaceModem3gpp *self,
                                                           GAsyncResult *res,
                                                           GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
modem_3gpp_cleanup_unsolicited_registration_events (MMIfaceModem3gpp *self,
                                                    GAsyncReadyCallback callback,
                                                    gpointer user_data)
{
    MMPortSerialAt *ports[2];
    GPtrArray *array;
    guint i;
    guint j;
    GTask *task;

    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Set up CREG unsolicited message handlers in both ports */
    array = mm_3gpp_creg_regex_get (FALSE);
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        mm_dbg ("(%s) cleaning up unsolicited registration messages handlers",
                mm_port_get_device (MM_PORT (ports[i])));

        for (j = 0; j < array->len; j++) {
            mm_port_serial_at_add_unsolicited_msg_handler (
                MM_PORT_SERIAL_AT (ports[i]),
                (GRegex *) g_ptr_array_index (array, j),
                NULL,
                NULL,
                NULL);
        }
    }
    mm_3gpp_creg_regex_destroy (array);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Scan networks (3GPP interface) */

static GList *
modem_3gpp_scan_networks_finish (MMIfaceModem3gpp *self,
                                 GAsyncResult *res,
                                 GError **error)
{
    const gchar *result;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    return mm_3gpp_parse_cops_test_response (result, error);
}

static void
modem_3gpp_scan_networks (MMIfaceModem3gpp *self,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+COPS=?",
                              300,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Register in network (3GPP interface) */

static gboolean
modem_3gpp_register_in_network_finish (MMIfaceModem3gpp *self,
                                       GAsyncResult *res,
                                       GError **error)
{
    return !!mm_base_modem_at_command_full_finish (MM_BASE_MODEM (self), res, error);
}

static void
modem_3gpp_register_in_network (MMIfaceModem3gpp *self,
                                const gchar *operator_id,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
    gchar *command;

    /* If the user sent a specific network to use, lock it in. */
    if (operator_id)
        command = g_strdup_printf ("+COPS=1,2,\"%s\"", operator_id);
    /* If no specific network was given, and the modem is not registered and not
     * searching, kick it to search for a network. Also do auto registration if
     * the modem had been set to manual registration last time but now is not.
     */
    else
        /* Note that '+COPS=0,,' (same but with commas) won't work in some Nokia
         * phones */
        command = g_strdup ("+COPS=0");

    mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                   mm_base_modem_peek_best_at_port (MM_BASE_MODEM (self), NULL),
                                   command,
                                   120,
                                   FALSE,
                                   FALSE, /* raw */
                                   cancellable,
                                   callback,
                                   user_data);
    g_free (command);
}

/*****************************************************************************/
/* Registration checks (3GPP interface) */

typedef struct {
    gboolean cs_supported;
    gboolean ps_supported;
    gboolean eps_supported;
    gboolean run_cs;
    gboolean run_ps;
    gboolean run_eps;
    gboolean running_cs;
    gboolean running_ps;
    gboolean running_eps;
    GError *cs_error;
    GError *ps_error;
    GError *eps_error;
} RunRegistrationChecksContext;

static void
run_registration_checks_context_free (RunRegistrationChecksContext *ctx)
{
    if (ctx->cs_error)
        g_error_free (ctx->cs_error);
    if (ctx->ps_error)
        g_error_free (ctx->ps_error);
    if (ctx->eps_error)
        g_error_free (ctx->eps_error);
    g_free (ctx);
}

static gboolean
modem_3gpp_run_registration_checks_finish (MMIfaceModem3gpp *self,
                                           GAsyncResult *res,
                                           GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void run_registration_checks_context_step (GTask *task);

static void
registration_status_check_ready (MMBroadbandModem *self,
                                 GAsyncResult *res,
                                 GTask *task)
{
    RunRegistrationChecksContext *ctx;
    const gchar *response;
    GError *error = NULL;
    GMatchInfo *match_info = NULL;
    guint i;
    gboolean parsed;
    gboolean cgreg;
    gboolean cereg;
    MMModem3gppRegistrationState state;
    MMModemAccessTechnology act;
    gulong lac;
    gulong cid;

    ctx = g_task_get_task_data (task);

    /* Only one must be running */
    g_assert ((ctx->running_cs ? 1 : 0) +
              (ctx->running_ps ? 1 : 0) +
              (ctx->running_eps ? 1 : 0) == 1);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (!response) {
        g_assert (error != NULL);
        if (ctx->running_cs)
            ctx->cs_error = error;
        else if (ctx->running_ps)
            ctx->ps_error = error;
        else
            ctx->eps_error = error;

        run_registration_checks_context_step (task);
        return;
    }

    /* Unsolicited registration status handlers will usually process the
     * response for us, but just in case they don't, do that here.
     */
    if (!response[0]) {
        /* Done */
        run_registration_checks_context_step (task);
        return;
    }

    /* Try to match the response */
    for (i = 0;
         i < self->priv->modem_3gpp_registration_regex->len;
         i++) {
        if (g_regex_match ((GRegex *)g_ptr_array_index (
                               self->priv->modem_3gpp_registration_regex, i),
                           response,
                           0,
                           &match_info))
            break;
        g_match_info_free (match_info);
        match_info = NULL;
    }

    if (!match_info) {
        error = g_error_new (MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Unknown registration status response: '%s'",
                             response);
        if (ctx->running_cs)
            ctx->cs_error = error;
        else if (ctx->running_ps)
            ctx->ps_error = error;
        else
            ctx->eps_error = error;

        run_registration_checks_context_step (task);
        return;
    }

    cgreg = FALSE;
    cereg = FALSE;
    state = MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;
    act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
    lac = 0;
    cid = 0;
    parsed = mm_3gpp_parse_creg_response (match_info,
                                          &state,
                                          &lac,
                                          &cid,
                                          &act,
                                          &cgreg,
                                          &cereg,
                                          &error);
    g_match_info_free (match_info);

    if (!parsed) {
        if (!error)
            error = g_error_new (MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Error parsing registration response: '%s'",
                                 response);
        if (ctx->running_cs)
            ctx->cs_error = error;
        else if (ctx->running_ps)
            ctx->ps_error = error;
        else
            ctx->eps_error = error;
        run_registration_checks_context_step (task);
        return;
    }

    /* Report new registration state */
    if (cgreg) {
        if (ctx->running_cs)
            mm_dbg ("Got PS registration state when checking CS registration state");
        else if (ctx->running_eps)
            mm_dbg ("Got PS registration state when checking EPS registration state");
        mm_iface_modem_3gpp_update_ps_registration_state (MM_IFACE_MODEM_3GPP (self), state);
    } else if (cereg) {
        if (ctx->running_cs)
            mm_dbg ("Got EPS registration state when checking CS registration state");
        else if (ctx->running_ps)
            mm_dbg ("Got EPS registration state when checking PS registration state");
        mm_iface_modem_3gpp_update_eps_registration_state (MM_IFACE_MODEM_3GPP (self), state);
    } else {
        if (ctx->running_ps)
            mm_dbg ("Got CS registration state when checking PS registration state");
        else if (ctx->running_eps)
            mm_dbg ("Got CS registration state when checking EPS registration state");
        mm_iface_modem_3gpp_update_cs_registration_state (MM_IFACE_MODEM_3GPP (self), state);
    }

    mm_iface_modem_3gpp_update_access_technologies (MM_IFACE_MODEM_3GPP (self), act);
    mm_iface_modem_3gpp_update_location (MM_IFACE_MODEM_3GPP (self), lac, cid);

    run_registration_checks_context_step (task);
}

static void
run_registration_checks_context_step (GTask *task)
{
    MMBroadbandModem *self;
    RunRegistrationChecksContext *ctx;
    GError *error = NULL;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    ctx->running_cs = FALSE;
    ctx->running_ps = FALSE;
    ctx->running_eps = FALSE;

    if (ctx->run_cs) {
        ctx->running_cs = TRUE;
        ctx->run_cs = FALSE;
        /* Check current CS-registration state. */
        mm_base_modem_at_command (MM_BASE_MODEM (self),
                                  "+CREG?",
                                  10,
                                  FALSE,
                                  (GAsyncReadyCallback)registration_status_check_ready,
                                  task);
        return;
    }

    if (ctx->run_ps) {
        ctx->running_ps = TRUE;
        ctx->run_ps = FALSE;
        /* Check current PS-registration state. */
        mm_base_modem_at_command (MM_BASE_MODEM (self),
                                  "+CGREG?",
                                  10,
                                  FALSE,
                                  (GAsyncReadyCallback)registration_status_check_ready,
                                  task);
        return;
    }

    if (ctx->run_eps) {
        ctx->running_eps = TRUE;
        ctx->run_eps = FALSE;
        /* Check current EPS-registration state. */
        mm_base_modem_at_command (MM_BASE_MODEM (self),
                                  "+CEREG?",
                                  10,
                                  FALSE,
                                  (GAsyncReadyCallback)registration_status_check_ready,
                                  task);
        return;
    }

    /* If all run checks returned errors we fail */
    if ((ctx->cs_supported || ctx->ps_supported || ctx->eps_supported) &&
        (!ctx->cs_supported || ctx->cs_error) &&
        (!ctx->ps_supported || ctx->ps_error) &&
        (!ctx->eps_supported || ctx->eps_error)) {
        /* Prefer the EPS, and then PS error if any */
        if (ctx->eps_error) {
            g_propagate_error (&error, ctx->eps_error);
            ctx->eps_error = NULL;
        } else if (ctx->ps_error) {
            g_propagate_error (&error, ctx->ps_error);
            ctx->ps_error = NULL;
        } else if (ctx->cs_error) {
            g_propagate_error (&error, ctx->cs_error);
            ctx->cs_error = NULL;
        } else
            g_assert_not_reached ();
    }

    if (error)
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_run_registration_checks (MMIfaceModem3gpp *self,
                                    gboolean cs_supported,
                                    gboolean ps_supported,
                                    gboolean eps_supported,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
    RunRegistrationChecksContext *ctx;
    GTask *task;

    ctx = g_new0 (RunRegistrationChecksContext, 1);
    ctx->cs_supported = cs_supported;
    ctx->ps_supported = ps_supported;
    ctx->eps_supported = eps_supported;
    ctx->run_cs = cs_supported;
    ctx->run_ps = ps_supported;
    ctx->run_eps = eps_supported;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)run_registration_checks_context_free);

    run_registration_checks_context_step (task);
}

/*****************************************************************************/
/* Enable/Disable unsolicited registration events (3GPP interface) */

typedef struct {
    gboolean enable; /* TRUE for enabling, FALSE for disabling */
    gboolean run_cs;
    gboolean run_ps;
    gboolean run_eps;
    gboolean running_cs;
    gboolean running_ps;
    gboolean running_eps;
    GError *cs_error;
    GError *ps_error;
    GError *eps_error;
    gboolean secondary_sequence;
    gboolean secondary_done;
} UnsolicitedRegistrationEventsContext;

static void
unsolicited_registration_events_context_free (UnsolicitedRegistrationEventsContext *ctx)
{
    if (ctx->cs_error)
        g_error_free (ctx->cs_error);
    if (ctx->ps_error)
        g_error_free (ctx->ps_error);
    if (ctx->eps_error)
        g_error_free (ctx->eps_error);
    g_free (ctx);
}

static GTask *
unsolicited_registration_events_task_new (MMBroadbandModem *self,
                                          gboolean enable,
                                          gboolean cs_supported,
                                          gboolean ps_supported,
                                          gboolean eps_supported,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
    UnsolicitedRegistrationEventsContext *ctx;
    GTask *task;

    ctx = g_new0 (UnsolicitedRegistrationEventsContext, 1);
    ctx->enable = enable;
    ctx->run_cs = cs_supported;
    ctx->run_ps = ps_supported;
    ctx->run_eps = eps_supported;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task,
                          ctx,
                          (GDestroyNotify)unsolicited_registration_events_context_free);
    return task;
}

static gboolean
modem_3gpp_enable_disable_unsolicited_registration_events_finish (MMIfaceModem3gpp *self,
                                                                  GAsyncResult *res,
                                                                  GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static gboolean
parse_registration_setup_reply (MMBaseModem *self,
                                gpointer none,
                                const gchar *command,
                                const gchar *response,
                                gboolean last_command,
                                const GError *error,
                                GVariant **result,
                                GError **result_error)
{
    /* If error, try next command */
    if (error)
        return FALSE;

    /* Set COMMAND as result! */
    *result = g_variant_new_string (command);
    return TRUE;
}

static const MMBaseModemAtCommand cs_registration_sequence[] = {
    /* Enable unsolicited registration notifications in CS network, with location */
    { "+CREG=2", 3, FALSE, parse_registration_setup_reply },
    /* Enable unsolicited registration notifications in CS network, without location */
    { "+CREG=1", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static const MMBaseModemAtCommand cs_unregistration_sequence[] = {
    /* Disable unsolicited registration notifications in CS network */
    { "+CREG=0", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static const MMBaseModemAtCommand ps_registration_sequence[] = {
    /* Enable unsolicited registration notifications in PS network, with location */
    { "+CGREG=2", 3, FALSE, parse_registration_setup_reply },
    /* Enable unsolicited registration notifications in PS network, without location */
    { "+CGREG=1", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static const MMBaseModemAtCommand ps_unregistration_sequence[] = {
    /* Disable unsolicited registration notifications in PS network */
    { "+CGREG=0", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static const MMBaseModemAtCommand eps_registration_sequence[] = {
    /* Enable unsolicited registration notifications in EPS network, with location */
    { "+CEREG=2", 3, FALSE, parse_registration_setup_reply },
    /* Enable unsolicited registration notifications in EPS network, without location */
    { "+CEREG=1", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static const MMBaseModemAtCommand eps_unregistration_sequence[] = {
    /* Disable unsolicited registration notifications in PS network */
    { "+CEREG=0", 3, FALSE, parse_registration_setup_reply },
    { NULL }
};

static void unsolicited_registration_events_context_step (GTask *task);

static void
unsolicited_registration_events_sequence_ready (MMBroadbandModem *self,
                                                GAsyncResult *res,
                                                GTask *task)
{
    UnsolicitedRegistrationEventsContext *ctx;
    GError *error = NULL;
    GVariant *command;
    MMPortSerialAt *secondary;

    ctx = g_task_get_task_data (task);

    /* Only one must be running */
    g_assert ((ctx->running_cs ? 1 : 0) +
              (ctx->running_ps ? 1 : 0) +
              (ctx->running_eps ? 1 : 0) == 1);

    if (ctx->secondary_done) {
        if (ctx->secondary_sequence)
            mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, &error);
        else
            mm_base_modem_at_command_full_finish (MM_BASE_MODEM (self), res, &error);

        if (error) {
            mm_dbg ("%s unsolicited registration events in secondary port failed: '%s'",
                    ctx->enable ? "Enabling" : "Disabling",
                    error->message);
            /* Keep errors reported */
            if (ctx->running_cs && !ctx->cs_error)
                ctx->cs_error = error;
            else if (ctx->running_ps && !ctx->ps_error)
                ctx->ps_error = error;
            else if (ctx->running_eps && !ctx->eps_error)
                ctx->eps_error = error;
            else
                g_error_free (error);
        } else {
            /* If successful in secondary port, cleanup primary error if any */
            if (ctx->running_cs && ctx->cs_error) {
                g_error_free (ctx->cs_error);
                ctx->cs_error = NULL;
            }
            else if (ctx->running_ps && ctx->ps_error) {
                g_error_free (ctx->ps_error);
                ctx->ps_error = NULL;
            }
            else if (ctx->running_eps && ctx->eps_error) {
                g_error_free (ctx->eps_error);
                ctx->eps_error = NULL;
            }
        }

        /* Done with primary and secondary, keep on */
        unsolicited_registration_events_context_step (task);
        return;
    }

    /*  We just run the sequence in the primary port */
    command = mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, &error);
    if (!command) {
        if (!error)
            error = g_error_new (MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "AT sequence failed");
        mm_dbg ("%s unsolicited registration events in primary port failed: '%s'",
                ctx->enable ? "Enabling" : "Disabling",
                error->message);
        /* Keep errors reported */
        if (ctx->running_cs)
            ctx->cs_error = error;
        else if (ctx->running_ps)
            ctx->ps_error = error;
        else
            ctx->eps_error = error;
        /* Even if primary failed, go on and try to enable in secondary port */
    }

    secondary = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));
    if (secondary) {
        const MMBaseModemAtCommand *registration_sequence = NULL;

        ctx->secondary_done = TRUE;

        /* Now use the same registration setup in secondary port, if any */
        if (command) {
            mm_base_modem_at_command_full (
                MM_BASE_MODEM (self),
                secondary,
                g_variant_get_string (command, NULL),
                3,
                FALSE,
                FALSE, /* raw */
                NULL, /* cancellable */
                (GAsyncReadyCallback)unsolicited_registration_events_sequence_ready,
                task);
            return;
        }

        /* If primary failed, run the whole sequence in secondary */
        ctx->secondary_sequence = TRUE;
        if (ctx->running_cs)
            registration_sequence = ctx->enable ? cs_registration_sequence : cs_unregistration_sequence;
        else if (ctx->running_ps)
            registration_sequence = ctx->enable ? ps_registration_sequence : ps_unregistration_sequence;
        else
            registration_sequence = ctx->enable ? eps_registration_sequence : eps_unregistration_sequence;
        mm_base_modem_at_sequence_full (
            MM_BASE_MODEM (self),
            secondary,
            registration_sequence,
            NULL,  /* response processor context */
            NULL,  /* response processor context free */
            NULL, /* cancellable */
            (GAsyncReadyCallback)unsolicited_registration_events_sequence_ready,
            task);
        return;
    }

    /* We're done */
    unsolicited_registration_events_context_step (task);
}

static void
unsolicited_registration_events_context_step (GTask *task)
{
    MMBroadbandModem *self;
    UnsolicitedRegistrationEventsContext *ctx;
    GError *error = NULL;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    ctx->running_cs = FALSE;
    ctx->running_ps = FALSE;
    ctx->running_eps = FALSE;
    ctx->secondary_done = FALSE;

    if (ctx->run_cs) {
        ctx->running_cs = TRUE;
        ctx->run_cs = FALSE;
        mm_base_modem_at_sequence_full (
            MM_BASE_MODEM (self),
            mm_base_modem_peek_port_primary (MM_BASE_MODEM (self)),
            ctx->enable ? cs_registration_sequence : cs_unregistration_sequence,
            NULL,  /* response processor context */
            NULL,  /* response processor context free */
            NULL,  /* cancellable */
            (GAsyncReadyCallback)unsolicited_registration_events_sequence_ready,
            task);
        return;
    }

    if (ctx->run_ps) {
        ctx->running_ps = TRUE;
        ctx->run_ps = FALSE;
        mm_base_modem_at_sequence_full (
            MM_BASE_MODEM (self),
            mm_base_modem_peek_port_primary (MM_BASE_MODEM (self)),
            ctx->enable ? ps_registration_sequence : ps_unregistration_sequence,
            NULL,  /* response processor context */
            NULL,  /* response processor context free */
            NULL,  /* cancellable */
            (GAsyncReadyCallback)unsolicited_registration_events_sequence_ready,
            task);
        return;
    }

    if (ctx->run_eps) {
        ctx->running_eps = TRUE;
        ctx->run_eps = FALSE;
        mm_base_modem_at_sequence_full (
            MM_BASE_MODEM (self),
            mm_base_modem_peek_port_primary (MM_BASE_MODEM (self)),
            ctx->enable ? eps_registration_sequence : eps_unregistration_sequence,
            NULL,  /* response processor context */
            NULL,  /* response processor context free */
            NULL,  /* cancellable */
            (GAsyncReadyCallback)unsolicited_registration_events_sequence_ready,
            task);
        return;
    }

    /* All done!
     * If we have any error reported, we'll propagate it. EPS errors take
     * precedence over PS errors and PS errors take precedence over CS errors. */
    if (ctx->eps_error) {
        g_propagate_error (&error, ctx->eps_error);
        ctx->eps_error = NULL;
    } else if (ctx->ps_error) {
        g_propagate_error (&error, ctx->ps_error);
        ctx->ps_error = NULL;
    } else if (ctx->cs_error) {
        g_propagate_error (&error, ctx->cs_error);
        ctx->cs_error = NULL;
    }

    if (error)
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_disable_unsolicited_registration_events (MMIfaceModem3gpp *self,
                                                    gboolean cs_supported,
                                                    gboolean ps_supported,
                                                    gboolean eps_supported,
                                                    GAsyncReadyCallback callback,
                                                    gpointer user_data)
{
    unsolicited_registration_events_context_step (
        unsolicited_registration_events_task_new (MM_BROADBAND_MODEM (self),
                                                  FALSE,
                                                  cs_supported,
                                                  ps_supported,
                                                  eps_supported,
                                                  callback,
                                                  user_data));
}

static void
modem_3gpp_enable_unsolicited_registration_events (MMIfaceModem3gpp *self,
                                                   gboolean cs_supported,
                                                   gboolean ps_supported,
                                                   gboolean eps_supported,
                                                   GAsyncReadyCallback callback,
                                                   gpointer user_data)
{
    unsolicited_registration_events_context_step (
        unsolicited_registration_events_task_new (MM_BROADBAND_MODEM (self),
                                                  TRUE,
                                                  cs_supported,
                                                  ps_supported,
                                                  eps_supported,
                                                  callback,
                                                  user_data));
}

/*****************************************************************************/
/* Cancel USSD (3GPP/USSD interface) */

static gboolean
modem_3gpp_ussd_cancel_finish (MMIfaceModem3gppUssd *self,
                               GAsyncResult *res,
                               GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cancel_command_ready (MMBroadbandModem *self,
                      GAsyncResult *res,
                      GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error)
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);

    /* Complete the pending action, if any */
    if (self->priv->pending_ussd_action) {
        g_simple_async_result_set_error (self->priv->pending_ussd_action,
                                         MM_CORE_ERROR,
                                         MM_CORE_ERROR_CANCELLED,
                                         "USSD session was cancelled");
        g_simple_async_result_complete_in_idle (self->priv->pending_ussd_action);
        g_object_unref (self->priv->pending_ussd_action);
        self->priv->pending_ussd_action = NULL;
    }

    mm_iface_modem_3gpp_ussd_update_state (MM_IFACE_MODEM_3GPP_USSD (self),
                                           MM_MODEM_3GPP_USSD_SESSION_STATE_IDLE);
}

static void
modem_3gpp_ussd_cancel (MMIfaceModem3gppUssd *self,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CUSD=2",
                              10,
                              TRUE,
                              (GAsyncReadyCallback)cancel_command_ready,
                              task);
}

/*****************************************************************************/
/* Send command (3GPP/USSD interface) */

typedef struct {
    MMBroadbandModem *self;
    GSimpleAsyncResult *result;
    gchar *command;
    gboolean current_is_unencoded;
    gboolean encoded_used;
    gboolean unencoded_used;
} Modem3gppUssdSendContext;

static void
modem_3gpp_ussd_send_context_complete_and_free (Modem3gppUssdSendContext *ctx)
{
    /* We check for result, as we may have already set it in
     * priv->pending_ussd_request */
    if (ctx->result) {
        g_simple_async_result_complete_in_idle (ctx->result);
        g_object_unref (ctx->result);
    }
    g_object_unref (ctx->self);
    g_free (ctx->command);
    g_slice_free (Modem3gppUssdSendContext, ctx);
}

static const gchar *
modem_3gpp_ussd_send_finish (MMIfaceModem3gppUssd *self,
                             GAsyncResult *res,
                             GError **error)
{
    if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
        return NULL;

    /* We can return the string as constant because it is owned by the async
     * result, which will be valid during the whole call of its callback, which
     * is when we're actually calling finish() */
    return (const gchar *)g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res));
}

static void modem_3gpp_ussd_context_step (Modem3gppUssdSendContext *ctx);

static void cusd_process_string (MMBroadbandModem *self,
                                 const gchar *str);

static void
ussd_send_command_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         Modem3gppUssdSendContext *ctx)
{
    GError *error = NULL;
    const gchar *reply;

    g_assert (ctx->result == NULL);

    reply = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        /* Some immediate error happened when sending the USSD request */
        mm_dbg ("Error sending USSD request: '%s'", error->message);
        g_error_free (error);

        if (self->priv->pending_ussd_action) {
            /* Recover result */
            ctx->result = self->priv->pending_ussd_action;
            self->priv->pending_ussd_action = NULL;
            modem_3gpp_ussd_context_step (ctx);
            return;
        }

        /* So the USSD action was completed already... */
        mm_dbg ("USSD action already completed via URCs");
        modem_3gpp_ussd_send_context_complete_and_free (ctx);
        return;
    }

    /* Cache the hint for the next time we send something */
    if (!ctx->self->priv->use_unencoded_ussd &&
        ctx->current_is_unencoded) {
        mm_dbg ("Will assume we want unencoded USSD commands");
        ctx->self->priv->use_unencoded_ussd = TRUE;
    } else if (ctx->self->priv->use_unencoded_ussd &&
               !ctx->current_is_unencoded) {
        mm_dbg ("Will assume we want encoded USSD commands");
        ctx->self->priv->use_unencoded_ussd = FALSE;
    }

    if (!self->priv->pending_ussd_action)
        mm_dbg ("USSD operation finished already via URCs");
    else if (reply && reply[0]) {
        reply = mm_strip_tag (reply, "+CUSD:");
        cusd_process_string (ctx->self, reply);
    }

    modem_3gpp_ussd_send_context_complete_and_free (ctx);
}

static void
modem_3gpp_ussd_context_send_encoded (Modem3gppUssdSendContext *ctx)
{
    gchar *at_command = NULL;
    GError *error = NULL;
    guint scheme = 0;
    gchar *encoded;

    /* Encode USSD command */
    encoded = mm_iface_modem_3gpp_ussd_encode (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                               ctx->command,
                                               &scheme,
                                               &error);
    if (!encoded) {
        mm_iface_modem_3gpp_ussd_update_state (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                               MM_MODEM_3GPP_USSD_SESSION_STATE_IDLE);
        g_simple_async_result_take_error (ctx->result, error);
        modem_3gpp_ussd_send_context_complete_and_free (ctx);
        return;
    }

    /* Build AT command */
    ctx->encoded_used = TRUE;
    ctx->current_is_unencoded = FALSE;
    at_command = g_strdup_printf ("+CUSD=1,\"%s\",%d", encoded, scheme);
    g_free (encoded);

    /* Cache the action, as it may be completed via URCs.
     * There shouldn't be any previous action pending. */
    g_warn_if_fail (ctx->self->priv->pending_ussd_action == NULL);
    ctx->self->priv->pending_ussd_action = ctx->result;
    ctx->result = NULL;

    mm_base_modem_at_command (MM_BASE_MODEM (ctx->self),
                              at_command,
                              10,
                              FALSE,
                              (GAsyncReadyCallback)ussd_send_command_ready,
                              ctx);
    g_free (at_command);
}

static void
modem_3gpp_ussd_context_send_unencoded (Modem3gppUssdSendContext *ctx)
{
    gchar *at_command = NULL;

    /* Build AT command with action unencoded */
    ctx->unencoded_used = TRUE;
    ctx->current_is_unencoded = TRUE;
    at_command = g_strdup_printf ("+CUSD=1,\"%s\",%d",
                                  ctx->command,
                                  MM_MODEM_GSM_USSD_SCHEME_7BIT);

    /* Cache the action, as it may be completed via URCs.
     * There shouldn't be any previous action pending. */
    g_warn_if_fail (ctx->self->priv->pending_ussd_action == NULL);
    ctx->self->priv->pending_ussd_action = ctx->result;
    ctx->result = NULL;

    mm_base_modem_at_command (MM_BASE_MODEM (ctx->self),
                              at_command,
                              10,
                              FALSE,
                              (GAsyncReadyCallback)ussd_send_command_ready,
                              ctx);
    g_free (at_command);
}

static void
modem_3gpp_ussd_context_step (Modem3gppUssdSendContext *ctx)
{
    if (ctx->encoded_used &&
        ctx->unencoded_used) {
        mm_iface_modem_3gpp_ussd_update_state (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                               MM_MODEM_3GPP_USSD_SESSION_STATE_IDLE);
        g_simple_async_result_set_error (ctx->result,
                                         MM_CORE_ERROR,
                                         MM_CORE_ERROR_FAILED,
                                         "Sending USSD command failed");
        modem_3gpp_ussd_send_context_complete_and_free (ctx);
        return;
    }

    if (ctx->self->priv->use_unencoded_ussd) {
        if (!ctx->unencoded_used)
            modem_3gpp_ussd_context_send_unencoded (ctx);
        else if (!ctx->encoded_used)
            modem_3gpp_ussd_context_send_encoded (ctx);
        else
            g_assert_not_reached ();
    } else {
        if (!ctx->encoded_used)
            modem_3gpp_ussd_context_send_encoded (ctx);
        else if (!ctx->unencoded_used)
            modem_3gpp_ussd_context_send_unencoded (ctx);
        else
            g_assert_not_reached ();
    }
}

static void
modem_3gpp_ussd_send (MMIfaceModem3gppUssd *self,
                      const gchar *command,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    Modem3gppUssdSendContext *ctx;

    ctx = g_slice_new0 (Modem3gppUssdSendContext);
    /* We're going to steal the string result in finish() so we must have a
     * callback specified. */
    g_assert (callback != NULL);
    ctx->self = g_object_ref (self);
    ctx->command = g_strdup (command);
    ctx->result = g_simple_async_result_new (G_OBJECT (self),
                                             callback,
                                             user_data,
                                             modem_3gpp_ussd_send);

    mm_iface_modem_3gpp_ussd_update_state (self,
                                           MM_MODEM_3GPP_USSD_SESSION_STATE_ACTIVE);

    modem_3gpp_ussd_context_step (ctx);
}

/*****************************************************************************/
/* USSD Encode/Decode (3GPP/USSD interface) */

static gchar *
modem_3gpp_ussd_encode (MMIfaceModem3gppUssd *self,
                        const gchar *command,
                        guint *scheme,
                        GError **error)
{
    MMBroadbandModem *broadband = MM_BROADBAND_MODEM (self);
    GByteArray *ussd_command;
    gchar *hex = NULL;

    ussd_command = g_byte_array_new ();

    /* encode to the current charset */
    if (mm_modem_charset_byte_array_append (ussd_command,
                                            command,
                                            FALSE,
                                            broadband->priv->modem_current_charset)) {
        *scheme = MM_MODEM_GSM_USSD_SCHEME_7BIT;
        /* convert to hex representation */
        hex = mm_utils_bin2hexstr (ussd_command->data, ussd_command->len);
    }

    g_byte_array_free (ussd_command, TRUE);

    return hex;
}

static gchar *
modem_3gpp_ussd_decode (MMIfaceModem3gppUssd *self,
                        const gchar *reply,
                        GError **error)
{
    MMBroadbandModem *broadband = MM_BROADBAND_MODEM (self);

    return mm_modem_charset_hex_to_utf8 (reply,
                                         broadband->priv->modem_current_charset);
}

/*****************************************************************************/
/* Setup/Cleanup unsolicited result codes (3GPP/USSD interface) */

static gboolean
modem_3gpp_ussd_setup_cleanup_unsolicited_result_codes_finish (MMIfaceModem3gppUssd *self,
                                                               GAsyncResult *res,
                                                               GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static gchar *
decode_ussd_response (MMBroadbandModem *self,
                      const gchar *reply,
                      GError **error)
{
    gchar *p;
    gchar *str;
    gchar *decoded;

    /* Look for the first ',' */
    p = strchr (reply, ',');
    if (!p) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Cannot decode USSD response (%s): missing field separator",
                     reply);
        return NULL;
    }

    /* Assume the string is the next field, and strip quotes. While doing this,
     * we also skip any other additional field we may have afterwards */
    if (p[1] == '"') {
        str = g_strdup (&p[2]);
        p = strchr (str, '"');
        if (p)
            *p = '\0';
    } else {
        str = g_strdup (&p[1]);
        p = strchr (str, ',');
        if (p)
            *p = '\0';
    }

    /* If reply doesn't seem to be hex; just return itself... */
    if (!mm_utils_ishexstr (str))
        decoded = g_strdup (str);
    else
        decoded = mm_iface_modem_3gpp_ussd_decode (MM_IFACE_MODEM_3GPP_USSD (self), str, error);

    g_free (str);

    return decoded;
}

static void
cusd_process_string (MMBroadbandModem *self,
                     const gchar *str)
{
    MMModem3gppUssdSessionState ussd_state = MM_MODEM_3GPP_USSD_SESSION_STATE_IDLE;

    if (!str || !isdigit (*str)) {
        if (self->priv->pending_ussd_action)
            g_simple_async_result_set_error (self->priv->pending_ussd_action,
                                             MM_CORE_ERROR,
                                             MM_CORE_ERROR_FAILED,
                                             "Invalid USSD response received: '%s'",
                                             str ? str : "(none)");
        else
            mm_warn ("Received invalid USSD network-initiated request: '%s'",
                     str ? str : "(none)");
    } else {
        gint status;

        status = g_ascii_digit_value (*str);
        switch (status) {
        case 0: /* no further action required */ {
            gchar *converted;
            GError *error = NULL;

            converted = decode_ussd_response (self, str, &error);
            if (self->priv->pending_ussd_action) {
                /* Response to the user's request */
                if (error)
                    g_simple_async_result_take_error (self->priv->pending_ussd_action, error);
                else
                    g_simple_async_result_set_op_res_gpointer (self->priv->pending_ussd_action,
                                                               converted,
                                                               g_free);
            } else {
                if (error) {
                    mm_warn ("Invalid network initiated USSD notification: %s",
                             error->message);
                    g_error_free (error);
                } else {
                    /* Network-initiated USSD-Notify */
                    mm_iface_modem_3gpp_ussd_update_network_notification (
                        MM_IFACE_MODEM_3GPP_USSD (self),
                        converted);
                    g_free (converted);
                }
            }
            break;
        }

        case 1: /* further action required */ {
            gchar *converted;
            GError *error = NULL;

            ussd_state = MM_MODEM_3GPP_USSD_SESSION_STATE_USER_RESPONSE;
            converted = decode_ussd_response (self, str, &error);
            if (self->priv->pending_ussd_action) {
                if (error)
                    g_simple_async_result_take_error (self->priv->pending_ussd_action, error);
                else
                    g_simple_async_result_set_op_res_gpointer (self->priv->pending_ussd_action,
                                                               converted,
                                                               g_free);
            } else {
                if (error) {
                    mm_warn ("Invalid network initiated USSD request: %s",
                             error->message);
                    g_error_free (error);
                } else {
                    /* Network-initiated USSD-Request */
                    mm_iface_modem_3gpp_ussd_update_network_request (
                        MM_IFACE_MODEM_3GPP_USSD (self),
                        converted);
                    g_free (converted);
                }
            }
            break;
        }

        case 2:
            if (self->priv->pending_ussd_action)
                g_simple_async_result_set_error (self->priv->pending_ussd_action,
                                                 MM_CORE_ERROR,
                                                 MM_CORE_ERROR_CANCELLED,
                                                 "USSD terminated by network.");
            break;

        case 4:
            if (self->priv->pending_ussd_action)
                g_simple_async_result_set_error (self->priv->pending_ussd_action,
                                                 MM_CORE_ERROR,
                                                 MM_CORE_ERROR_UNSUPPORTED,
                                                 "Operation not supported.");
            break;

        default:
            if (self->priv->pending_ussd_action)
                g_simple_async_result_set_error (self->priv->pending_ussd_action,
                                                 MM_CORE_ERROR,
                                                 MM_CORE_ERROR_FAILED,
                                                 "Unhandled USSD reply: %s (%d)",
                                                 str,
                                                 status);
            break;
        }
    }

    mm_iface_modem_3gpp_ussd_update_state (MM_IFACE_MODEM_3GPP_USSD (self),
                                           ussd_state);

    /* Complete the pending action */
    if (self->priv->pending_ussd_action) {
        g_simple_async_result_complete_in_idle (self->priv->pending_ussd_action);
        g_object_unref (self->priv->pending_ussd_action);
        self->priv->pending_ussd_action = NULL;
    }
}

static void
cusd_received (MMPortSerialAt *port,
               GMatchInfo *info,
               MMBroadbandModem *self)
{
    gchar *str;

    mm_dbg ("Unsolicited USSD URC received");
    str = g_match_info_fetch (info, 1);
    cusd_process_string (self, str);
    g_free (str);
}

static void
set_unsolicited_result_code_handlers (MMIfaceModem3gppUssd *self,
                                      gboolean enable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    MMPortSerialAt *ports[2];
    GRegex *cusd_regex;
    guint i;
    GTask *task;

    cusd_regex = mm_3gpp_cusd_regex_get ();
    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Enable unsolicited result codes in given port */
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;
        /* Set/unset unsolicited CUSD event handler */
        mm_dbg ("(%s) %s unsolicited result code handlers",
                mm_port_get_device (MM_PORT (ports[i])),
                enable ? "Setting" : "Removing");
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            cusd_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) cusd_received : NULL,
            enable ? self : NULL,
            NULL);
    }

    g_regex_unref (cusd_regex);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_ussd_setup_unsolicited_result_codes (MMIfaceModem3gppUssd *self,
                                                GAsyncReadyCallback callback,
                                                gpointer user_data)
{
    set_unsolicited_result_code_handlers (self, TRUE, callback, user_data);
}

static void
modem_3gpp_ussd_cleanup_unsolicited_result_codes (MMIfaceModem3gppUssd *self,
                                                  GAsyncReadyCallback callback,
                                                  gpointer user_data)
{
    set_unsolicited_result_code_handlers (self, FALSE, callback, user_data);
}

/*****************************************************************************/
/* Enable/Disable URCs (3GPP/USSD interface) */

static gboolean
modem_3gpp_ussd_enable_disable_unsolicited_result_codes_finish (MMIfaceModem3gppUssd *self,
                                                                GAsyncResult *res,
                                                                GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
urc_enable_disable_ready (MMBroadbandModem *self,
                          GAsyncResult *res,
                          GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_ussd_disable_unsolicited_result_codes (MMIfaceModem3gppUssd *self,
                                                  GAsyncReadyCallback callback,
                                                  gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CUSD=0",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)urc_enable_disable_ready,
                              task);
}

static void
modem_3gpp_ussd_enable_unsolicited_result_codes (MMIfaceModem3gppUssd *self,
                                                 GAsyncReadyCallback callback,
                                                 gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CUSD=1",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)urc_enable_disable_ready,
                              task);
}

/*****************************************************************************/
/* Check if USSD supported (3GPP/USSD interface) */

static gboolean
modem_3gpp_ussd_check_support_finish (MMIfaceModem3gppUssd *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cusd_format_check_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_3gpp_ussd_check_support (MMIfaceModem3gppUssd *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Check USSD support */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CUSD=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cusd_format_check_ready,
                              task);
}

/*****************************************************************************/
/* Check if Messaging supported (Messaging interface) */

static gboolean
modem_messaging_check_support_finish (MMIfaceModemMessaging *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cnmi_format_check_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* CNMI command is supported; assume we have full messaging capabilities */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_messaging_check_support (MMIfaceModemMessaging *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* We assume that CDMA-only modems don't have messaging capabilities */
    if (mm_iface_modem_is_cdma_only (MM_IFACE_MODEM (self))) {
        g_task_return_new_error (
            task,
            MM_CORE_ERROR,
            MM_CORE_ERROR_UNSUPPORTED,
            "CDMA-only modems don't have messaging capabilities");
        g_object_unref (task);
        return;
    }

    /* Check CNMI support */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CNMI=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cnmi_format_check_ready,
                              task);
}

/*****************************************************************************/
/* Load supported SMS storages (Messaging interface) */

typedef struct {
    GArray *mem1;
    GArray *mem2;
    GArray *mem3;
} SupportedStoragesResult;

static void
supported_storages_result_free (SupportedStoragesResult *result)
{
    if (result->mem1)
        g_array_unref (result->mem1);
    if (result->mem2)
        g_array_unref (result->mem2);
    if (result->mem3)
        g_array_unref (result->mem3);
    g_free (result);
}

static gboolean
modem_messaging_load_supported_storages_finish (MMIfaceModemMessaging *self,
                                                GAsyncResult *res,
                                                GArray **mem1,
                                                GArray **mem2,
                                                GArray **mem3,
                                                GError **error)
{
    SupportedStoragesResult *result;

    result = g_task_propagate_pointer (G_TASK (res), error);
    if (!result)
        return FALSE;

    *mem1 = g_array_ref (result->mem1);
    *mem2 = g_array_ref (result->mem2);
    *mem3 = g_array_ref (result->mem3);
    supported_storages_result_free (result);
    return TRUE;
}

static void
cpms_format_check_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    const gchar *response;
    GError *error = NULL;
    SupportedStoragesResult *result;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    result = g_new0 (SupportedStoragesResult, 1);

    /* Parse reply */
    if (!mm_3gpp_parse_cpms_test_response (response,
                                           &result->mem1,
                                           &result->mem2,
                                           &result->mem3)) {
        supported_storages_result_free (result);
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Couldn't parse supported storages reply: '%s'",
                                 response);
        g_object_unref (task);
        return;
    }

    g_task_return_pointer (task,
                           result,
                           (GDestroyNotify)supported_storages_result_free);
    g_object_unref (task);
}

static void
modem_messaging_load_supported_storages (MMIfaceModemMessaging *self,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Check support storages */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CPMS=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cpms_format_check_ready,
                              task);
}

/*****************************************************************************/
/* Init current SMS storages (Messaging interface) */

static gboolean
modem_messaging_init_current_storages_finish (MMIfaceModemMessaging *_self,
                                              GAsyncResult *res,
                                              GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cpms_query_ready (MMBroadbandModem *self,
                  GAsyncResult *res,
                  GTask *task)
{
    const gchar *response;
    GError *error = NULL;
    MMSmsStorage mem1;
    MMSmsStorage mem2;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Parse reply */
    if (!mm_3gpp_parse_cpms_query_response (response,
                                            &mem1,
                                            &mem2,
                                            &error)) {
        g_task_return_error (task, error);
    } else {
        gchar *aux;

        self->priv->current_sms_mem1_storage = mem1;
        self->priv->current_sms_mem2_storage = mem2;

        mm_dbg ("Current storages initialized:");

        aux = mm_common_build_sms_storages_string (&mem1, 1);
        mm_dbg ("  mem1 (list/read/delete) storages: '%s'", aux);
        g_free (aux);

        aux = mm_common_build_sms_storages_string (&mem2, 1);
        mm_dbg ("  mem2 (write/send) storages:       '%s'", aux);
        g_free (aux);

        g_task_return_boolean (task, TRUE);
    }
    g_object_unref (task);
}

static void
modem_messaging_init_current_storages (MMIfaceModemMessaging *self,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Check support storages */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CPMS?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cpms_query_ready,
                              task);
}

/*****************************************************************************/
/* Lock/unlock SMS storage (Messaging interface implementation helper)
 *
 * The basic commands to work with SMS storages play with AT+CPMS and three
 * different storages: mem1, mem2 and mem3.
 *   'mem1' is the storage for reading, listing and deleting.
 *   'mem2' is the storage for writing and sending from storage.
 *   'mem3' is the storage for receiving.
 *
 * When a command is to be issued for a specific storage, we need a way to
 * lock the access so that other actions are forbidden until the current one
 * finishes. Just think of two sequential actions to store two different
 * SMS into 2 different storages. If the second action is run while the first
 * one is still running, we should issue a RETRY error.
 *
 * Note that mem3 cannot be locked; we just set the default mem3 and that's it.
 *
 * When we unlock the storage, we don't go back to the default storage
 * automatically, we just keep track of which is the current one and only go to
 * the default one if needed.
 */

void
mm_broadband_modem_unlock_sms_storages (MMBroadbandModem *self,
                                        gboolean mem1,
                                        gboolean mem2)
{
    if (mem1) {
        g_assert (self->priv->mem1_storage_locked);
        self->priv->mem1_storage_locked = FALSE;
    }

    if (mem2) {
        g_assert (self->priv->mem2_storage_locked);
        self->priv->mem2_storage_locked = FALSE;
    }
}

gboolean
mm_broadband_modem_lock_sms_storages_finish (MMBroadbandModem *self,
                                             GAsyncResult *res,
                                             GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

typedef struct {
    MMSmsStorage previous_mem1;
    gboolean mem1_locked;
    MMSmsStorage previous_mem2;
    gboolean mem2_locked;
} LockSmsStoragesContext;

static void
lock_storages_cpms_set_ready (MMBaseModem *_self,
                              GAsyncResult *res,
                              GTask *task)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    LockSmsStoragesContext *ctx;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    mm_base_modem_at_command_finish (_self, res, &error);
    if (error) {
        /* Reset previous storages and set unlocked */
        if (ctx->mem1_locked) {
            self->priv->current_sms_mem1_storage = ctx->previous_mem1;
            self->priv->mem1_storage_locked = FALSE;
        }
        if (ctx->mem2_locked) {
            self->priv->current_sms_mem2_storage = ctx->previous_mem2;
            self->priv->mem2_storage_locked = FALSE;
        }
        g_task_return_error (task, error);
    }
    else
        g_task_return_boolean (task, TRUE);

    g_object_unref (task);
}

void
mm_broadband_modem_lock_sms_storages (MMBroadbandModem *self,
                                      MMSmsStorage mem1, /* reading/listing/deleting */
                                      MMSmsStorage mem2, /* storing/sending */
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    LockSmsStoragesContext *ctx;
    GTask *task;
    gchar *cmd = NULL;
    gchar *mem1_str = NULL;
    gchar *mem2_str = NULL;

    /* If storages are currently locked by someone else, just return an
     * error */
    if ((mem1 != MM_SMS_STORAGE_UNKNOWN && self->priv->mem1_storage_locked) ||
        (mem2 != MM_SMS_STORAGE_UNKNOWN && self->priv->mem2_storage_locked)) {
        g_task_report_new_error (
            self,
            callback,
            user_data,
            mm_broadband_modem_lock_sms_storages,
            MM_CORE_ERROR,
            MM_CORE_ERROR_RETRY,
            "SMS storage currently locked, try again later");
        return;
    }

    /* We allow locking either just one or both */
    g_assert (mem1 != MM_SMS_STORAGE_UNKNOWN ||
              mem2 != MM_SMS_STORAGE_UNKNOWN);

    ctx = g_new0 (LockSmsStoragesContext, 1);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, g_free);

    /* Some modems may not support empty string parameters, then if mem1 is
     * UNKNOWN, and current sms mem1 storage has a valid value, we send again
     * the already locked mem1 value in place of an empty string.
     * This way we also avoid to confuse the environment of other sync operation
     * that have potentially locked mem1 previously.
     */
    if (mem1 != MM_SMS_STORAGE_UNKNOWN) {
        ctx->mem1_locked = TRUE;
        ctx->previous_mem1 = self->priv->current_sms_mem1_storage;

        self->priv->current_sms_mem1_storage = mem1;
        self->priv->mem1_storage_locked = TRUE;
    } else if (self->priv->current_sms_mem1_storage != MM_SMS_STORAGE_UNKNOWN) {
        mm_dbg ("Given sms mem1 storage is unknown. Using current sms mem1 storage value '%s' instead",
                mm_sms_storage_get_string (self->priv->current_sms_mem1_storage));
    } else {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_RETRY,
                                 "Cannot lock mem2 storage alone when current mem1 storage is unknown");
        g_object_unref (task);
        return;
    }
    mem1_str = g_ascii_strup (mm_sms_storage_get_string (self->priv->current_sms_mem1_storage), -1);

    if (mem2 != MM_SMS_STORAGE_UNKNOWN) {
        ctx->mem2_locked = TRUE;
        ctx->previous_mem2 = self->priv->current_sms_mem2_storage;

        self->priv->mem2_storage_locked = TRUE;
        self->priv->current_sms_mem2_storage = mem2;

        mem2_str = g_ascii_strup (mm_sms_storage_get_string (self->priv->current_sms_mem2_storage), -1);
    }

    g_assert (mem1_str != NULL);

    /* We don't touch 'mem3' here */
    mm_dbg ("Locking SMS storages to: mem1 (%s), mem2 (%s)...",
            mem1_str,
            mem2_str ? mem2_str : "none");

    if (mem2_str)
        cmd = g_strdup_printf ("+CPMS=\"%s\",\"%s\"", mem1_str, mem2_str);
    else
        cmd = g_strdup_printf ("+CPMS=\"%s\"", mem1_str);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              cmd,
                              3,
                              FALSE,
                              (GAsyncReadyCallback)lock_storages_cpms_set_ready,
                              task);
    g_free (mem1_str);
    g_free (mem2_str);
    g_free (cmd);
}

/*****************************************************************************/
/* Set default SMS storage (Messaging interface) */

static gboolean
modem_messaging_set_default_storage_finish (MMIfaceModemMessaging *self,
                                            GAsyncResult *res,
                                            GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cpms_set_ready (MMBroadbandModem *self,
                GAsyncResult *res,
                GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error)
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_messaging_set_default_storage (MMIfaceModemMessaging *_self,
                                     MMSmsStorage storage,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (_self);
    gchar *cmd;
    gchar *mem1_str;
    gchar *mem_str;
    GTask *task;

    /* We provide the current sms storage for mem1 if not UNKNOWN */
    if (self->priv->current_sms_mem1_storage == MM_SMS_STORAGE_UNKNOWN) {
        g_task_report_new_error (self,
                                 callback,
                                 user_data,
                                 modem_messaging_set_default_storage,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_INVALID_ARGS,
                                 "Cannot set default storage when current mem1 storage is unknown");
        return;
    }

    /* Set defaults as current */
    self->priv->current_sms_mem2_storage = storage;

    mem1_str = g_ascii_strup (mm_sms_storage_get_string (self->priv->current_sms_mem1_storage), -1);
    mem_str = g_ascii_strup (mm_sms_storage_get_string (storage), -1);

    cmd = g_strdup_printf ("+CPMS=\"%s\",\"%s\",\"%s\"", mem1_str, mem_str, mem_str);

    task = g_task_new (self, NULL, callback, user_data);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              cmd,
                              3,
                              FALSE,
                              (GAsyncReadyCallback)cpms_set_ready,
                              task);
    g_free (mem1_str);
    g_free (mem_str);
    g_free (cmd);
}

/*****************************************************************************/
/* Setup SMS format (Messaging interface) */

static gboolean
modem_messaging_setup_sms_format_finish (MMIfaceModemMessaging *self,
                                         GAsyncResult *res,
                                         GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cmgf_set_ready (MMBroadbandModem *self,
                GAsyncResult *res,
                GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        mm_dbg ("Failed to set preferred SMS mode: '%s'; assuming text mode'",
                error->message);
        g_error_free (error);
        self->priv->modem_messaging_sms_pdu_mode = FALSE;
    } else
        mm_dbg ("Successfully set preferred SMS mode: '%s'",
                self->priv->modem_messaging_sms_pdu_mode ? "PDU" : "text");

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
set_preferred_sms_format (MMBroadbandModem *self,
                          GTask *task)
{
    gchar *cmd;

    cmd = g_strdup_printf ("+CMGF=%s",
                           self->priv->modem_messaging_sms_pdu_mode ? "0" : "1");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              cmd,
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cmgf_set_ready,
                              task);
    g_free (cmd);
}

static void
cmgf_format_check_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    GError *error = NULL;
    const gchar *response;
    gboolean sms_pdu_supported = FALSE;
    gboolean sms_text_supported = FALSE;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error ||
        !mm_3gpp_parse_cmgf_test_response (response,
                                           &sms_pdu_supported,
                                           &sms_text_supported,
                                           &error)) {
        mm_dbg ("Failed to query supported SMS modes: '%s'",
                error->message);
        g_error_free (error);
    }

    /* Only use text mode if PDU mode not supported */
    self->priv->modem_messaging_sms_pdu_mode = TRUE;
    if (!sms_pdu_supported) {
        if (sms_text_supported) {
            mm_dbg ("PDU mode not supported, will try to use Text mode");
            self->priv->modem_messaging_sms_pdu_mode = FALSE;
        } else
            mm_dbg ("Neither PDU nor Text modes are reported as supported; "
                    "will anyway default to PDU mode");
    }

    self->priv->sms_supported_modes_checked = TRUE;

    set_preferred_sms_format (self, task);
}

static void
modem_messaging_setup_sms_format (MMIfaceModemMessaging *self,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* If we already checked for supported SMS types, go on to select the
     * preferred format. */
    if (MM_BROADBAND_MODEM (self)->priv->sms_supported_modes_checked) {
        set_preferred_sms_format (MM_BROADBAND_MODEM (self), task);
        return;
    }

    /* Check supported SMS formats */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CMGF=?",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)cmgf_format_check_ready,
                              task);
}

/*****************************************************************************/
/* Setup/cleanup messaging related unsolicited events (Messaging interface) */

static gboolean
modem_messaging_setup_cleanup_unsolicited_events_finish (MMIfaceModemMessaging *self,
                                                         GAsyncResult *res,
                                                         GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

typedef struct {
    guint idx;
} SmsPartContext;

static void
sms_part_ready (MMBroadbandModem *self,
                GAsyncResult *res,
                GTask *task)
{
    SmsPartContext *ctx;
    MMSmsPart *part;
    MM3gppPduInfo *info;
    const gchar *response;
    GError *error = NULL;

    /* Always always always unlock mem1 storage. Warned you've been. */
    mm_broadband_modem_unlock_sms_storages (self, TRUE, FALSE);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        /* We're really ignoring this error afterwards, as we don't have a callback
         * passed to the async operation, so just log the error here. */
        mm_warn ("Couldn't retrieve SMS part: '%s'",
                 error->message);
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    info = mm_3gpp_parse_cmgr_read_response (response, ctx->idx, &error);
    if (!info) {
        mm_warn ("Couldn't parse SMS part: '%s'",
                 error->message);
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    part = mm_sms_part_3gpp_new_from_pdu (info->index, info->pdu, &error);
    if (part) {
        mm_dbg ("Correctly parsed PDU (%d)", ctx->idx);
        mm_iface_modem_messaging_take_part (MM_IFACE_MODEM_MESSAGING (self),
                                            part,
                                            MM_SMS_STATE_RECEIVED,
                                            self->priv->modem_messaging_sms_default_storage);
    } else {
        /* Don't treat the error as critical */
        mm_dbg ("Error parsing PDU (%d): %s", ctx->idx, error->message);
        g_error_free (error);
    }

    /* All done */
    mm_3gpp_pdu_info_free (info);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
indication_lock_storages_ready (MMBroadbandModem *self,
                                GAsyncResult *res,
                                GTask *task)
{
    SmsPartContext *ctx;
    gchar *command;
    GError *error = NULL;

    if (!mm_broadband_modem_lock_sms_storages_finish (self, res, &error)) {
        /* TODO: we should either make this lock() never fail, by automatically
         * retrying after some time, or otherwise retry here. */
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Storage now set and locked */

    /* Retrieve the message */
    ctx = g_task_get_task_data (task);
    command = g_strdup_printf ("+CMGR=%d", ctx->idx);
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              command,
                              10,
                              FALSE,
                              (GAsyncReadyCallback)sms_part_ready,
                              task);
    g_free (command);
}

static void
cmti_received (MMPortSerialAt *port,
               GMatchInfo *info,
               MMBroadbandModem *self)
{
    SmsPartContext *ctx;
    GTask *task;
    guint idx = 0;
    MMSmsStorage storage;
    gchar *str;

    if (!mm_get_uint_from_match_info (info, 2, &idx))
        return;

    /* The match info gives us in which storage the index applies */
    str = mm_get_string_unquoted_from_match_info (info, 1);
    storage = mm_common_get_sms_storage_from_string (str, NULL);
    if (storage == MM_SMS_STORAGE_UNKNOWN) {
        mm_dbg ("Skipping CMTI indication, unknown storage '%s' reported", str);
        g_free (str);
        return;
    }
    g_free (str);

    /* Don't signal multiple times if there are multiple CMTI notifications for a message */
    if (mm_sms_list_has_part (self->priv->modem_messaging_sms_list,
                              storage,
                              idx)) {
        mm_dbg ("Skipping CMTI indication, part already processed");
        return;
    }

    ctx = g_new (SmsPartContext, 1);
    ctx->idx = idx;

    task = g_task_new (self, NULL, NULL, NULL);
    g_task_set_task_data (task, ctx, g_free);

    /* First, request to set the proper storage to read from */
    mm_broadband_modem_lock_sms_storages (self,
                                          storage,
                                          MM_SMS_STORAGE_UNKNOWN,
                                          (GAsyncReadyCallback)indication_lock_storages_ready,
                                          task);
}

static void
cds_received (MMPortSerialAt *port,
              GMatchInfo *info,
              MMBroadbandModem *self)
{
    GError *error = NULL;
    MMSmsPart *part;
    guint length;
    gchar *pdu;

    mm_dbg ("Got new non-stored message indication");

    if (!mm_get_uint_from_match_info (info, 1, &length))
        return;

    pdu = g_match_info_fetch (info, 2);
    if (!pdu)
        return;

    part = mm_sms_part_3gpp_new_from_pdu (SMS_PART_INVALID_INDEX, pdu, &error);
    if (part) {
        mm_dbg ("Correctly parsed non-stored PDU");
        mm_iface_modem_messaging_take_part (MM_IFACE_MODEM_MESSAGING (self),
                                            part,
                                            MM_SMS_STATE_RECEIVED,
                                            MM_SMS_STORAGE_UNKNOWN);
    } else {
        /* Don't treat the error as critical */
        mm_dbg ("Error parsing non-stored PDU: %s", error->message);
        g_error_free (error);
    }
}

static void
set_messaging_unsolicited_events_handlers (MMIfaceModemMessaging *self,
                                           gboolean enable,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
    MMPortSerialAt *ports[2];
    GRegex *cmti_regex;
    GRegex *cds_regex;
    guint i;
    GTask *task;

    cmti_regex = mm_3gpp_cmti_regex_get ();
    cds_regex = mm_3gpp_cds_regex_get ();
    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Add messaging unsolicited events handler for port primary and secondary */
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        /* Set/unset unsolicited CMTI event handler */
        mm_dbg ("(%s) %s messaging unsolicited events handlers",
                mm_port_get_device (MM_PORT (ports[i])),
                enable ? "Setting" : "Removing");
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            cmti_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) cmti_received : NULL,
            enable ? self : NULL,
            NULL);
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            cds_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) cds_received : NULL,
            enable ? self : NULL,
            NULL);
    }

    g_regex_unref (cmti_regex);
    g_regex_unref (cds_regex);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_messaging_setup_unsolicited_events (MMIfaceModemMessaging *self,
                                          GAsyncReadyCallback callback,
                                          gpointer user_data)
{
    set_messaging_unsolicited_events_handlers (self, TRUE, callback, user_data);
}

static void
modem_messaging_cleanup_unsolicited_events (MMIfaceModemMessaging *self,
                                            GAsyncReadyCallback callback,
                                            gpointer user_data)
{
    set_messaging_unsolicited_events_handlers (self, FALSE, callback, user_data);
}

/*****************************************************************************/
/* Enable unsolicited events (SMS indications) (Messaging interface) */

static gboolean
modem_messaging_enable_unsolicited_events_finish (MMIfaceModemMessaging *self,
                                                  GAsyncResult *res,
                                                  GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static gboolean
cnmi_response_processor (MMBaseModem *self,
                         gpointer none,
                         const gchar *command,
                         const gchar *response,
                         gboolean last_command,
                         const GError *error,
                         GVariant **result,
                         GError **result_error)
{
    if (error) {
        /* If we get a not-supported error and we're not in the last command, we
         * won't set 'result_error', so we'll keep on the sequence */
        if (!g_error_matches (error, MM_MESSAGE_ERROR, MM_MESSAGE_ERROR_NOT_SUPPORTED) ||
            last_command)
            *result_error = g_error_copy (error);

        return FALSE;
    }

    *result = NULL;
    return TRUE;
}

static const MMBaseModemAtCommand cnmi_sequence[] = {
    { "+CNMI=2,1,2,1,0", 3, FALSE, cnmi_response_processor },

    /* Many Qualcomm-based devices don't support <ds> of '1', despite
     * reporting they support it in the +CNMI=? response.  But they do
     * accept '2'.
     */
    { "+CNMI=2,1,2,2,0", 3, FALSE, cnmi_response_processor },

    /* Last resort: turn off delivery status reports altogether */
    { "+CNMI=2,1,2,0,0", 3, FALSE, cnmi_response_processor },
    { NULL }
};

static void
modem_messaging_enable_unsolicited_events_secondary_ready (MMBaseModem *self,
                                                           GAsyncResult *res,
                                                           GTask *task)
{
    GError *inner_error = NULL;
    MMPortSerialAt *secondary;

    secondary = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Since the secondary is not required, we don't propagate the error anywhere */
    mm_base_modem_at_sequence_full_finish (MM_BASE_MODEM (self), res, NULL, &inner_error);
    if (inner_error) {
        mm_dbg ("(%s) Unable to enable messaging unsolicited events on modem secondary: %s",
                mm_port_get_device (MM_PORT (secondary)),
                inner_error->message);
        g_error_free (inner_error);
    }

    mm_dbg ("(%s) Messaging unsolicited events enabled on secondary",
            mm_port_get_device (MM_PORT (secondary)));

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_messaging_enable_unsolicited_events_primary_ready (MMBaseModem *self,
                                                         GAsyncResult *res,
                                                         GTask *task)
{
    GError *inner_error = NULL;
    MMPortSerialAt *primary;
    MMPortSerialAt *secondary;

    primary = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    secondary = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    mm_base_modem_at_sequence_full_finish (MM_BASE_MODEM (self), res, NULL, &inner_error);
    if (inner_error) {
        g_task_return_error (task, inner_error);
        g_object_unref (task);
        return;
    }

    mm_dbg ("(%s) Messaging unsolicited events enabled on primary",
            mm_port_get_device (MM_PORT (primary)));

    /* Try to enable unsolicited events for secondary port */
    if (secondary) {
        mm_dbg ("(%s) Enabling messaging unsolicited events on secondary port",
                mm_port_get_device (MM_PORT (secondary)));
        mm_base_modem_at_sequence_full (
            MM_BASE_MODEM (self),
            secondary,
            cnmi_sequence,
            NULL, /* response_processor_context */
            NULL, /* response_processor_context_free */
            NULL,
            (GAsyncReadyCallback)modem_messaging_enable_unsolicited_events_secondary_ready,
            task);
        return;
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_messaging_enable_unsolicited_events (MMIfaceModemMessaging *self,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data)
{
    GTask *task;
    MMPortSerialAt *primary;

    task = g_task_new (self, NULL, callback, user_data);
    primary = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));

    /* Enable unsolicited events for primary port */
    mm_dbg ("(%s) Enabling messaging unsolicited events on primary port",
            mm_port_get_device (MM_PORT (primary)));
    mm_base_modem_at_sequence_full (
        MM_BASE_MODEM (self),
        primary,
        cnmi_sequence,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        NULL,
        (GAsyncReadyCallback)modem_messaging_enable_unsolicited_events_primary_ready,
        task);
}

/*****************************************************************************/
/* Load initial list of SMS parts (Messaging interface) */

typedef struct {
    MMSmsStorage list_storage;
} ListPartsContext;

static gboolean
modem_messaging_load_initial_sms_parts_finish (MMIfaceModemMessaging *self,
                                               GAsyncResult *res,
                                               GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static MMSmsState
sms_state_from_str (const gchar *str)
{
    /* We merge unread and read messages in the same state */
    if (strstr (str, "REC"))
        return MM_SMS_STATE_RECEIVED;

    /* look for 'unsent' BEFORE looking for 'sent' */
    if (strstr (str, "UNSENT"))
        return MM_SMS_STATE_STORED;

    if (strstr (str, "SENT"))
        return MM_SMS_STATE_SENT;

    return MM_SMS_STATE_UNKNOWN;
}

static MMSmsPduType
sms_pdu_type_from_str (const gchar *str)
{
    /* We merge unread and read messages in the same state */
    if (strstr (str, "REC"))
        return MM_SMS_PDU_TYPE_DELIVER;

    if (strstr (str, "STO"))
        return MM_SMS_PDU_TYPE_SUBMIT;

    return MM_SMS_PDU_TYPE_UNKNOWN;
}

static void
sms_text_part_list_ready (MMBroadbandModem *self,
                          GAsyncResult *res,
                          GTask *task)
{
    ListPartsContext *ctx;
    GRegex *r;
    GMatchInfo *match_info = NULL;
    const gchar *response;
    GError *error = NULL;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* +CMGL: <index>,<stat>,<oa/da>,[alpha],<scts><CR><LF><data><CR><LF> */
    r = g_regex_new ("\\+CMGL:\\s*(\\d+)\\s*,\\s*([^,]*),\\s*([^,]*),\\s*([^,]*),\\s*([^\\r\\n]*)\\r\\n([^\\r\\n]*)",
                     0, 0, NULL);
    g_assert (r);

    if (!g_regex_match_full (r, response, strlen (response), 0, 0, &match_info, NULL)) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_INVALID_ARGS,
                                 "Couldn't parse SMS list response");
        g_object_unref (task);
        g_match_info_free (match_info);
        g_regex_unref (r);
        return;
    }

    ctx = g_task_get_task_data (task);

    while (g_match_info_matches (match_info)) {
        MMSmsPart *part;
        guint matches, idx;
        gchar *number, *timestamp, *text, *ucs2_text, *stat;
        gsize ucs2_len = 0;
        GByteArray *raw;

        matches = g_match_info_get_match_count (match_info);
        if (matches != 7) {
            mm_dbg ("Failed to match entire CMGL response (count %d)", matches);
            goto next;
        }

        if (!mm_get_uint_from_match_info (match_info, 1, &idx)) {
            mm_dbg ("Failed to convert message index");
            goto next;
        }

        /* Get part state */
        stat = mm_get_string_unquoted_from_match_info (match_info, 2);
        if (!stat) {
            mm_dbg ("Failed to get part status");
            goto next;
        }

        /* Get and parse number */
        number = mm_get_string_unquoted_from_match_info (match_info, 3);
        if (!number) {
            mm_dbg ("Failed to get message sender number");
            g_free (stat);
            goto next;
        }

        number = mm_broadband_modem_take_and_convert_to_utf8 (MM_BROADBAND_MODEM (self),
                                                              number);

        /* Get and parse timestamp (always expected in ASCII) */
        timestamp = mm_get_string_unquoted_from_match_info (match_info, 5);

        /* Get and parse text */
        text = mm_broadband_modem_take_and_convert_to_utf8 (MM_BROADBAND_MODEM (self),
                                                            g_match_info_fetch (match_info, 6));

        /* The raw SMS data can only be GSM, UCS2, or unknown (8-bit), so we
         * need to convert to UCS2 here.
         */
        ucs2_text = g_convert (text, -1, "UCS-2BE//TRANSLIT", "UTF-8", NULL, &ucs2_len, NULL);
        g_assert (ucs2_text);
        raw = g_byte_array_sized_new (ucs2_len);
        g_byte_array_append (raw, (const guint8 *) ucs2_text, ucs2_len);
        g_free (ucs2_text);

        /* all take() methods pass ownership of the value as well */
        part = mm_sms_part_new (idx,
                                sms_pdu_type_from_str (stat));
        mm_sms_part_take_number (part, number);
        mm_sms_part_take_timestamp (part, timestamp);
        mm_sms_part_take_text (part, text);
        mm_sms_part_take_data (part, raw);
        mm_sms_part_set_class (part, -1);

        mm_dbg ("Correctly parsed SMS list entry (%d)", idx);
        mm_iface_modem_messaging_take_part (MM_IFACE_MODEM_MESSAGING (self),
                                            part,
                                            sms_state_from_str (stat),
                                            ctx->list_storage);
        g_free (stat);
next:
        g_match_info_next (match_info, NULL);
    }
    g_match_info_free (match_info);
    g_regex_unref (r);

    /* We consider all done */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static MMSmsState
sms_state_from_index (guint index)
{
    /* We merge unread and read messages in the same state */
    switch (index) {
    case 0: /* received, unread */
    case 1: /* received, read */
        return MM_SMS_STATE_RECEIVED;
    case 2:
        return MM_SMS_STATE_STORED;
    case 3:
        return MM_SMS_STATE_SENT;
    default:
        return MM_SMS_STATE_UNKNOWN;
    }
}

static void
sms_pdu_part_list_ready (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GTask *task)
{
    ListPartsContext *ctx;
    const gchar *response;
    GError *error = NULL;
    GList *info_list;
    GList *l;

    /* Always always always unlock mem1 storage. Warned you've been. */
    mm_broadband_modem_unlock_sms_storages (self, TRUE, FALSE);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    info_list = mm_3gpp_parse_pdu_cmgl_response (response, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    for (l = info_list; l; l = g_list_next (l)) {
        MM3gppPduInfo *info = l->data;
        MMSmsPart *part;

        part = mm_sms_part_3gpp_new_from_pdu (info->index, info->pdu, &error);
        if (part) {
            mm_dbg ("Correctly parsed PDU (%d)", info->index);
            mm_iface_modem_messaging_take_part (MM_IFACE_MODEM_MESSAGING (self),
                                                part,
                                                sms_state_from_index (info->status),
                                                ctx->list_storage);
        } else {
            /* Don't treat the error as critical */
            mm_dbg ("Error parsing PDU (%d): %s", info->index, error->message);
            g_clear_error (&error);
        }
    }

    mm_3gpp_pdu_info_list_free (info_list);

    /* We consider all done */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
list_parts_lock_storages_ready (MMBroadbandModem *self,
                                GAsyncResult *res,
                                GTask *task)
{
    GError *error = NULL;

    if (!mm_broadband_modem_lock_sms_storages_finish (self, res, &error)) {
        /* TODO: we should either make this lock() never fail, by automatically
         * retrying after some time, or otherwise retry here. */
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Storage now set and locked */

    /* Get SMS parts from ALL types.
     * Different command to be used if we are on Text or PDU mode */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              (MM_BROADBAND_MODEM (self)->priv->modem_messaging_sms_pdu_mode ?
                               "+CMGL=4" :
                               "+CMGL=\"ALL\""),
                              20,
                              FALSE,
                              (GAsyncReadyCallback) (MM_BROADBAND_MODEM (self)->priv->modem_messaging_sms_pdu_mode ?
                                                     sms_pdu_part_list_ready :
                                                     sms_text_part_list_ready),
                              task);
}

static void
modem_messaging_load_initial_sms_parts (MMIfaceModemMessaging *self,
                                        MMSmsStorage storage,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
    ListPartsContext *ctx;
    GTask *task;

    ctx = g_new (ListPartsContext, 1);
    ctx->list_storage = storage;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, g_free);

    mm_dbg ("Listing SMS parts in storage '%s'",
            mm_sms_storage_get_string (storage));

    /* First, request to set the proper storage to read from */
    mm_broadband_modem_lock_sms_storages (MM_BROADBAND_MODEM (self),
                                          storage,
                                          MM_SMS_STORAGE_UNKNOWN,
                                          (GAsyncReadyCallback)list_parts_lock_storages_ready,
                                          task);
}

/*****************************************************************************/
/* Create SMS (Messaging interface) */

static MMBaseSms *
modem_messaging_create_sms (MMIfaceModemMessaging *self)
{
    return mm_base_sms_new (MM_BASE_MODEM (self));
}

/*****************************************************************************/
/* Check if Voice supported (Voice interface) */

static gboolean
modem_voice_check_support_finish (MMIfaceModemVoice *self,
                                  GAsyncResult *res,
                                  GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
ath_format_check_ready (MMBroadbandModem *self,
                        GAsyncResult *res,
                        GTask *task)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* ATH command is supported; assume we have full voice capabilities */
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_voice_check_support (MMIfaceModemVoice *self,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* We assume that all modems have voice capabilities, but ... */

    /* Check ATH support */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "H",
                              3,
                              TRUE,
                              (GAsyncReadyCallback)ath_format_check_ready,
                              task);
}

/*****************************************************************************/
/* Setup/cleanup voice related unsolicited events (Voice interface) */

static gboolean
modem_voice_setup_cleanup_unsolicited_events_finish (MMIfaceModemVoice *self,
                                                     GAsyncResult *res,
                                                     GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
ring_received (MMPortSerialAt *port,
               GMatchInfo *info,
               MMBroadbandModem *self)
{
    mm_dbg ("Ringing");
    mm_iface_modem_voice_create_incoming_call (MM_IFACE_MODEM_VOICE (self));
}

static void
cring_received (MMPortSerialAt *port,
                GMatchInfo *info,
                MMBroadbandModem *self)
{
    /* The match info gives us in which storage the index applies */
    gchar *str;

    /* We could have "VOICE" or "DATA". Now consider only "VOICE" */

    str = mm_get_string_unquoted_from_match_info (info, 1);
    mm_dbg ("Ringing (%s)", str);
    g_free (str);

    mm_iface_modem_voice_create_incoming_call (MM_IFACE_MODEM_VOICE (self));
}

static void
clip_received (MMPortSerialAt *port,
               GMatchInfo *info,
               MMBroadbandModem *self)
{
    /* The match info gives us in which storage the index applies */
    gchar *str;

    str = mm_get_string_unquoted_from_match_info (info, 1);

    if (str) {
        guint validity  = 0;
        guint type      = 0;

        mm_get_uint_from_match_info (info, 2, &type);
        mm_get_uint_from_match_info (info, 3, &validity);

        mm_dbg ("Caller ID received: number '%s', type '%d', validity '%d'", str, type, validity);

        mm_iface_modem_voice_update_incoming_call_number (MM_IFACE_MODEM_VOICE (self), str, type, validity);

        g_free (str);
    }
}

static void
set_voice_unsolicited_events_handlers (MMIfaceModemVoice *self,
                                       gboolean enable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    MMPortSerialAt *ports[2];
    GRegex *cring_regex;
    GRegex *ring_regex;
    GRegex *clip_regex;
    guint i;
    GTask *task;

    cring_regex = mm_voice_cring_regex_get ();
    ring_regex  = mm_voice_ring_regex_get ();
    clip_regex  = mm_voice_clip_regex_get ();
    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    /* Enable unsolicited events in given port */
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        /* Set/unset unsolicited CMTI event handler */
        mm_dbg ("(%s) %s voice unsolicited events handlers",
                mm_port_get_device (MM_PORT (ports[i])),
                enable ? "Setting" : "Removing");
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            cring_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) cring_received : NULL,
            enable ? self : NULL,
            NULL);
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            ring_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) ring_received : NULL,
            enable ? self : NULL,
            NULL);
        mm_port_serial_at_add_unsolicited_msg_handler (
            ports[i],
            clip_regex,
            enable ? (MMPortSerialAtUnsolicitedMsgFn) clip_received : NULL,
            enable ? self : NULL,
            NULL);
    }

    g_regex_unref (clip_regex);
    g_regex_unref (cring_regex);
    g_regex_unref (ring_regex);

    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
modem_voice_setup_unsolicited_events (MMIfaceModemVoice *self,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    set_voice_unsolicited_events_handlers (self, TRUE, callback, user_data);
}

static void
modem_voice_cleanup_unsolicited_events (MMIfaceModemVoice *self,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data)
{
    set_voice_unsolicited_events_handlers (self, FALSE, callback, user_data);
}

/*****************************************************************************/
/* Enable unsolicited events (CALL indications) (Voice interface) */

static gboolean
modem_voice_enable_unsolicited_events_finish (MMIfaceModemVoice *self,
                                              GAsyncResult *res,
                                              GError **error)
{
    GError *inner_error = NULL;

    mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return FALSE;
    }

    return TRUE;
}

static gboolean
ring_response_processor (MMBaseModem *self,
                         gpointer none,
                         const gchar *command,
                         const gchar *response,
                         gboolean last_command,
                         const GError *error,
                         GVariant **result,
                         GError **result_error)
{
    if (error) {
        /* If we get a not-supported error and we're not in the last command, we
         * won't set 'result_error', so we'll keep on the sequence */
        if (!g_error_matches (error, MM_MESSAGE_ERROR, MM_MESSAGE_ERROR_NOT_SUPPORTED) ||
            last_command)
            *result_error = g_error_copy (error);

        return TRUE;
    }

    *result = NULL;
    return FALSE;
}

static const MMBaseModemAtCommand ring_sequence[] = {
    /* Show caller number on RING. */
    { "+CLIP=1", 3, FALSE, ring_response_processor },
    /* Show difference between data call and voice call */
    { "+CRC=1", 3, FALSE, ring_response_processor },
    { NULL }
};

static void
modem_voice_enable_unsolicited_events (MMIfaceModemVoice *self,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    mm_base_modem_at_sequence (
        MM_BASE_MODEM (self),
        ring_sequence,
        NULL, /* response_processor_context */
        NULL, /* response_processor_context_free */
        callback,
        user_data);
}

/*****************************************************************************/
/* Create CALL (Voice interface) */

static MMBaseCall *
modem_voice_create_call (MMIfaceModemVoice *self)
{
    return mm_base_call_new (MM_BASE_MODEM (self));
}

/*****************************************************************************/
/* ESN loading (CDMA interface) */

static gchar *
modem_cdma_load_esn_finish (MMIfaceModemCdma *self,
                            GAsyncResult *res,
                            GError **error)
{
    const gchar *result;
    gchar *esn = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    result = mm_strip_tag (result, "+GSN:");
    mm_parse_gsn (result, NULL, NULL, &esn);
    mm_dbg ("loaded ESN: %s", esn);
    return esn;
}

static void
modem_cdma_load_esn (MMIfaceModemCdma *self,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
    mm_dbg ("loading ESN...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+GSN",
                              3,
                              TRUE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* MEID loading (CDMA interface) */

static gchar *
modem_cdma_load_meid_finish (MMIfaceModemCdma *self,
                             GAsyncResult *res,
                             GError **error)
{
    const gchar *result;
    gchar *meid = NULL;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!result)
        return NULL;

    result = mm_strip_tag (result, "+GSN:");
    mm_parse_gsn (result, NULL, &meid, NULL);
    mm_dbg ("loaded MEID: %s", meid);
    return meid;
}

static void
modem_cdma_load_meid (MMIfaceModemCdma *self,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    /* Some devices return both the MEID and the ESN in the +GSN response */
    mm_dbg ("loading MEID...");
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+GSN",
                              3,
                              TRUE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Setup/Cleanup unsolicited events (CDMA interface) */

typedef struct {
    MMBroadbandModem *self;
    gboolean setup;
    GSimpleAsyncResult *result;
    MMPortSerialQcdm *qcdm;
} CdmaUnsolicitedEventsContext;

static void
cdma_unsolicited_events_context_complete_and_free (CdmaUnsolicitedEventsContext *ctx,
                                                   gboolean close_port,
                                                   GError *error)
{
    if (error)
        g_simple_async_result_take_error (ctx->result, error);
    else
        g_simple_async_result_set_op_res_gboolean (ctx->result, TRUE);
    g_simple_async_result_complete_in_idle (ctx->result);

    g_clear_object (&ctx->result);
    g_clear_object (&ctx->self);

    if (ctx->qcdm && close_port)
        mm_port_serial_close (MM_PORT_SERIAL (ctx->qcdm));
    g_clear_object (&ctx->qcdm);

    g_free (ctx);
}

static void
logcmd_qcdm_ready (MMPortSerialQcdm *port,
                   GAsyncResult *res,
                   CdmaUnsolicitedEventsContext *ctx)
{
    QcdmResult *result;
    gint err = QCDM_SUCCESS;
    GByteArray *response;
    GError *error = NULL;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        cdma_unsolicited_events_context_complete_and_free (ctx, TRUE, error);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_log_config_set_mask_result ((const gchar *) response->data,
                                                  response->len,
                                                  &err);
    g_byte_array_unref (response);
    if (!result) {
        error = g_error_new (MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Failed to parse Log Config Set Mask command result: %d",
                             err);
        cdma_unsolicited_events_context_complete_and_free (ctx, TRUE, error);
        return;
    }

    mm_port_serial_qcdm_add_unsolicited_msg_handler (port,
                                                     DM_LOG_ITEM_EVDO_PILOT_SETS_V2,
                                                     ctx->setup ? qcdm_evdo_pilot_sets_log_handle : NULL,
                                                     ctx->self,
                                                     NULL);

    qcdm_result_unref (result);

    /* Balance the mm_port_seral_open() from modem_cdma_setup_cleanup_unsolicited_events().
     * We want to close it in either case:
     *  (a) we're cleaning up and setup opened the port
     *  (b) if it was unexpectedly closed before cleanup and thus cleanup opened it
     *
     * Setup should leave the port open to allow log messages to be received
     * and sent to handlers.
     */
    cdma_unsolicited_events_context_complete_and_free (ctx, ctx->setup ? FALSE : TRUE, NULL);
}

static void
modem_cdma_setup_cleanup_unsolicited_events (MMBroadbandModem *self,
                                             gboolean setup,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data)
{
    CdmaUnsolicitedEventsContext *ctx;
    GByteArray *logcmd;
    uint16_t log_items[] = { DM_LOG_ITEM_EVDO_PILOT_SETS_V2, 0 };
    GError *error = NULL;

    ctx = g_new0 (CdmaUnsolicitedEventsContext, 1);
    ctx->self = g_object_ref (self);
    ctx->setup = TRUE;
    ctx->result = g_simple_async_result_new (G_OBJECT (self),
                                             callback,
                                             user_data,
                                             modem_cdma_setup_cleanup_unsolicited_events);
    ctx->qcdm = mm_base_modem_get_port_qcdm (MM_BASE_MODEM (self));
    if (!ctx->qcdm) {
        cdma_unsolicited_events_context_complete_and_free (ctx, FALSE, NULL);
        return;
    }

    /* Setup must open the QCDM port and keep it open to receive unsolicited
     * events.  Cleanup expects the port to already be opened from setup, but
     * if not we still want to open it and try to disable log messages.
     */
    if (setup || !mm_port_serial_is_open (MM_PORT_SERIAL (ctx->qcdm))) {
        if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->qcdm), &error)) {
            cdma_unsolicited_events_context_complete_and_free (ctx, FALSE, error);
            return;
        }
    }

    logcmd = g_byte_array_sized_new (512);
    logcmd->len = qcdm_cmd_log_config_set_mask_new ((char *) logcmd->data,
                                                    512,
                                                    0x01,  /* Equipment ID */
                                                    setup ? log_items : NULL);
    assert (logcmd->len);

    mm_port_serial_qcdm_command (ctx->qcdm,
                                 logcmd,
                                 5,
                                 NULL,
                                 (GAsyncReadyCallback)logcmd_qcdm_ready,
                                 ctx);
    g_byte_array_unref (logcmd);
}

static gboolean
modem_cdma_setup_cleanup_unsolicited_events_finish (MMIfaceModemCdma *self,
                                                    GAsyncResult *res,
                                                    GError **error)
{
    return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
}

static void
modem_cdma_setup_unsolicited_events (MMIfaceModemCdma *self,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data)
{
    modem_cdma_setup_cleanup_unsolicited_events (MM_BROADBAND_MODEM (self),
                                                 TRUE,
                                                 callback,
                                                 user_data);
}

static void
modem_cdma_cleanup_unsolicited_events (MMIfaceModemCdma *self,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
    modem_cdma_setup_cleanup_unsolicited_events (MM_BROADBAND_MODEM (self),
                                                 FALSE,
                                                 callback,
                                                 user_data);
}

/*****************************************************************************/
/* HDR state check (CDMA interface) */

typedef struct {
    guint8 hybrid_mode;
    guint8 session_state;
    guint8 almp_state;
} HdrStateResults;

static void
hdr_state_cleanup_port (MMPortSerial *port)
{
    mm_port_serial_close (port);
    g_object_unref (port);
}

static gboolean
modem_cdma_get_hdr_state_finish (MMIfaceModemCdma *self,
                                 GAsyncResult *res,
                                 guint8 *hybrid_mode,
                                 guint8 *session_state,
                                 guint8 *almp_state,
                                 GError **error)
{
    HdrStateResults *results;

    results = g_task_propagate_pointer (G_TASK (res), error);
    if (!results)
        return FALSE;

    *hybrid_mode = results->hybrid_mode;
    *session_state = results->session_state;
    *almp_state = results->almp_state;
    g_free (results);

    return TRUE;
}

static void
hdr_subsys_state_info_ready (MMPortSerialQcdm *port,
                             GAsyncResult *res,
                             GTask *task)
{
    QcdmResult *result;
    HdrStateResults *results;
    gint err = QCDM_SUCCESS;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_hdr_subsys_state_info_result ((const gchar *) response->data,
                                                    response->len,
                                                    &err);
    g_byte_array_unref (response);
    if (!result) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Failed to parse HDR subsys state info command result: %d",
                                 err);
        g_object_unref (task);
        return;
    }

    /* Build results */
    results = g_new0 (HdrStateResults, 1);
    qcdm_result_get_u8 (result, QCDM_CMD_HDR_SUBSYS_STATE_INFO_ITEM_HDR_HYBRID_MODE, &results->hybrid_mode);
    results->session_state = QCDM_CMD_HDR_SUBSYS_STATE_INFO_SESSION_STATE_CLOSED;
    qcdm_result_get_u8 (result, QCDM_CMD_HDR_SUBSYS_STATE_INFO_ITEM_SESSION_STATE, &results->session_state);
    results->almp_state = QCDM_CMD_HDR_SUBSYS_STATE_INFO_ALMP_STATE_INACTIVE;
    qcdm_result_get_u8 (result, QCDM_CMD_HDR_SUBSYS_STATE_INFO_ITEM_ALMP_STATE, &results->almp_state);
    qcdm_result_unref (result);

    g_task_return_pointer (task, results, g_free);
    g_object_unref (task);
}

static void
modem_cdma_get_hdr_state (MMIfaceModemCdma *self,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    MMPortSerialQcdm *qcdm;
    GTask *task;
    GByteArray *hdrstate;
    GError *error = NULL;

    task = g_task_new (self, NULL, callback, user_data);

    qcdm = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (!qcdm) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_UNSUPPORTED,
                                 "Cannot get HDR state without a QCDM port");
        g_object_unref (task);
        return;
    }

    if (!mm_port_serial_open (MM_PORT_SERIAL (qcdm), &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    g_task_set_task_data (task,
                          g_object_ref (qcdm),
                          (GDestroyNotify) hdr_state_cleanup_port);

    /* Setup command */
    hdrstate = g_byte_array_sized_new (25);
    hdrstate->len = qcdm_cmd_hdr_subsys_state_info_new ((gchar *) hdrstate->data, 25);
    g_assert (hdrstate->len);

    mm_port_serial_qcdm_command (qcdm,
                                 hdrstate,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)hdr_subsys_state_info_ready,
                                 task);
    g_byte_array_unref (hdrstate);
}

/*****************************************************************************/
/* Call Manager state check (CDMA interface) */

typedef struct {
    guint system_mode;
    guint operating_mode;
} CallManagerStateResults;

typedef struct {
    MMBroadbandModem *self;
    GSimpleAsyncResult *result;
    MMPortSerialQcdm *qcdm;
} CallManagerStateContext;

static void
cm_state_cleanup_port (MMPortSerial *port)
{
    mm_port_serial_close (port);
    g_object_unref (port);
}

static gboolean
modem_cdma_get_call_manager_state_finish (MMIfaceModemCdma *self,
                                          GAsyncResult *res,
                                          guint *system_mode,
                                          guint *operating_mode,
                                          GError **error)
{
    CallManagerStateResults *result;

    result = g_task_propagate_pointer (G_TASK (res), error);
    if (!result)
        return FALSE;

    *system_mode = result->system_mode;
    *operating_mode = result->operating_mode;
    g_free (result);

    return TRUE;
}

static void
cm_subsys_state_info_ready (MMPortSerialQcdm *port,
                            GAsyncResult *res,
                            GTask *task)
{
    QcdmResult *result;
    CallManagerStateResults *results;
    gint err = QCDM_SUCCESS;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Parse the response */
    result = qcdm_cmd_cm_subsys_state_info_result ((const gchar *) response->data,
                                                   response->len,
                                                   &err);
    g_byte_array_unref (response);
    if (!result) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Failed to parse CM subsys state info command result: %d",
                                 err);
        g_object_unref (task);
        return;
    }

    /* Build results */
    results = g_new0 (CallManagerStateResults, 1);
    qcdm_result_get_u32 (result, QCDM_CMD_CM_SUBSYS_STATE_INFO_ITEM_OPERATING_MODE, &results->operating_mode);
    qcdm_result_get_u32 (result, QCDM_CMD_CM_SUBSYS_STATE_INFO_ITEM_SYSTEM_MODE, &results->system_mode);
    qcdm_result_unref (result);

    g_task_return_pointer (task, results, g_free);
    g_object_unref (task);
}

static void
modem_cdma_get_call_manager_state (MMIfaceModemCdma *self,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data)
{
    MMPortSerialQcdm *qcdm;
    GTask *task;
    GByteArray *cmstate;
    GError *error = NULL;

    task = g_task_new (self, NULL, callback, user_data);

    qcdm = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (!qcdm) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_UNSUPPORTED,
                                 "Cannot get call manager state without a QCDM port");
        g_object_unref (task);
        return;
    }

    if (!mm_port_serial_open (MM_PORT_SERIAL (qcdm), &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    g_task_set_task_data (task,
                          g_object_ref (qcdm),
                          (GDestroyNotify) cm_state_cleanup_port);

    /* Setup command */
    cmstate = g_byte_array_sized_new (25);
    cmstate->len = qcdm_cmd_cm_subsys_state_info_new ((gchar *) cmstate->data, 25);
    g_assert (cmstate->len);

    mm_port_serial_qcdm_command (qcdm,
                                 cmstate,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback)cm_subsys_state_info_ready,
                                 task);
    g_byte_array_unref (cmstate);
}

/*****************************************************************************/
/* Serving System check (CDMA interface) */

typedef struct {
    guint sid;
    guint nid;
    guint class;
    guint band;
} Cdma1xServingSystemResults;

static void
cdma1x_serving_system_state_cleanup_port (MMPortSerial *port)
{
    mm_port_serial_close (port);
    g_object_unref (port);
}

static void
cdma1x_serving_system_complete_and_free (GTask *task,
                                         guint sid,
                                         guint nid,
                                         guint class,
                                         guint band)
{
    Cdma1xServingSystemResults *results;

    results = g_new0 (Cdma1xServingSystemResults, 1);
    results->sid = sid;
    results->band = band;
    results->class = class;
    results->nid = nid;

    g_task_return_pointer (task, results, g_free);
    g_object_unref (task);
}

static GError *
cdma1x_serving_system_no_service_error (void)
{
    /* NOTE: update get_cdma1x_serving_system_ready() in mm-iface-modem-cdma.c
     * if this error changes */
    return g_error_new_literal (MM_MOBILE_EQUIPMENT_ERROR,
                                MM_MOBILE_EQUIPMENT_ERROR_NO_NETWORK,
                                "No CDMA service");
}

static gboolean
modem_cdma_get_cdma1x_serving_system_finish (MMIfaceModemCdma *self,
                                             GAsyncResult *res,
                                             guint *class,
                                             guint *band,
                                             guint *sid,
                                             guint *nid,
                                             GError **error)
{
    Cdma1xServingSystemResults *results;

    results = g_task_propagate_pointer (G_TASK (res), error);
    if (!results)
        return FALSE;

    *sid = results->sid;
    *nid = results->nid;
    *class = results->class;
    *band = results->band;
    g_free (results);

    return TRUE;
}

static void
css_query_ready (MMIfaceModemCdma *self,
                 GAsyncResult *res,
                 GTask *task)
{
    GError *error = NULL;
    const gchar *result;
    gint class = 0;
    gint sid = MM_MODEM_CDMA_SID_UNKNOWN;
    gint num;
    guchar band = 'Z';
    gboolean class_ok = FALSE;
    gboolean band_ok = FALSE;
    gboolean success = FALSE;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Strip any leading command tag and spaces */
    result = mm_strip_tag (result, "+CSS:");
    num = sscanf (result, "? , %d", &sid);
    if (num == 1) {
        /* UTStarcom and Huawei modems that use IS-707-A format; note that
         * this format obviously doesn't have other indicators like band and
         * class and thus SID 0 will be reported as "no service" (see below).
         */
        class = 0;
        band = 'Z';
        success = TRUE;
    } else {
        GRegex *r;
        GMatchInfo *match_info;

        /* Format is "<band_class>,<band>,<sid>" */
        r = g_regex_new ("\\s*([^,]*?)\\s*,\\s*([^,]*?)\\s*,\\s*(\\d+)", G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, NULL);
        g_assert (r);

        g_regex_match (r, result, 0, &match_info);
        if (g_match_info_get_match_count (match_info) >= 3) {
            gint override_class = 0;
            gchar *str;

            /* band class */
            str = g_match_info_fetch (match_info, 1);
            class = mm_cdma_normalize_class (str);
            g_free (str);

            /* band */
            str = g_match_info_fetch (match_info, 2);
            band = mm_cdma_normalize_band (str, &override_class);
            if (override_class)
                class = override_class;
            g_free (str);

            /* sid */
            str = g_match_info_fetch (match_info, 3);
            if (!mm_get_int_from_str (str, &sid))
                sid = MM_MODEM_CDMA_SID_UNKNOWN;
            g_free (str);

            success = TRUE;
        }

        g_match_info_free (match_info);
        g_regex_unref (r);
    }

    if (!success) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Could not parse Serving System results");
        g_object_unref (task);
        return;
    }

    /* Normalize the SID */
    if (sid < 0 || sid > 32767)
        sid = MM_MODEM_CDMA_SID_UNKNOWN;

    if (class == 1 || class == 2)
        class_ok = TRUE;
    if (band != 'Z')
        band_ok = TRUE;

    /* Return 'no service' if none of the elements of the +CSS response
     * indicate that the modem has service.  Note that this allows SID 0
     * when at least one of the other elements indicates service.
     * Normally we'd treat SID 0 as 'no service' but some modems
     * (Sierra 5725) sometimes return SID 0 even when registered.
     */
    if (sid == 0 && !class_ok && !band_ok)
        sid = MM_MODEM_CDMA_SID_UNKNOWN;

    /* 99999 means unknown/no service */
    if (sid == MM_MODEM_CDMA_SID_UNKNOWN) {
        g_task_return_error (task, cdma1x_serving_system_no_service_error ());
        g_object_unref (task);
        return;
    }

    /* No means to get NID with AT commands right now */
    cdma1x_serving_system_complete_and_free (task, sid, MM_MODEM_CDMA_NID_UNKNOWN, class, band);
}

static void
serving_system_query_css (GTask *task)
{
    mm_base_modem_at_command (MM_BASE_MODEM (g_task_get_source_object (task)),
                              "+CSS?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)css_query_ready,
                              task);
}

static void
qcdm_cdma_status_ready (MMPortSerialQcdm *port,
                        GAsyncResult *res,
                        GTask *task)
{
    QcdmResult *result = NULL;
    guint32 sid = MM_MODEM_CDMA_SID_UNKNOWN;
    guint32 nid = MM_MODEM_CDMA_NID_UNKNOWN;
    guint32 rxstate = 0;
    gint err = QCDM_SUCCESS;
    GError *error = NULL;
    GByteArray *response;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (error) {
        mm_dbg ("Failed to get cdma status: %s", error->message);
        g_clear_error (&error);

        /* Fall back to AT+CSS */
        serving_system_query_css (task);
        return;
    }

    result = qcdm_cmd_cdma_status_result ((const gchar *) response->data,
                                          response->len,
                                          &err);
    if (!result) {
        if (err != QCDM_SUCCESS)
            mm_dbg ("Failed to parse cdma status command result: %d", err);
        g_byte_array_unref (response);

        /* Fall back to AT+CSS */
        serving_system_query_css (task);
        return;
    }

    g_byte_array_unref (response);

    qcdm_result_get_u32 (result, QCDM_CMD_CDMA_STATUS_ITEM_RX_STATE, &rxstate);
    qcdm_result_get_u32 (result, QCDM_CMD_CDMA_STATUS_ITEM_SID, &sid);
    qcdm_result_get_u32 (result, QCDM_CMD_CDMA_STATUS_ITEM_NID, &nid);
    qcdm_result_unref (result);

    /* 99999 means unknown/no service */
    if (rxstate == QCDM_CMD_CDMA_STATUS_RX_STATE_ENTERING_CDMA) {
        sid = MM_MODEM_CDMA_SID_UNKNOWN;
        nid = MM_MODEM_CDMA_NID_UNKNOWN;
    }

    mm_dbg ("CDMA 1x Status RX state: %d", rxstate);
    mm_dbg ("CDMA 1x Status SID: %d", sid);
    mm_dbg ("CDMA 1x Status NID: %d", nid);

    cdma1x_serving_system_complete_and_free (task,
                                             sid,
                                             nid,
                                             0,
                                             (sid == MM_MODEM_CDMA_SID_UNKNOWN) ? 0 : 'Z');
}

static void
modem_cdma_get_cdma1x_serving_system (MMIfaceModemCdma *self,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    GError *error = NULL;
    GByteArray *cdma_status;
    GTask *task;
    MMPortSerialQcdm *qcdm;

    task = g_task_new (self, NULL, callback, user_data);

    qcdm = mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));
    if (!qcdm) {
        /* Fall back to AT+CSS */
        serving_system_query_css (task);
        return;
    }

    if (!mm_port_serial_open (MM_PORT_SERIAL (qcdm), &error)) {
        mm_dbg ("Failed to open QCDM port for serving-system request: %s", error->message);
        g_error_free (error);

        /* Fall back to AT+CSS */
        serving_system_query_css (task);
        return;
    }

    g_task_set_task_data (task,
                          g_object_ref (qcdm),
                          (GDestroyNotify) cdma1x_serving_system_state_cleanup_port);

    /* Setup command */
    cdma_status = g_byte_array_sized_new (25);
    cdma_status->len = qcdm_cmd_cdma_status_new ((char *) cdma_status->data, 25);
    g_assert (cdma_status->len);
    mm_port_serial_qcdm_command (qcdm,
                                 cdma_status,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback) qcdm_cdma_status_ready,
                                 task);
    g_byte_array_unref (cdma_status);
}

/*****************************************************************************/
/* Service status, analog/digital check (CDMA interface) */

static gboolean
modem_cdma_get_service_status_finish (MMIfaceModemCdma *self,
                                      GAsyncResult *res,
                                      gboolean *has_cdma_service,
                                      GError **error)
{
    GError *inner_error = NULL;
    gboolean value;

    value = g_task_propagate_boolean (G_TASK (res), error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return FALSE;
    }

    *has_cdma_service = value;
    return TRUE;
}

static void
cad_query_ready (MMIfaceModemCdma *self,
                 GAsyncResult *res,
                 GTask *task)
{
    GError *error = NULL;
    const gchar *result;

    result = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error)
        g_task_return_error (task, error);
    else {
        guint cad;

        /* Strip any leading command tag and spaces */
        result = mm_strip_tag (result, "+CAD:");
        if (!mm_get_uint_from_str (result, &cad))
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "Failed to parse +CAD response '%s'",
                                     result);
        else
            /* 1 == CDMA service */
            g_task_return_boolean (task, (cad == 1));
    }
    g_object_unref (task);
}

static void
modem_cdma_get_service_status (MMIfaceModemCdma *self,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CAD?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)cad_query_ready,
                              task);
}

/*****************************************************************************/
/* Detailed registration state (CDMA interface) */

typedef struct {
    MMModemCdmaRegistrationState detailed_cdma1x_state;
    MMModemCdmaRegistrationState detailed_evdo_state;
} DetailedRegistrationStateResults;

typedef struct {
    MMPortSerialAt *port;
    MMModemCdmaRegistrationState cdma1x_state;
    MMModemCdmaRegistrationState evdo_state;
} DetailedRegistrationStateContext;

static DetailedRegistrationStateResults *
detailed_registration_state_result_new (DetailedRegistrationStateContext *ctx)
{
    DetailedRegistrationStateResults *results;

    results = g_new (DetailedRegistrationStateResults, 1);
    results->detailed_cdma1x_state = ctx->cdma1x_state;
    results->detailed_evdo_state = ctx->evdo_state;

    return results;
}

static void
detailed_registration_state_context_free (DetailedRegistrationStateContext *ctx)
{
    g_object_unref (ctx->port);
    g_free (ctx);
}

static gboolean
modem_cdma_get_detailed_registration_state_finish (MMIfaceModemCdma *self,
                                                   GAsyncResult *res,
                                                   MMModemCdmaRegistrationState *detailed_cdma1x_state,
                                                   MMModemCdmaRegistrationState *detailed_evdo_state,
                                                   GError **error)
{
    DetailedRegistrationStateResults *results;

    results = g_task_propagate_pointer (G_TASK (res), error);
    if (!results)
        return FALSE;

    *detailed_cdma1x_state = results->detailed_cdma1x_state;
    *detailed_evdo_state = results->detailed_evdo_state;
    g_free (results);
    return TRUE;
}

static void
speri_ready (MMIfaceModemCdma *self,
             GAsyncResult *res,
             GTask *task)
{
    DetailedRegistrationStateContext *ctx;
    gboolean roaming = FALSE;
    const gchar *response;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        /* silently discard SPERI errors */
        g_error_free (error);
        g_task_return_pointer (task,
                               detailed_registration_state_result_new (ctx),
                               g_free);
        g_object_unref (task);
        return;
    }

    /* Try to parse the results */
    response = mm_strip_tag (response, "$SPERI:");
    if (!response ||
        !mm_cdma_parse_eri (response, &roaming, NULL, NULL)) {
        mm_warn ("Couldn't parse SPERI response '%s'", response);
        g_task_return_pointer (task,
                               detailed_registration_state_result_new (ctx),
                               g_free);
        g_object_unref (task);
        return;
    }

    if (roaming) {
        /* Change the 1x and EVDO registration states to roaming if they were
         * anything other than UNKNOWN.
         */
        if (ctx->cdma1x_state > MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)
            ctx->cdma1x_state = MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
        if (ctx->evdo_state > MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)
            ctx->evdo_state = MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING;
    } else {
        /* Change 1x and/or EVDO registration state to home if home/roaming wasn't previously known */
        if (ctx->cdma1x_state == MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED)
            ctx->cdma1x_state = MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
        if (ctx->evdo_state == MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED)
            ctx->evdo_state = MM_MODEM_CDMA_REGISTRATION_STATE_HOME;
    }

    g_task_return_pointer (task,
                           detailed_registration_state_result_new (ctx),
                           g_free);
    g_object_unref (task);
}

static void
spservice_ready (MMIfaceModemCdma *self,
                 GAsyncResult *res,
                 GTask *task)
{
    DetailedRegistrationStateContext *ctx;
    GError *error = NULL;
    const gchar *response;
    MMModemCdmaRegistrationState cdma1x_state;
    MMModemCdmaRegistrationState evdo_state;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Try to parse the results */
    cdma1x_state = MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
    evdo_state = MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
    if (!mm_cdma_parse_spservice_read_response (response,
                                                &cdma1x_state,
                                                &evdo_state)) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_FAILED,
                                 "Couldn't parse SPSERVICE response '%s'",
                                 response);
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    /* Store new intermediate results */
    ctx->cdma1x_state = cdma1x_state;
    ctx->evdo_state = evdo_state;

    /* If SPERI not supported, we're done */
    if (!MM_BROADBAND_MODEM (self)->priv->has_speri) {
        g_task_return_pointer (task,
                               detailed_registration_state_result_new (ctx),
                               g_free);
        g_object_unref (task);
        return;
    }

    /* Get roaming status to override generic registration state */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "$SPERI?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)speri_ready,
                              task);
}

static void
modem_cdma_get_detailed_registration_state (MMIfaceModemCdma *self,
                                            MMModemCdmaRegistrationState cdma1x_state,
                                            MMModemCdmaRegistrationState evdo_state,
                                            GAsyncReadyCallback callback,
                                            gpointer user_data)
{
    MMPortSerialAt *port;
    GError *error = NULL;
    DetailedRegistrationStateContext *ctx;
    GTask *task;

    /* The default implementation to get detailed registration state
     * requires the use of an AT port; so if we cannot get any, just
     * return the error */
    port = mm_base_modem_peek_best_at_port (MM_BASE_MODEM (self), &error);
    if (!port) {
        g_task_report_error (self,
                             callback,
                             user_data,
                             modem_cdma_get_detailed_registration_state,
                             error);
        return;
    }

    /* Setup context */
    ctx = g_new0 (DetailedRegistrationStateContext, 1);
    ctx->port = g_object_ref (port);
    ctx->cdma1x_state = cdma1x_state;
    ctx->evdo_state = evdo_state;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)detailed_registration_state_context_free);

    /* NOTE: If we get this generic implementation of getting detailed
     * registration state called, we DO know that we have Sprint commands
     * supported, we checked it in setup_registration_checks() */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+SPSERVICE?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)spservice_ready,
                              task);
}

/*****************************************************************************/
/* Setup registration checks (CDMA interface) */

typedef struct {
    gboolean skip_qcdm_call_manager_step;
    gboolean skip_qcdm_hdr_step;
    gboolean skip_at_cdma_service_status_step;
    gboolean skip_at_cdma1x_serving_system_step;
    gboolean skip_detailed_registration_state;
} SetupRegistrationChecksResults;

typedef struct {
    MMBroadbandModem *self;
    GSimpleAsyncResult *result;
    GError *error;
    gboolean has_qcdm_port;
    gboolean has_sprint_commands;
} SetupRegistrationChecksContext;

static void
setup_registration_checks_context_complete_and_free (SetupRegistrationChecksContext *ctx)
{
    if (ctx->error)
        g_simple_async_result_take_error (ctx->result, ctx->error);
    else {
        SetupRegistrationChecksResults *results;

        results = g_new0 (SetupRegistrationChecksResults, 1);

        /* Skip QCDM steps if no QCDM port */
        if (!ctx->has_qcdm_port) {
            mm_dbg ("Will skip all QCDM-based registration checks");
            results->skip_qcdm_call_manager_step = TRUE;
            results->skip_qcdm_hdr_step = TRUE;
        }

        if (MM_IFACE_MODEM_CDMA_GET_INTERFACE (ctx->self)->get_detailed_registration_state ==
            modem_cdma_get_detailed_registration_state) {
            /* Skip CDMA1x Serving System check if we have Sprint specific
             * commands AND if the default detailed registration checker
             * is the generic one. Implementations knowing that their
             * CSS response is undesired, should either setup NULL callbacks
             * for the specific step, or subclass this setup and return
             * FALSE themselves. */
            if (ctx->has_sprint_commands) {
                mm_dbg ("Will skip CDMA1x Serving System check, "
                        "we do have Sprint commands");
                results->skip_at_cdma1x_serving_system_step = TRUE;
            } else {
                /* If there aren't Sprint specific commands, and the detailed
                 * registration state getter wasn't subclassed, skip the step */
                mm_dbg ("Will skip generic detailed registration check, we "
                        "don't have Sprint commands");
                results->skip_detailed_registration_state = TRUE;
            }
        }

        g_simple_async_result_set_op_res_gpointer (ctx->result, results, g_free);
    }

    g_simple_async_result_complete_in_idle (ctx->result);
    g_object_unref (ctx->result);
    g_object_unref (ctx->self);
    g_free (ctx);
}

static gboolean
modem_cdma_setup_registration_checks_finish (MMIfaceModemCdma *self,
                                             GAsyncResult *res,
                                             gboolean *skip_qcdm_call_manager_step,
                                             gboolean *skip_qcdm_hdr_step,
                                             gboolean *skip_at_cdma_service_status_step,
                                             gboolean *skip_at_cdma1x_serving_system_step,
                                             gboolean *skip_detailed_registration_state,
                                             GError **error)
{
    SetupRegistrationChecksResults *results;

    if (g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error))
        return FALSE;

    results = g_simple_async_result_get_op_res_gpointer (G_SIMPLE_ASYNC_RESULT (res));
    *skip_qcdm_call_manager_step = results->skip_qcdm_call_manager_step;
    *skip_qcdm_hdr_step = results->skip_qcdm_hdr_step;
    *skip_at_cdma_service_status_step = results->skip_at_cdma_service_status_step;
    *skip_at_cdma1x_serving_system_step = results->skip_at_cdma1x_serving_system_step;
    *skip_detailed_registration_state = results->skip_detailed_registration_state;
    return TRUE;
}

static void
speri_check_ready (MMIfaceModemCdma *self,
                   GAsyncResult *res,
                   SetupRegistrationChecksContext *ctx)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error)
        g_error_free (error);
    else
        /* We DO have SPERI */
        ctx->self->priv->has_speri = TRUE;

    /* All done */
    ctx->self->priv->checked_sprint_support = TRUE;
    setup_registration_checks_context_complete_and_free (ctx);
}

static void
spservice_check_ready (MMIfaceModemCdma *self,
                       GAsyncResult *res,
                       SetupRegistrationChecksContext *ctx)
{
    GError *error = NULL;

    mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, &error);
    if (error) {
        g_error_free (error);
        ctx->self->priv->checked_sprint_support = TRUE;
        setup_registration_checks_context_complete_and_free (ctx);
        return;
    }

    /* We DO have SPSERVICE, look for SPERI */
    ctx->has_sprint_commands = TRUE;
    ctx->self->priv->has_spservice = TRUE;
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "$SPERI?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)speri_check_ready,
                              ctx);
}

static void
modem_cdma_setup_registration_checks (MMIfaceModemCdma *self,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    SetupRegistrationChecksContext *ctx;

    ctx = g_new0 (SetupRegistrationChecksContext, 1);
    ctx->self = g_object_ref (self);
    ctx->result = g_simple_async_result_new (G_OBJECT (self),
                                             callback,
                                             user_data,
                                             modem_cdma_setup_registration_checks);

    /* Check if we have a QCDM port */
    ctx->has_qcdm_port = !!mm_base_modem_peek_port_qcdm (MM_BASE_MODEM (self));

    /* If we have cached results of Sprint command checking, use them */
    if (ctx->self->priv->checked_sprint_support) {
        ctx->has_sprint_commands = ctx->self->priv->has_spservice;

        /* Completes in idle */
        setup_registration_checks_context_complete_and_free (ctx);
        return;
    }

    /* Otherwise, launch Sprint command checks. */
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+SPSERVICE?",
                              3,
                              FALSE,
                              (GAsyncReadyCallback)spservice_check_ready,
                              ctx);
}

/*****************************************************************************/
/* Register in network (CDMA interface) */

typedef struct {
    MMBroadbandModem *self;
    GSimpleAsyncResult *result;
    GCancellable *cancellable;
    GTimer *timer;
    guint max_registration_time;
} RegisterInCdmaNetworkContext;

static void
register_in_cdma_network_context_complete_and_free (RegisterInCdmaNetworkContext *ctx)
{
    /* If our cancellable reference is still around, clear it */
    if (ctx->self->priv->modem_cdma_pending_registration_cancellable ==
        ctx->cancellable) {
        g_clear_object (&ctx->self->priv->modem_cdma_pending_registration_cancellable);
    }

    if (ctx->timer)
        g_timer_destroy (ctx->timer);

    g_simple_async_result_complete (ctx->result);
    g_object_unref (ctx->result);
    g_object_unref (ctx->cancellable);
    g_object_unref (ctx->self);
    g_free (ctx);
}

static gboolean
modem_cdma_register_in_network_finish (MMIfaceModemCdma *self,
                                       GAsyncResult *res,
                                       GError **error)
{
    return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
}

#undef REG_IS_IDLE
#define REG_IS_IDLE(state)                              \
    (state == MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN)

#undef REG_IS_DONE
#define REG_IS_DONE(state)                                  \
    (state == MM_MODEM_CDMA_REGISTRATION_STATE_HOME ||      \
     state == MM_MODEM_CDMA_REGISTRATION_STATE_ROAMING ||   \
     state == MM_MODEM_CDMA_REGISTRATION_STATE_REGISTERED)

static void run_cdma_registration_checks_ready (MMBroadbandModem *self,
                                                GAsyncResult *res,
                                                RegisterInCdmaNetworkContext *ctx);

static gboolean
run_cdma_registration_checks_again (RegisterInCdmaNetworkContext *ctx)
{
    /* Get fresh registration state */
    mm_iface_modem_cdma_run_registration_checks (
        MM_IFACE_MODEM_CDMA (ctx->self),
        (GAsyncReadyCallback)run_cdma_registration_checks_ready,
        ctx);
    return G_SOURCE_REMOVE;
}

static void
run_cdma_registration_checks_ready (MMBroadbandModem *self,
                                    GAsyncResult *res,
                                    RegisterInCdmaNetworkContext *ctx)
{
    GError *error = NULL;

    mm_iface_modem_cdma_run_registration_checks_finish (MM_IFACE_MODEM_CDMA (self), res, &error);

    if (error) {
        mm_dbg ("CDMA registration check failed: '%s'", error->message);
        mm_iface_modem_cdma_update_cdma1x_registration_state (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
            MM_MODEM_CDMA_SID_UNKNOWN,
            MM_MODEM_CDMA_NID_UNKNOWN);
        mm_iface_modem_cdma_update_evdo_registration_state (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN);
        mm_iface_modem_cdma_update_access_technologies (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN);

        g_simple_async_result_take_error (ctx->result, error);
        register_in_cdma_network_context_complete_and_free (ctx);
        return;
    }

    /* If we got registered in at least one CDMA network, end registration checks */
    if (REG_IS_DONE (self->priv->modem_cdma_cdma1x_registration_state) ||
        REG_IS_DONE (self->priv->modem_cdma_evdo_registration_state)) {
        mm_dbg ("Modem is currently registered in a CDMA network "
                "(CDMA1x: '%s', EV-DO: '%s')",
                REG_IS_DONE (self->priv->modem_cdma_cdma1x_registration_state) ? "yes" : "no",
                REG_IS_DONE (self->priv->modem_cdma_evdo_registration_state) ? "yes" : "no");
        g_simple_async_result_set_op_res_gboolean (ctx->result, TRUE);
        register_in_cdma_network_context_complete_and_free (ctx);
        return;
    }

    /* Don't spend too much time waiting to get registered */
    if (g_timer_elapsed (ctx->timer, NULL) > ctx->max_registration_time) {
        mm_dbg ("CDMA registration check timed out");
        mm_iface_modem_cdma_update_cdma1x_registration_state (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN,
            MM_MODEM_CDMA_SID_UNKNOWN,
            MM_MODEM_CDMA_NID_UNKNOWN);
        mm_iface_modem_cdma_update_evdo_registration_state (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN);
        mm_iface_modem_cdma_update_access_technologies (
            MM_IFACE_MODEM_CDMA (self),
            MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN);
        g_simple_async_result_take_error (
            ctx->result,
            mm_mobile_equipment_error_for_code (MM_MOBILE_EQUIPMENT_ERROR_NETWORK_TIMEOUT));
        register_in_cdma_network_context_complete_and_free (ctx);
        return;
    }

    /* Check again in a few seconds. */
    mm_dbg ("Modem not yet registered in a CDMA network... will recheck soon");
    g_timeout_add_seconds (3,
                           (GSourceFunc)run_cdma_registration_checks_again,
                           ctx);
}

static void
modem_cdma_register_in_network (MMIfaceModemCdma *self,
                                guint max_registration_time,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
    MMBroadbandModem *broadband = MM_BROADBAND_MODEM (self);
    RegisterInCdmaNetworkContext *ctx;

    /* (Try to) cancel previous registration request */
    if (broadband->priv->modem_cdma_pending_registration_cancellable) {
        g_cancellable_cancel (broadband->priv->modem_cdma_pending_registration_cancellable);
        g_clear_object (&broadband->priv->modem_cdma_pending_registration_cancellable);
    }

    ctx = g_new0 (RegisterInCdmaNetworkContext, 1);
    ctx->self = g_object_ref (self);
    ctx->max_registration_time = max_registration_time;
    ctx->result = g_simple_async_result_new (G_OBJECT (self),
                                             callback,
                                             user_data,
                                             modem_cdma_register_in_network);
    ctx->cancellable = g_cancellable_new ();

    /* Keep an accessible reference to the cancellable, so that we can cancel
     * previous request when needed */
    broadband->priv->modem_cdma_pending_registration_cancellable =
        g_object_ref (ctx->cancellable);

    /* Get fresh registration state */
    ctx->timer = g_timer_new ();
    mm_iface_modem_cdma_run_registration_checks (
        self,
        (GAsyncReadyCallback)run_cdma_registration_checks_ready,
        ctx);
}

/*****************************************************************************/
/* Load location capabilities (Location interface) */

static MMModemLocationSource
modem_location_load_capabilities_finish (MMIfaceModemLocation *self,
                                         GAsyncResult *res,
                                         GError **error)
{
    GError *inner_error = NULL;
    gssize value;

    value = g_task_propagate_int (G_TASK (res), &inner_error);
    if (inner_error) {
        g_propagate_error (error, inner_error);
        return MM_MODEM_LOCATION_SOURCE_NONE;
    }
    return (MMModemLocationSource)value;
}

static void
modem_location_load_capabilities (MMIfaceModemLocation *self,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    /* Default location capabilities supported by the generic broadband
     * implementation are only LAC-CI in 3GPP-enabled modems. And even this,
     * will only be true if the modem supports CREG/CGREG=2 */
    if (!mm_iface_modem_is_3gpp (MM_IFACE_MODEM (self)))
        g_task_return_int (task, MM_MODEM_LOCATION_SOURCE_NONE);
    else
        g_task_return_int (task, MM_MODEM_LOCATION_SOURCE_3GPP_LAC_CI);

    g_object_unref (task);
}

/*****************************************************************************/
/* Enable location gathering (Location interface) */

static gboolean
enable_location_gathering_finish (MMIfaceModemLocation *self,
                                  GAsyncResult *res,
                                  GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
enable_location_gathering (MMIfaceModemLocation *self,
                           MMModemLocationSource source,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
    GTask *task;

    /* 3GPP modems need to re-run registration checks when enabling the 3GPP
     * location source, so that we get up to date LAC/CI location information.
     * Note that we don't care for when the registration checks get finished.
     */
    if (source == MM_MODEM_LOCATION_SOURCE_3GPP_LAC_CI &&
        mm_iface_modem_is_3gpp (MM_IFACE_MODEM (self))) {
        /* Reload registration to get LAC/CI */
        mm_iface_modem_3gpp_run_registration_checks (MM_IFACE_MODEM_3GPP (self), NULL, NULL);
        /* Reload registration information to get MCC/MNC */
        if (MM_BROADBAND_MODEM (self)->priv->modem_3gpp_registration_state == MM_MODEM_3GPP_REGISTRATION_STATE_HOME ||
            MM_BROADBAND_MODEM (self)->priv->modem_3gpp_registration_state == MM_MODEM_3GPP_REGISTRATION_STATE_ROAMING)
            mm_iface_modem_3gpp_reload_current_registration_info (MM_IFACE_MODEM_3GPP (self), NULL, NULL);
    }

    /* Done we are */
    task = g_task_new (self, NULL, callback, user_data);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

/*****************************************************************************/
/* Load network time (Time interface) */

static gchar *
modem_time_load_network_time_finish (MMIfaceModemTime *self,
                                     GAsyncResult *res,
                                     GError **error)
{
    const gchar *response;
    gchar *result = NULL;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!response)
        return NULL;
    if (!mm_parse_cclk_response (response, &result, NULL, error))
        return NULL;
    return result;
}

static void
modem_time_load_network_time (MMIfaceModemTime *self,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CCLK?",
                              3,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Load network timezone (Time interface) */

static MMNetworkTimezone *
modem_time_load_network_timezone_finish (MMIfaceModemTime *self,
                                         GAsyncResult *res,
                                         GError **error)
{
    const gchar *response;
    MMNetworkTimezone *tz = NULL;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!response)
        return NULL;
    if (!mm_parse_cclk_response (response, NULL, &tz, error))
        return NULL;
    return tz;
}

static void
modem_time_load_network_timezone (MMIfaceModemTime *self,
                                  GAsyncReadyCallback callback,
                                  gpointer user_data)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CCLK?",
                              3,
                              FALSE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Check support (Time interface) */

static const MMBaseModemAtCommand time_check_sequence[] = {
    { "+CTZU=1",  3, TRUE, mm_base_modem_response_processor_no_result_continue },
    { "+CCLK?",   3, TRUE, mm_base_modem_response_processor_string },
    { NULL }
};

static gboolean
modem_time_check_support_finish (MMIfaceModemTime *self,
                                 GAsyncResult *res,
                                 GError **error)
{
    return !!mm_base_modem_at_sequence_finish (MM_BASE_MODEM (self), res, NULL, error);
}

static void
modem_time_check_support (MMIfaceModemTime *self,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    mm_base_modem_at_sequence (MM_BASE_MODEM (self),
                               time_check_sequence,
                               NULL, /* response_processor_context */
                               NULL, /* response_processor_context_free */
                               callback,
                               user_data);
}

/*****************************************************************************/
/* Check support (Signal interface) */

static gboolean
modem_signal_check_support_finish (MMIfaceModemSignal  *self,
                                   GAsyncResult        *res,
                                   GError             **error)
{
    return !!mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
}

static void
modem_signal_check_support (MMIfaceModemSignal  *self,
                            GAsyncReadyCallback  callback,
                            gpointer             user_data)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CESQ=?",
                              3,
                              TRUE,
                              callback,
                              user_data);
}

/*****************************************************************************/
/* Load extended signal information (Signal interface) */

static gboolean
modem_signal_load_values_finish (MMIfaceModemSignal  *self,
                                 GAsyncResult        *res,
                                 MMSignal           **cdma,
                                 MMSignal           **evdo,
                                 MMSignal           **gsm,
                                 MMSignal           **umts,
                                 MMSignal           **lte,
                                 GError             **error)
{
    const gchar *response;

    response = mm_base_modem_at_command_finish (MM_BASE_MODEM (self), res, error);
    if (!response || !mm_3gpp_cesq_response_to_signal_info (response, gsm, umts, lte, error))
        return FALSE;

    /* No 3GPP2 support */
    if (cdma)
        *cdma = NULL;
    if (evdo)
        *evdo = NULL;
    return TRUE;
}

static void
modem_signal_load_values (MMIfaceModemSignal  *self,
                          GCancellable        *cancellable,
                          GAsyncReadyCallback  callback,
                          gpointer             user_data)
{
    mm_base_modem_at_command (MM_BASE_MODEM (self),
                              "+CESQ",
                              3,
                              TRUE,
                              callback,
                              user_data);
}

/*****************************************************************************/

static const gchar *primary_init_sequence[] = {
    /* Ensure echo is off */
    "E0",
    /* Get word responses */
    "V1",
    /* Extended numeric codes */
    "+CMEE=1",
    /* Report all call status */
    "X4",
    /* Assert DCD when carrier detected */
    "&C1",
    NULL
};

static const gchar *secondary_init_sequence[] = {
    /* Ensure echo is off */
    "E0",
    NULL
};

static void
setup_ports (MMBroadbandModem *self)
{
    MMPortSerialAt *ports[2];
    GRegex *regex;
    GPtrArray *array;
    gint i, j;

    ports[0] = mm_base_modem_peek_port_primary (MM_BASE_MODEM (self));
    ports[1] = mm_base_modem_peek_port_secondary (MM_BASE_MODEM (self));

    if (ports[0])
        g_object_set (ports[0],
                      MM_PORT_SERIAL_AT_INIT_SEQUENCE, primary_init_sequence,
                      NULL);

    if (ports[1])
        g_object_set (ports[1],
                      MM_PORT_SERIAL_AT_INIT_SEQUENCE, secondary_init_sequence,
                      NULL);

    /* Cleanup all unsolicited message handlers in all AT ports */

    /* Set up CREG unsolicited message handlers, with NULL callbacks */
    array = mm_3gpp_creg_regex_get (FALSE);
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        for (j = 0; j < array->len; j++) {
            mm_port_serial_at_add_unsolicited_msg_handler (MM_PORT_SERIAL_AT (ports[i]),
                                                           (GRegex *)g_ptr_array_index (array, j),
                                                           NULL,
                                                           NULL,
                                                           NULL);
        }
    }
    mm_3gpp_creg_regex_destroy (array);

    /* Set up CIEV unsolicited message handler, with NULL callback */
    regex = mm_3gpp_ciev_regex_get ();
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        mm_port_serial_at_add_unsolicited_msg_handler (MM_PORT_SERIAL_AT (ports[i]),
                                                       regex,
                                                       NULL,
                                                       NULL,
                                                       NULL);
    }
    g_regex_unref (regex);

    /* Set up CMTI unsolicited message handler, with NULL callback */
    regex = mm_3gpp_cmti_regex_get ();
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        mm_port_serial_at_add_unsolicited_msg_handler (MM_PORT_SERIAL_AT (ports[i]),
                                                       regex,
                                                       NULL,
                                                       NULL,
                                                       NULL);
    }
    g_regex_unref (regex);

    /* Set up CUSD unsolicited message handler, with NULL callback */
    regex = mm_3gpp_cusd_regex_get ();
    for (i = 0; i < 2; i++) {
        if (!ports[i])
            continue;

        mm_port_serial_at_add_unsolicited_msg_handler (MM_PORT_SERIAL_AT (ports[i]),
                                                       regex,
                                                       NULL,
                                                       NULL,
                                                       NULL);
    }
    g_regex_unref (regex);
}

/*****************************************************************************/
/* Generic ports open/close context */

struct _PortsContext {
    volatile gint ref_count;

    MMPortSerialAt *primary;
    gboolean primary_open;
    MMPortSerialAt *secondary;
    gboolean secondary_open;
    MMPortSerialQcdm *qcdm;
    gboolean qcdm_open;
};

static PortsContext *
ports_context_ref (PortsContext *ctx)
{
    g_atomic_int_inc (&ctx->ref_count);
    return ctx;
}

static void
ports_context_unref (PortsContext *ctx)
{
    if (g_atomic_int_dec_and_test (&ctx->ref_count)) {
        if (ctx->primary) {
            if (ctx->primary_open)
                mm_port_serial_close (MM_PORT_SERIAL (ctx->primary));
            g_object_unref (ctx->primary);
        }
        if (ctx->secondary) {
            if (ctx->secondary_open)
                mm_port_serial_close (MM_PORT_SERIAL (ctx->secondary));
            g_object_unref (ctx->secondary);
        }
        if (ctx->qcdm) {
            if (ctx->qcdm_open)
                mm_port_serial_close (MM_PORT_SERIAL (ctx->qcdm));
            g_object_unref (ctx->qcdm);
        }
        g_free (ctx);
    }
}

/*****************************************************************************/
/* Initialization started/stopped */

static gboolean
initialization_stopped (MMBroadbandModem *self,
                        gpointer user_data,
                        GError **error)
{
    PortsContext *ctx = (PortsContext *)user_data;

    if (ctx)
        ports_context_unref (ctx);
    return TRUE;
}

static gpointer
initialization_started_finish (MMBroadbandModem *self,
                               GAsyncResult *res,
                               GError **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static gboolean
open_ports_initialization (MMBroadbandModem *self,
                           PortsContext *ctx,
                           GError **error)
{
    ctx->primary = mm_base_modem_get_port_primary (MM_BASE_MODEM (self));
    if (!ctx->primary) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Couldn't get primary port");
        return FALSE;
    }

    /* Open and send first commands to the primary serial port.
     * We do keep the primary port open during the whole initialization
     * sequence. Note that this port is not really passed to the interfaces,
     * they will get the primary port themselves. */
    if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->primary), error)) {
        g_prefix_error (error, "Couldn't open primary port: ");
        return FALSE;
    }

    ctx->primary_open = TRUE;

    /* Try to disable echo */
    mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                   ctx->primary,
                                   "E0", 3,
                                   FALSE, FALSE, NULL, NULL, NULL);
    /* Try to get extended errors */
    mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                   ctx->primary,
                                   "+CMEE=1", 3,
                                   FALSE, FALSE, NULL, NULL, NULL);

    return TRUE;
}

static void
initialization_started (MMBroadbandModem *self,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    GError *error = NULL;
    GTask *task;
    PortsContext *ctx;

    task = g_task_new (self, NULL, callback, user_data);

    ctx = g_new0 (PortsContext, 1);
    ctx->ref_count = 1;

    if (!open_ports_initialization (self, ctx, &error)) {
        ports_context_unref (ctx);
        g_prefix_error (&error, "Couldn't open ports during modem initialization: ");
        g_task_return_error (task, error);
    } else
        g_task_return_pointer (task, ctx, (GDestroyNotify)ports_context_unref);
    g_object_unref (task);
}

/*****************************************************************************/
/* Disabling stopped */

static gboolean
disabling_stopped (MMBroadbandModem *self,
                   GError **error)
{
    if (self->priv->enabled_ports_ctx) {
        ports_context_unref (self->priv->enabled_ports_ctx);
        self->priv->enabled_ports_ctx = NULL;
    }

    return TRUE;
}

/*****************************************************************************/
/* Initializing the modem (during first enabling) */

static gboolean
enabling_modem_init_finish (MMBroadbandModem *self,
                            GAsyncResult *res,
                            GError **error)
{
    return !!mm_base_modem_at_command_full_finish (MM_BASE_MODEM (self), res, error);
}

static void
enabling_modem_init (MMBroadbandModem *self,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
    /* Init command. ITU rec v.250 (6.1.1) says:
     *   The DTE should not include additional commands on the same command line
     *   after the Z command because such commands may be ignored.
     * So run ATZ alone.
     */
    mm_base_modem_at_command_full (MM_BASE_MODEM (self),
                                   mm_base_modem_peek_port_primary (MM_BASE_MODEM (self)),
                                   "Z",
                                   6,
                                   FALSE,
                                   FALSE,
                                   NULL, /* cancellable */
                                   callback,
                                   user_data);
}

/*****************************************************************************/
/* Enabling started */

typedef struct {
    PortsContext *ports;
    gboolean modem_init_required;
} EnablingStartedContext;

static void
enabling_started_context_free (EnablingStartedContext *ctx)
{
    ports_context_unref (ctx->ports);
    g_slice_free (EnablingStartedContext, ctx);
}

static gboolean
enabling_started_finish (MMBroadbandModem *self,
                         GAsyncResult *res,
                         GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static gboolean
enabling_after_modem_init_timeout (GTask *task)
{
    MMBroadbandModem *self;
    EnablingStartedContext *ctx;

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    /* Reset init sequence enabled flags and run them explicitly */
    g_object_set (ctx->ports->primary,
                  MM_PORT_SERIAL_AT_INIT_SEQUENCE_ENABLED, TRUE,
                  NULL);
    mm_port_serial_at_run_init_sequence (ctx->ports->primary);
    if (ctx->ports->secondary) {
        g_object_set (ctx->ports->secondary,
                      MM_PORT_SERIAL_AT_INIT_SEQUENCE_ENABLED, TRUE,
                      NULL);
        mm_port_serial_at_run_init_sequence (ctx->ports->secondary);
    }

    /* Store enabled ports context and complete */
    self->priv->enabled_ports_ctx = ports_context_ref (ctx->ports);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
    return G_SOURCE_REMOVE;
}

static void
enabling_modem_init_ready (MMBroadbandModem *self,
                           GAsyncResult *res,
                           GTask *task)
{
    GError *error = NULL;

    if (!MM_BROADBAND_MODEM_GET_CLASS (self)->enabling_modem_init_finish (self, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Specify that the modem init was run once */
    self->priv->modem_init_run = TRUE;

    /* After the modem init sequence, give a 500ms period for the modem to settle */
    mm_dbg ("Giving some time to settle the modem...");
    g_timeout_add (500, (GSourceFunc)enabling_after_modem_init_timeout, task);
}

static void
enabling_flash_done (MMPortSerial *port,
                     GAsyncResult *res,
                     GTask *task)
{
    MMBroadbandModem *self;
    EnablingStartedContext *ctx;
    GError *error = NULL;

    if (!mm_port_serial_flash_finish (port, res, &error)) {
        g_prefix_error (&error, "Primary port flashing failed: ");
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    self = g_task_get_source_object (task);
    ctx = g_task_get_task_data (task);

    if (ctx->modem_init_required) {
        mm_dbg ("Running modem initialization sequence...");
        MM_BROADBAND_MODEM_GET_CLASS (self)->enabling_modem_init (self,
                                                                  (GAsyncReadyCallback)enabling_modem_init_ready,
                                                                  task);
        return;
    }

    /* Store enabled ports context and complete */
    self->priv->enabled_ports_ctx = ports_context_ref (ctx->ports);
    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static gboolean
open_ports_enabling (MMBroadbandModem *self,
                     PortsContext *ctx,
                     gboolean modem_init_required,
                     GError **error)
{
    /* Open primary */
    ctx->primary = mm_base_modem_get_port_primary (MM_BASE_MODEM (self));
    if (!ctx->primary) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "Couldn't get primary port");
        return FALSE;
    }

    /* If we'll need to run modem initialization, disable port init sequence */
    if (modem_init_required)
        g_object_set (ctx->primary,
                      MM_PORT_SERIAL_AT_INIT_SEQUENCE_ENABLED, FALSE,
                      NULL);


    if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->primary), error)) {
        g_prefix_error (error, "Couldn't open primary port: ");
        return FALSE;
    }

    ctx->primary_open = TRUE;

    /* Open secondary (optional) */
    ctx->secondary = mm_base_modem_get_port_secondary (MM_BASE_MODEM (self));
    if (ctx->secondary) {
        /* If we'll need to run modem initialization, disable port init sequence */
        if (modem_init_required)
            g_object_set (ctx->secondary,
                          MM_PORT_SERIAL_AT_INIT_SEQUENCE_ENABLED, FALSE,
                          NULL);
        if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->secondary), error)) {
            g_prefix_error (error, "Couldn't open secondary port: ");
            return FALSE;
        }
        ctx->secondary_open = TRUE;
    }

    /* Open qcdm (optional) */
    ctx->qcdm = mm_base_modem_get_port_qcdm (MM_BASE_MODEM (self));
    if (ctx->qcdm) {
        if (!mm_port_serial_open (MM_PORT_SERIAL (ctx->qcdm), error)) {
            g_prefix_error (error, "Couldn't open QCDM port: ");
            return FALSE;
        }
        ctx->qcdm_open = TRUE;
    }

    return TRUE;
}

static void
enabling_started (MMBroadbandModem *self,
                  GAsyncReadyCallback callback,
                  gpointer user_data)
{
    GError *error = NULL;
    EnablingStartedContext *ctx;
    GTask *task;

    ctx = g_slice_new0 (EnablingStartedContext);
    ctx->ports = g_new0 (PortsContext, 1);
    ctx->ports->ref_count = 1;

    /* Skip modem initialization if the device was hotplugged OR if we already
     * did it (i.e. don't reinitialize if the modem got disabled and enabled
     * again) */
    if (self->priv->modem_init_run)
        mm_dbg ("Skipping modem initialization: not first enabling");
    else if (mm_base_modem_get_hotplugged (MM_BASE_MODEM (self))) {
        self->priv->modem_init_run = TRUE;
        mm_dbg ("Skipping modem initialization: device hotplugged");
    } else if (!MM_BROADBAND_MODEM_GET_CLASS (self)->enabling_modem_init ||
               !MM_BROADBAND_MODEM_GET_CLASS (self)->enabling_modem_init_finish)
        mm_dbg ("Skipping modem initialization: not required");
    else
        ctx->modem_init_required = TRUE;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)enabling_started_context_free);

    /* Enabling */
    if (!open_ports_enabling (self, ctx->ports, ctx->modem_init_required, &error)) {
        g_prefix_error (&error, "Couldn't open ports during modem enabling: ");
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Ports were correctly opened, now flash the primary port */
    mm_dbg ("Flashing primary AT port before enabling...");
    mm_port_serial_flash (MM_PORT_SERIAL (ctx->ports->primary),
                          100,
                          FALSE,
                          (GAsyncReadyCallback)enabling_flash_done,
                          task);
}

/*****************************************************************************/
/* First registration checks */

static void
modem_3gpp_run_registration_checks_ready (MMIfaceModem3gpp *self,
                                          GAsyncResult *res)
{
    GError *error = NULL;

    if (!mm_iface_modem_3gpp_run_registration_checks_finish (self, res, &error)) {
        mm_warn ("Initial 3GPP registration check failed: %s", error->message);
        g_error_free (error);
        return;
    }
    mm_dbg ("Initial 3GPP registration checks finished");
}

static void
modem_cdma_run_registration_checks_ready (MMIfaceModemCdma *self,
                                          GAsyncResult *res)
{
    GError *error = NULL;

    if (!mm_iface_modem_cdma_run_registration_checks_finish (self, res, &error)) {
        mm_warn ("Initial CDMA registration check failed: %s", error->message);
        g_error_free (error);
        return;
    }
    mm_dbg ("Initial CDMA registration checks finished");
}

static gboolean
schedule_initial_registration_checks_cb (MMBroadbandModem *self)
{
    if (mm_iface_modem_is_3gpp (MM_IFACE_MODEM (self)))
        mm_iface_modem_3gpp_run_registration_checks (MM_IFACE_MODEM_3GPP (self),
                                                     (GAsyncReadyCallback) modem_3gpp_run_registration_checks_ready,
                                                     NULL);
    if (mm_iface_modem_is_cdma (MM_IFACE_MODEM (self)))
        mm_iface_modem_cdma_run_registration_checks (MM_IFACE_MODEM_CDMA (self),
                                                     (GAsyncReadyCallback) modem_cdma_run_registration_checks_ready,
                                                     NULL);
    /* We got a full reference, so balance it out here */
    g_object_unref (self);
    return G_SOURCE_REMOVE;
}

static void
schedule_initial_registration_checks (MMBroadbandModem *self)
{
    g_idle_add ((GSourceFunc) schedule_initial_registration_checks_cb, g_object_ref (self));
}

/*****************************************************************************/

typedef enum {
    DISABLING_STEP_FIRST,
    DISABLING_STEP_WAIT_FOR_FINAL_STATE,
    DISABLING_STEP_DISCONNECT_BEARERS,
    DISABLING_STEP_IFACE_SIMPLE,
    DISABLING_STEP_IFACE_FIRMWARE,
    DISABLING_STEP_IFACE_SIGNAL,
    DISABLING_STEP_IFACE_OMA,
    DISABLING_STEP_IFACE_TIME,
    DISABLING_STEP_IFACE_MESSAGING,
    DISABLING_STEP_IFACE_VOICE,
    DISABLING_STEP_IFACE_LOCATION,
    DISABLING_STEP_IFACE_CONTACTS,
    DISABLING_STEP_IFACE_CDMA,
    DISABLING_STEP_IFACE_3GPP_USSD,
    DISABLING_STEP_IFACE_3GPP,
    DISABLING_STEP_IFACE_MODEM,
    DISABLING_STEP_LAST,
} DisablingStep;

typedef struct {
    MMBroadbandModem *self;
    DisablingStep step;
    MMModemState previous_state;
    gboolean disabled;
} DisablingContext;

static void disabling_step (GTask *task);

static void
disabling_context_free (DisablingContext *ctx)
{
    GError *error = NULL;

    if (MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->disabling_stopped &&
        !MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->disabling_stopped (ctx->self, &error)) {
        mm_warn ("Error when stopping the disabling sequence: %s", error->message);
        g_error_free (error);
    }

    if (ctx->disabled)
        mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                     MM_MODEM_STATE_DISABLED,
                                     MM_MODEM_STATE_CHANGE_REASON_USER_REQUESTED);
    else if (ctx->previous_state != MM_MODEM_STATE_DISABLED) {
        /* Fallback to previous state */
        mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                     ctx->previous_state,
                                     MM_MODEM_STATE_CHANGE_REASON_UNKNOWN);
    }

    g_object_unref (ctx->self);
    g_free (ctx);
}

static gboolean
disable_finish (MMBaseModem *self,
               GAsyncResult *res,
               GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

#undef INTERFACE_DISABLE_READY_FN
#define INTERFACE_DISABLE_READY_FN(NAME,TYPE,FATAL_ERRORS)              \
    static void                                                         \
    NAME##_disable_ready (MMBroadbandModem *self,                       \
                          GAsyncResult *result,                         \
                          GTask *task)                                  \
    {                                                                   \
        DisablingContext *ctx;                                          \
        GError *error = NULL;                                           \
                                                                        \
        if (!mm_##NAME##_disable_finish (TYPE (self),                   \
                                         result,                        \
                                         &error)) {                     \
            if (FATAL_ERRORS) {                                         \
                g_task_return_error (task, error);                      \
                g_object_unref (task);                                  \
                return;                                                 \
            }                                                           \
                                                                        \
            mm_dbg ("Couldn't disable interface: '%s'",                 \
                    error->message);                                    \
            g_error_free (error);                                       \
            return;                                                     \
        }                                                               \
                                                                        \
        /* Go on to next step */                                        \
        ctx = g_task_get_task_data (task);                              \
        ctx->step++;                                                    \
        disabling_step (task);                                          \
    }

INTERFACE_DISABLE_READY_FN (iface_modem,           MM_IFACE_MODEM,           TRUE)
INTERFACE_DISABLE_READY_FN (iface_modem_3gpp,      MM_IFACE_MODEM_3GPP,      TRUE)
INTERFACE_DISABLE_READY_FN (iface_modem_3gpp_ussd, MM_IFACE_MODEM_3GPP_USSD, TRUE)
INTERFACE_DISABLE_READY_FN (iface_modem_cdma,      MM_IFACE_MODEM_CDMA,      TRUE)
INTERFACE_DISABLE_READY_FN (iface_modem_location,  MM_IFACE_MODEM_LOCATION,  FALSE)
INTERFACE_DISABLE_READY_FN (iface_modem_messaging, MM_IFACE_MODEM_MESSAGING, FALSE)
INTERFACE_DISABLE_READY_FN (iface_modem_voice,     MM_IFACE_MODEM_VOICE,     FALSE)
INTERFACE_DISABLE_READY_FN (iface_modem_signal,    MM_IFACE_MODEM_SIGNAL,    FALSE)
INTERFACE_DISABLE_READY_FN (iface_modem_time,      MM_IFACE_MODEM_TIME,      FALSE)
INTERFACE_DISABLE_READY_FN (iface_modem_oma,       MM_IFACE_MODEM_OMA,       FALSE)

static void
bearer_list_disconnect_all_bearers_ready (MMBearerList *list,
                                          GAsyncResult *res,
                                          GTask *task)
{
    DisablingContext *ctx;
    GError *error = NULL;

    if (!mm_bearer_list_disconnect_all_bearers_finish (list, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Go on to next step */
    ctx = g_task_get_task_data (task);
    ctx->step++;
    disabling_step (task);
}

static void
disabling_wait_for_final_state_ready (MMIfaceModem *self,
                                      GAsyncResult *res,
                                      GTask *task)
{
    DisablingContext *ctx;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    ctx->previous_state = mm_iface_modem_wait_for_final_state_finish (self, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    switch (ctx->previous_state) {
    case MM_MODEM_STATE_UNKNOWN:
    case MM_MODEM_STATE_FAILED:
    case MM_MODEM_STATE_LOCKED:
    case MM_MODEM_STATE_DISABLED:
        /* Just return success, don't relaunch disabling.
         * Note that we do consider here UNKNOWN and FAILED status on purpose,
         * as the MMManager will try to disable every modem before removing
         * it. */
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    default:
        break;
    }

    /* We're in a final state now, go on */

    mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                 MM_MODEM_STATE_DISABLING,
                                 MM_MODEM_STATE_CHANGE_REASON_USER_REQUESTED);

    ctx->step++;
    disabling_step (task);
}

static void
disabling_step (GTask *task)
{
    DisablingContext *ctx;

    /* Don't run new steps if we're cancelled */
    if (g_task_return_error_if_cancelled (task)) {
        g_object_unref (task);
        return;
    }
    ctx = g_task_get_task_data (task);

    switch (ctx->step) {
    case DISABLING_STEP_FIRST:
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_WAIT_FOR_FINAL_STATE:
        mm_iface_modem_wait_for_final_state (MM_IFACE_MODEM (ctx->self),
                                             MM_MODEM_STATE_UNKNOWN, /* just any */
                                             (GAsyncReadyCallback)disabling_wait_for_final_state_ready,
                                             task);
        return;

    case DISABLING_STEP_DISCONNECT_BEARERS:
        if (ctx->self->priv->modem_bearer_list) {
            mm_bearer_list_disconnect_all_bearers (
                ctx->self->priv->modem_bearer_list,
                (GAsyncReadyCallback)bearer_list_disconnect_all_bearers_ready,
                task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_SIMPLE:
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_FIRMWARE:
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_SIGNAL:
        if (ctx->self->priv->modem_signal_dbus_skeleton) {
            mm_dbg ("Modem has extended signal reporting capabilities, disabling the Signal interface...");
            /* Disabling the Modem Signal interface */
            mm_iface_modem_signal_disable (MM_IFACE_MODEM_SIGNAL (ctx->self),
                                           (GAsyncReadyCallback)iface_modem_signal_disable_ready,
                                           task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_OMA:
        if (ctx->self->priv->modem_oma_dbus_skeleton) {
            mm_dbg ("Modem has OMA capabilities, disabling the OMA interface...");
            /* Disabling the Modem Oma interface */
            mm_iface_modem_oma_disable (MM_IFACE_MODEM_OMA (ctx->self),
                                        (GAsyncReadyCallback)iface_modem_oma_disable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_TIME:
        if (ctx->self->priv->modem_time_dbus_skeleton) {
            mm_dbg ("Modem has time capabilities, disabling the Time interface...");
            /* Disabling the Modem Time interface */
            mm_iface_modem_time_disable (MM_IFACE_MODEM_TIME (ctx->self),
                                         (GAsyncReadyCallback)iface_modem_time_disable_ready,
                                         task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_MESSAGING:
        if (ctx->self->priv->modem_messaging_dbus_skeleton) {
            mm_dbg ("Modem has messaging capabilities, disabling the Messaging interface...");
            /* Disabling the Modem Messaging interface */
            mm_iface_modem_messaging_disable (MM_IFACE_MODEM_MESSAGING (ctx->self),
                                              (GAsyncReadyCallback)iface_modem_messaging_disable_ready,
                                              task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_VOICE:
        if (ctx->self->priv->modem_voice_dbus_skeleton) {
            mm_dbg ("Modem has voice capabilities, disabling the Voice interface...");
            /* Disabling the Modem Voice interface */
            mm_iface_modem_voice_disable (MM_IFACE_MODEM_VOICE (ctx->self),
                                          (GAsyncReadyCallback)iface_modem_voice_disable_ready,
                                          task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_LOCATION:
        if (ctx->self->priv->modem_location_dbus_skeleton) {
            mm_dbg ("Modem has location capabilities, disabling the Location interface...");
            /* Disabling the Modem Location interface */
            mm_iface_modem_location_disable (MM_IFACE_MODEM_LOCATION (ctx->self),
                                             (GAsyncReadyCallback)iface_modem_location_disable_ready,
                                             task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_CONTACTS:
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_CDMA:
        if (ctx->self->priv->modem_cdma_dbus_skeleton) {
            mm_dbg ("Modem has CDMA capabilities, disabling the Modem CDMA interface...");
            /* Disabling the Modem CDMA interface */
            mm_iface_modem_cdma_disable (MM_IFACE_MODEM_CDMA (ctx->self),
                                        (GAsyncReadyCallback)iface_modem_cdma_disable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_3GPP_USSD:
        if (ctx->self->priv->modem_3gpp_ussd_dbus_skeleton) {
            mm_dbg ("Modem has 3GPP/USSD capabilities, disabling the Modem 3GPP/USSD interface...");
            /* Disabling the Modem 3GPP USSD interface */
            mm_iface_modem_3gpp_ussd_disable (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                              (GAsyncReadyCallback)iface_modem_3gpp_ussd_disable_ready,
                                              task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_3GPP:
        if (ctx->self->priv->modem_3gpp_dbus_skeleton) {
            mm_dbg ("Modem has 3GPP capabilities, disabling the Modem 3GPP interface...");
            /* Disabling the Modem 3GPP interface */
            mm_iface_modem_3gpp_disable (MM_IFACE_MODEM_3GPP (ctx->self),
                                        (GAsyncReadyCallback)iface_modem_3gpp_disable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_IFACE_MODEM:
        /* This skeleton may be NULL when mm_base_modem_disable() gets called at
         * the same time as modem object disposal. */
        if (ctx->self->priv->modem_dbus_skeleton) {
            /* Disabling the Modem interface */
            mm_iface_modem_disable (MM_IFACE_MODEM (ctx->self),
                                    (GAsyncReadyCallback)iface_modem_disable_ready,
                                    task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case DISABLING_STEP_LAST:
        ctx->disabled = TRUE;
        /* All disabled without errors! */
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    g_assert_not_reached ();
}

static void
disable (MMBaseModem *self,
         GCancellable *cancellable,
         GAsyncReadyCallback callback,
         gpointer user_data)
{
    DisablingContext *ctx;
    GTask *task;

    ctx = g_new0 (DisablingContext, 1);
    ctx->self = g_object_ref (self);
    ctx->step = DISABLING_STEP_FIRST;

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)disabling_context_free);

    disabling_step (task);
}

/*****************************************************************************/

typedef enum {
    ENABLING_STEP_FIRST,
    ENABLING_STEP_WAIT_FOR_FINAL_STATE,
    ENABLING_STEP_STARTED,
    ENABLING_STEP_IFACE_MODEM,
    ENABLING_STEP_IFACE_3GPP,
    ENABLING_STEP_IFACE_3GPP_USSD,
    ENABLING_STEP_IFACE_CDMA,
    ENABLING_STEP_IFACE_CONTACTS,
    ENABLING_STEP_IFACE_LOCATION,
    ENABLING_STEP_IFACE_MESSAGING,
    ENABLING_STEP_IFACE_VOICE,
    ENABLING_STEP_IFACE_TIME,
    ENABLING_STEP_IFACE_SIGNAL,
    ENABLING_STEP_IFACE_OMA,
    ENABLING_STEP_IFACE_FIRMWARE,
    ENABLING_STEP_IFACE_SIMPLE,
    ENABLING_STEP_LAST,
} EnablingStep;

typedef struct {
    MMBroadbandModem *self;
    EnablingStep step;
    MMModemState previous_state;
    gboolean enabled;
} EnablingContext;

static void enabling_step (GTask *task);

static void
enabling_context_free (EnablingContext *ctx)
{
    if (ctx->enabled)
        mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                     MM_MODEM_STATE_ENABLED,
                                     MM_MODEM_STATE_CHANGE_REASON_USER_REQUESTED);
    else if (ctx->previous_state != MM_MODEM_STATE_ENABLED) {
        /* Fallback to previous state */
        mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                     ctx->previous_state,
                                     MM_MODEM_STATE_CHANGE_REASON_UNKNOWN);
    }

    g_object_unref (ctx->self);
    g_free (ctx);
}

static gboolean
enable_finish (MMBaseModem *self,
               GAsyncResult *res,
               GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

#undef INTERFACE_ENABLE_READY_FN
#define INTERFACE_ENABLE_READY_FN(NAME,TYPE,FATAL_ERRORS)               \
    static void                                                         \
    NAME##_enable_ready (MMBroadbandModem *self,                        \
                         GAsyncResult *result,                          \
                         GTask *task)                                   \
    {                                                                   \
        EnablingContext *ctx;                                           \
        GError *error = NULL;                                           \
                                                                        \
        if (!mm_##NAME##_enable_finish (TYPE (self),                    \
                                        result,                         \
                                        &error)) {                      \
            if (FATAL_ERRORS) {                                         \
                g_task_return_error (task, error);                      \
                g_object_unref (task);                                  \
                return;                                                 \
            }                                                           \
                                                                        \
            mm_dbg ("Couldn't enable interface: '%s'",                  \
                    error->message);                                    \
            g_error_free (error);                                       \
        }                                                               \
                                                                        \
        /* Go on to next step */                                        \
        ctx = g_task_get_task_data (task);                              \
        ctx->step++;                                                    \
        enabling_step (task);                                           \
    }

INTERFACE_ENABLE_READY_FN (iface_modem,           MM_IFACE_MODEM,           TRUE)
INTERFACE_ENABLE_READY_FN (iface_modem_3gpp,      MM_IFACE_MODEM_3GPP,      TRUE)
INTERFACE_ENABLE_READY_FN (iface_modem_3gpp_ussd, MM_IFACE_MODEM_3GPP_USSD, TRUE)
INTERFACE_ENABLE_READY_FN (iface_modem_cdma,      MM_IFACE_MODEM_CDMA,      TRUE)
INTERFACE_ENABLE_READY_FN (iface_modem_location,  MM_IFACE_MODEM_LOCATION,  FALSE)
INTERFACE_ENABLE_READY_FN (iface_modem_messaging, MM_IFACE_MODEM_MESSAGING, FALSE)
INTERFACE_ENABLE_READY_FN (iface_modem_voice,     MM_IFACE_MODEM_VOICE,     FALSE)
INTERFACE_ENABLE_READY_FN (iface_modem_signal,    MM_IFACE_MODEM_SIGNAL,    FALSE)
INTERFACE_ENABLE_READY_FN (iface_modem_time,      MM_IFACE_MODEM_TIME,      FALSE)
INTERFACE_ENABLE_READY_FN (iface_modem_oma,       MM_IFACE_MODEM_OMA,       FALSE)

static void
enabling_started_ready (MMBroadbandModem *self,
                        GAsyncResult *result,
                        GTask *task)
{
    EnablingContext *ctx;
    GError *error = NULL;

    if (!MM_BROADBAND_MODEM_GET_CLASS (self)->enabling_started_finish (self, result, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* Go on to next step */
    ctx = g_task_get_task_data (task);
    ctx->step++;
    enabling_step (task);
}

static void
enabling_wait_for_final_state_ready (MMIfaceModem *self,
                                     GAsyncResult *res,
                                     GTask *task)
{
    EnablingContext *ctx;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    ctx->previous_state = mm_iface_modem_wait_for_final_state_finish (self, res, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    if (ctx->previous_state >= MM_MODEM_STATE_ENABLED) {
        /* Just return success, don't relaunch enabling */
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    /* We're in a final state now, go on */

    mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                 MM_MODEM_STATE_ENABLING,
                                 MM_MODEM_STATE_CHANGE_REASON_USER_REQUESTED);

    ctx->step++;
    enabling_step (task);
}

static void
enabling_step (GTask *task)
{
    EnablingContext *ctx;

    /* Don't run new steps if we're cancelled */
    if (g_task_return_error_if_cancelled (task)) {
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    switch (ctx->step) {
    case ENABLING_STEP_FIRST:
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_WAIT_FOR_FINAL_STATE:
        mm_iface_modem_wait_for_final_state (MM_IFACE_MODEM (ctx->self),
                                             MM_MODEM_STATE_UNKNOWN, /* just any */
                                             (GAsyncReadyCallback)enabling_wait_for_final_state_ready,
                                             task);
        return;

    case ENABLING_STEP_STARTED:
        if (MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->enabling_started &&
            MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->enabling_started_finish) {
            MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->enabling_started (ctx->self,
                                                                        (GAsyncReadyCallback)enabling_started_ready,
                                                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_MODEM:
        g_assert (ctx->self->priv->modem_dbus_skeleton != NULL);
        /* Enabling the Modem interface */
        mm_iface_modem_enable (MM_IFACE_MODEM (ctx->self),
                               g_task_get_cancellable (task),
                               (GAsyncReadyCallback)iface_modem_enable_ready,
                               task);
        return;

    case ENABLING_STEP_IFACE_3GPP:
        if (ctx->self->priv->modem_3gpp_dbus_skeleton) {
            mm_dbg ("Modem has 3GPP capabilities, enabling the Modem 3GPP interface...");
            /* Enabling the Modem 3GPP interface */
            mm_iface_modem_3gpp_enable (MM_IFACE_MODEM_3GPP (ctx->self),
                                        g_task_get_cancellable (task),
                                        (GAsyncReadyCallback)iface_modem_3gpp_enable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_3GPP_USSD:
        if (ctx->self->priv->modem_3gpp_ussd_dbus_skeleton) {
            mm_dbg ("Modem has 3GPP/USSD capabilities, enabling the Modem 3GPP/USSD interface...");
            mm_iface_modem_3gpp_ussd_enable (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                             (GAsyncReadyCallback)iface_modem_3gpp_ussd_enable_ready,
                                             task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_CDMA:
        if (ctx->self->priv->modem_cdma_dbus_skeleton) {
            mm_dbg ("Modem has CDMA capabilities, enabling the Modem CDMA interface...");
            /* Enabling the Modem CDMA interface */
            mm_iface_modem_cdma_enable (MM_IFACE_MODEM_CDMA (ctx->self),
                                        g_task_get_cancellable (task),
                                        (GAsyncReadyCallback)iface_modem_cdma_enable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_CONTACTS:
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_LOCATION:
        if (ctx->self->priv->modem_location_dbus_skeleton) {
            mm_dbg ("Modem has location capabilities, enabling the Location interface...");
            /* Enabling the Modem Location interface */
            mm_iface_modem_location_enable (MM_IFACE_MODEM_LOCATION (ctx->self),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)iface_modem_location_enable_ready,
                                            task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_MESSAGING:
        if (ctx->self->priv->modem_messaging_dbus_skeleton) {
            mm_dbg ("Modem has messaging capabilities, enabling the Messaging interface...");
            /* Enabling the Modem Messaging interface */
            mm_iface_modem_messaging_enable (MM_IFACE_MODEM_MESSAGING (ctx->self),
                                             g_task_get_cancellable (task),
                                             (GAsyncReadyCallback)iface_modem_messaging_enable_ready,
                                             task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_VOICE:
        if (ctx->self->priv->modem_voice_dbus_skeleton) {
            mm_dbg ("Modem has voice capabilities, enabling the Voice interface...");
            /* Enabling the Modem Voice interface */
            mm_iface_modem_voice_enable (MM_IFACE_MODEM_VOICE (ctx->self),
                                         g_task_get_cancellable (task),
                                         (GAsyncReadyCallback)iface_modem_voice_enable_ready,
                                         task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_TIME:
        if (ctx->self->priv->modem_time_dbus_skeleton) {
            mm_dbg ("Modem has time capabilities, enabling the Time interface...");
            /* Enabling the Modem Time interface */
            mm_iface_modem_time_enable (MM_IFACE_MODEM_TIME (ctx->self),
                                        g_task_get_cancellable (task),
                                        (GAsyncReadyCallback)iface_modem_time_enable_ready,
                                        task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_SIGNAL:
        if (ctx->self->priv->modem_signal_dbus_skeleton) {
            mm_dbg ("Modem has extended signal reporting capabilities, enabling the Signal interface...");
            /* Enabling the Modem Signal interface */
            mm_iface_modem_signal_enable (MM_IFACE_MODEM_SIGNAL (ctx->self),
                                          g_task_get_cancellable (task),
                                          (GAsyncReadyCallback)iface_modem_signal_enable_ready,
                                          task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_OMA:
        if (ctx->self->priv->modem_oma_dbus_skeleton) {
            mm_dbg ("Modem has OMA capabilities, enabling the OMA interface...");
            /* Enabling the Modem Oma interface */
            mm_iface_modem_oma_enable (MM_IFACE_MODEM_OMA (ctx->self),
                                       g_task_get_cancellable (task),
                                       (GAsyncReadyCallback)iface_modem_oma_enable_ready,
                                       task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_FIRMWARE:
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_IFACE_SIMPLE:
        /* Fall down to next step */
        ctx->step++;

    case ENABLING_STEP_LAST:
        ctx->enabled = TRUE;

        /* Once all interfaces have been enabled, trigger registration checks in
         * 3GPP and CDMA modems. We have to do this at this point so that e.g.
         * location interface gets proper registration related info reported.
         *
         * We do this in an idle so that we don't mess up the logs at this point
         * with the new requests being triggered.
         */
        schedule_initial_registration_checks (ctx->self);

        /* All enabled without errors! */
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    g_assert_not_reached ();
}

static void
enable (MMBaseModem *self,
        GCancellable *cancellable,
        GAsyncReadyCallback callback,
        gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, cancellable, callback, user_data);

    /* Check state before launching modem enabling */
    switch (MM_BROADBAND_MODEM (self)->priv->modem_state) {
    case MM_MODEM_STATE_UNKNOWN:
        /* We should never have a UNKNOWN->ENABLED transition */
        g_assert_not_reached ();
        break;

    case MM_MODEM_STATE_FAILED:
    case MM_MODEM_STATE_INITIALIZING:
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_WRONG_STATE,
                                 "Cannot enable modem: "
                                 "device not fully initialized yet");
        break;

    case MM_MODEM_STATE_LOCKED:
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_WRONG_STATE,
                                 "Cannot enable modem: device locked");
        break;

    case MM_MODEM_STATE_DISABLED: {
        EnablingContext *ctx;

        ctx = g_new0 (EnablingContext, 1);
        ctx->self = g_object_ref (self);
        ctx->step = ENABLING_STEP_FIRST;

        g_task_set_task_data (task, ctx, (GDestroyNotify)enabling_context_free);

        enabling_step (task);
        return;
    }

    case MM_MODEM_STATE_DISABLING:
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_WRONG_STATE,
                                 "Cannot enable modem: "
                                 "currently being disabled");
        break;

    case MM_MODEM_STATE_ENABLING:
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_IN_PROGRESS,
                                 "Cannot enable modem: "
                                 "already being enabled");
        break;

    case MM_MODEM_STATE_ENABLED:
    case MM_MODEM_STATE_SEARCHING:
    case MM_MODEM_STATE_REGISTERED:
    case MM_MODEM_STATE_DISCONNECTING:
    case MM_MODEM_STATE_CONNECTING:
    case MM_MODEM_STATE_CONNECTED:
        /* Just return success, don't relaunch enabling */
        g_task_return_boolean (task, TRUE);
        break;
    }

    g_object_unref (task);
}

/*****************************************************************************/

typedef enum {
    INITIALIZE_STEP_FIRST,
    INITIALIZE_STEP_SETUP_PORTS,
    INITIALIZE_STEP_STARTED,
    INITIALIZE_STEP_SETUP_SIMPLE_STATUS,
    INITIALIZE_STEP_IFACE_MODEM,
    INITIALIZE_STEP_IFACE_3GPP,
    INITIALIZE_STEP_IFACE_3GPP_USSD,
    INITIALIZE_STEP_IFACE_CDMA,
    INITIALIZE_STEP_IFACE_CONTACTS,
    INITIALIZE_STEP_IFACE_LOCATION,
    INITIALIZE_STEP_IFACE_MESSAGING,
    INITIALIZE_STEP_IFACE_VOICE,
    INITIALIZE_STEP_IFACE_TIME,
    INITIALIZE_STEP_IFACE_SIGNAL,
    INITIALIZE_STEP_IFACE_OMA,
    INITIALIZE_STEP_IFACE_FIRMWARE,
    INITIALIZE_STEP_SIM_HOT_SWAP,
    INITIALIZE_STEP_IFACE_SIMPLE,
    INITIALIZE_STEP_LAST,
} InitializeStep;

typedef struct {
    MMBroadbandModem *self;
    InitializeStep step;
    gpointer ports_ctx;
} InitializeContext;

static void initialize_step (GTask *task);

static void
initialize_context_free (InitializeContext *ctx)
{
    GError *error = NULL;

    if (ctx->ports_ctx &&
        MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->initialization_stopped &&
        !MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->initialization_stopped (ctx->self, ctx->ports_ctx, &error)) {
        mm_warn ("Error when stopping the initialization sequence: %s", error->message);
        g_error_free (error);
    }

    g_object_unref (ctx->self);
    g_free (ctx);
}

static gboolean
initialize_finish (MMBaseModem *self,
                   GAsyncResult *res,
                   GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
initialization_started_ready (MMBroadbandModem *self,
                              GAsyncResult *result,
                              GTask *task)
{
    InitializeContext *ctx;
    GError *error = NULL;
    gpointer ports_ctx;

    ctx = g_task_get_task_data (task);

    /* May return NULL without error */
    ports_ctx = MM_BROADBAND_MODEM_GET_CLASS (self)->initialization_started_finish (self, result, &error);
    if (error) {
        mm_warn ("Couldn't start initialization: %s", error->message);
        g_error_free (error);

        /* There is no Modem interface yet, so just update the variable directly */
        ctx->self->priv->modem_state = MM_MODEM_STATE_FAILED;

        /* Just jump to the last step */
        ctx->step = INITIALIZE_STEP_LAST;
        initialize_step (task);
        return;
    }

    /* Keep the ctx for later use when stopping initialization */
    ctx->ports_ctx = ports_ctx;

    /* Go on to next step */
    ctx->step++;
    initialize_step (task);
}

static void
iface_modem_initialize_ready (MMBroadbandModem *self,
                              GAsyncResult *result,
                              GTask *task)
{
    InitializeContext *ctx;
    GError *error = NULL;

    ctx = g_task_get_task_data (task);

    /* If the modem interface fails to get initialized, we will move the modem
     * to a FAILED state. Note that in this case we still export the interface. */
    if (!mm_iface_modem_initialize_finish (MM_IFACE_MODEM (self), result, &error)) {
        MMModemStateFailedReason failed_reason = MM_MODEM_STATE_FAILED_REASON_UNKNOWN;

        /* Report the new FAILED state */
        mm_warn ("Modem couldn't be initialized: %s", error->message);

        if (g_error_matches (error,
                             MM_MOBILE_EQUIPMENT_ERROR,
                             MM_MOBILE_EQUIPMENT_ERROR_SIM_NOT_INSERTED))
            failed_reason = MM_MODEM_STATE_FAILED_REASON_SIM_MISSING;
        else if (g_error_matches (error,
                                  MM_MOBILE_EQUIPMENT_ERROR,
                                  MM_MOBILE_EQUIPMENT_ERROR_SIM_FAILURE) ||
                 g_error_matches (error,
                                  MM_MOBILE_EQUIPMENT_ERROR,
                                  MM_MOBILE_EQUIPMENT_ERROR_SIM_WRONG))
            failed_reason = MM_MODEM_STATE_FAILED_REASON_SIM_MISSING;

        g_error_free (error);

        mm_iface_modem_update_failed_state (MM_IFACE_MODEM (self), failed_reason);

        /* Jump to the firmware step. We allow firmware switching even in failed
         * state */
        ctx->step = INITIALIZE_STEP_IFACE_FIRMWARE;
        initialize_step (task);
        return;
    }

    /* bind simple properties */
    mm_iface_modem_bind_simple_status (MM_IFACE_MODEM (self),
                                       self->priv->modem_simple_status);

    /* If we find ourselves in a LOCKED state, we shouldn't keep on
     * the initialization sequence. Instead, we will re-initialize once
     * we are unlocked. */
    if (ctx->self->priv->modem_state == MM_MODEM_STATE_LOCKED) {
        /* Jump to the Firmware interface. We do allow modems to export
         * both the Firmware and Simple interfaces when locked. */
        ctx->step = INITIALIZE_STEP_IFACE_FIRMWARE;
        initialize_step (task);
        return;
    }

    /* Go on to next step */
    ctx->step++;
    initialize_step (task);
}

#undef INTERFACE_INIT_READY_FN
#define INTERFACE_INIT_READY_FN(NAME,TYPE,FATAL_ERRORS)                 \
    static void                                                         \
    NAME##_initialize_ready (MMBroadbandModem *self,                    \
                             GAsyncResult *result,                      \
                             GTask *task)                               \
    {                                                                   \
        InitializeContext *ctx;                                         \
        GError *error = NULL;                                           \
                                                                        \
        ctx = g_task_get_task_data (task);                              \
                                                                        \
        if (!mm_##NAME##_initialize_finish (TYPE (self), result, &error)) { \
            if (FATAL_ERRORS) {                                         \
                mm_warn ("Couldn't initialize interface: '%s'",         \
                         error->message);                               \
                g_error_free (error);                                   \
                                                                        \
                /* Report the new FAILED state */                       \
                mm_iface_modem_update_failed_state (MM_IFACE_MODEM (self), \
                                                    MM_MODEM_STATE_FAILED_REASON_UNKNOWN); \
                                                                        \
                /* Just jump to the last step */                        \
                ctx->step = INITIALIZE_STEP_LAST;                       \
                initialize_step (task);                                 \
                return;                                                 \
            }                                                           \
                                                                        \
            mm_dbg ("Couldn't initialize interface: '%s'",              \
                    error->message);                                    \
            /* Just shutdown this interface */                          \
            mm_##NAME##_shutdown (TYPE (self));                         \
            g_error_free (error);                                       \
        } else {                                                        \
            /* bind simple properties */                                \
            mm_##NAME##_bind_simple_status (TYPE (self), self->priv->modem_simple_status); \
        }                                                               \
                                                                        \
        /* Go on to next step */                                        \
        ctx->step++;                                                    \
        initialize_step (task);                                         \
    }

INTERFACE_INIT_READY_FN (iface_modem_3gpp,      MM_IFACE_MODEM_3GPP,      TRUE)
INTERFACE_INIT_READY_FN (iface_modem_3gpp_ussd, MM_IFACE_MODEM_3GPP_USSD, FALSE)
INTERFACE_INIT_READY_FN (iface_modem_cdma,      MM_IFACE_MODEM_CDMA,      TRUE)
INTERFACE_INIT_READY_FN (iface_modem_location,  MM_IFACE_MODEM_LOCATION,  FALSE)
INTERFACE_INIT_READY_FN (iface_modem_messaging, MM_IFACE_MODEM_MESSAGING, FALSE)
INTERFACE_INIT_READY_FN (iface_modem_voice,     MM_IFACE_MODEM_VOICE,     FALSE)
INTERFACE_INIT_READY_FN (iface_modem_time,      MM_IFACE_MODEM_TIME,      FALSE)
INTERFACE_INIT_READY_FN (iface_modem_signal,    MM_IFACE_MODEM_SIGNAL,    FALSE)
INTERFACE_INIT_READY_FN (iface_modem_oma,       MM_IFACE_MODEM_OMA,       FALSE)
INTERFACE_INIT_READY_FN (iface_modem_firmware,  MM_IFACE_MODEM_FIRMWARE,  FALSE)

static void
initialize_step (GTask *task)
{
    InitializeContext *ctx;

    /* Don't run new steps if we're cancelled */
    if (g_task_return_error_if_cancelled (task)) {
        g_object_unref (task);
        return;
    }

    ctx = g_task_get_task_data (task);

    switch (ctx->step) {
    case INITIALIZE_STEP_FIRST:
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_SETUP_PORTS:
        if (MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->setup_ports)
            MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->setup_ports (ctx->self);
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_STARTED:
        if (MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->initialization_started &&
            MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->initialization_started_finish) {
            MM_BROADBAND_MODEM_GET_CLASS (ctx->self)->initialization_started (ctx->self,
                                                                              (GAsyncReadyCallback)initialization_started_ready,
                                                                              task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_SETUP_SIMPLE_STATUS:
        /* Simple status must be created before any interface initialization,
         * so that interfaces add and bind the properties they want to export.
         */
        if (!ctx->self->priv->modem_simple_status)
            ctx->self->priv->modem_simple_status = mm_simple_status_new ();
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_MODEM:
        /* Initialize the Modem interface */
        mm_iface_modem_initialize (MM_IFACE_MODEM (ctx->self),
                                   g_task_get_cancellable (task),
                                   (GAsyncReadyCallback)iface_modem_initialize_ready,
                                   task);
        return;

    case INITIALIZE_STEP_IFACE_3GPP:
        if (mm_iface_modem_is_3gpp (MM_IFACE_MODEM (ctx->self))) {
            /* Initialize the 3GPP interface */
            mm_iface_modem_3gpp_initialize (MM_IFACE_MODEM_3GPP (ctx->self),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)iface_modem_3gpp_initialize_ready,
                                            task);
            return;
        }

        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_3GPP_USSD:
        if (mm_iface_modem_is_3gpp (MM_IFACE_MODEM (ctx->self))) {
            /* Initialize the 3GPP/USSD interface */
            mm_iface_modem_3gpp_ussd_initialize (MM_IFACE_MODEM_3GPP_USSD (ctx->self),
                                                 (GAsyncReadyCallback)iface_modem_3gpp_ussd_initialize_ready,
                                                 task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_CDMA:
        if (mm_iface_modem_is_cdma (MM_IFACE_MODEM (ctx->self))) {
            /* Initialize the CDMA interface */
            mm_iface_modem_cdma_initialize (MM_IFACE_MODEM_CDMA (ctx->self),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)iface_modem_cdma_initialize_ready,
                                            task);
            return;
        }
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_CONTACTS:
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_LOCATION:
        /* Initialize the Location interface */
        mm_iface_modem_location_initialize (MM_IFACE_MODEM_LOCATION (ctx->self),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)iface_modem_location_initialize_ready,
                                            task);
        return;

    case INITIALIZE_STEP_IFACE_MESSAGING:
        /* Initialize the Messaging interface */
        mm_iface_modem_messaging_initialize (MM_IFACE_MODEM_MESSAGING (ctx->self),
                                             g_task_get_cancellable (task),
                                             (GAsyncReadyCallback)iface_modem_messaging_initialize_ready,
                                             task);
        return;

    case INITIALIZE_STEP_IFACE_VOICE:
        /* Initialize the Voice interface */
        mm_iface_modem_voice_initialize (MM_IFACE_MODEM_VOICE (ctx->self),
                                         g_task_get_cancellable (task),
                                         (GAsyncReadyCallback)iface_modem_voice_initialize_ready,
                                         task);
        return;

    case INITIALIZE_STEP_IFACE_TIME:
        /* Initialize the Time interface */
        mm_iface_modem_time_initialize (MM_IFACE_MODEM_TIME (ctx->self),
                                        g_task_get_cancellable (task),
                                        (GAsyncReadyCallback)iface_modem_time_initialize_ready,
                                        task);
        return;

    case INITIALIZE_STEP_IFACE_SIGNAL:
        /* Initialize the Signal interface */
        mm_iface_modem_signal_initialize (MM_IFACE_MODEM_SIGNAL (ctx->self),
                                          g_task_get_cancellable (task),
                                          (GAsyncReadyCallback)iface_modem_signal_initialize_ready,
                                          task);
        return;

    case INITIALIZE_STEP_IFACE_OMA:
        /* Initialize the Oma interface */
        mm_iface_modem_oma_initialize (MM_IFACE_MODEM_OMA (ctx->self),
                                       g_task_get_cancellable (task),
                                       (GAsyncReadyCallback)iface_modem_oma_initialize_ready,
                                       task);
        return;

    case INITIALIZE_STEP_IFACE_FIRMWARE:
        /* Initialize the Firmware interface */
        mm_iface_modem_firmware_initialize (MM_IFACE_MODEM_FIRMWARE (ctx->self),
                                            g_task_get_cancellable (task),
                                            (GAsyncReadyCallback)iface_modem_firmware_initialize_ready,
                                            task);
        return;

    case INITIALIZE_STEP_SIM_HOT_SWAP:
        /* Create the SIM hot swap ports context only if not already done before
         * (we may be re-running the initialization step after SIM-PIN unlock) */
        if (!ctx->self->priv->sim_hot_swap_ports_ctx) {
            gboolean is_sim_hot_swap_supported = FALSE;
            gboolean is_sim_hot_swap_configured = FALSE;

            g_object_get (ctx->self,
                          MM_IFACE_MODEM_SIM_HOT_SWAP_SUPPORTED,  &is_sim_hot_swap_supported,
                          MM_IFACE_MODEM_SIM_HOT_SWAP_CONFIGURED, &is_sim_hot_swap_configured,
                          NULL);

            if (is_sim_hot_swap_supported) {

                if (!is_sim_hot_swap_configured) {
                    mm_warn ("SIM hot swap supported but not configured. Skipping opening ports");
                } else {
                    PortsContext *ports;
                    GError *error = NULL;

                    mm_dbg ("Creating ports context for SIM hot swap");

                    ports = g_new0 (PortsContext, 1);
                    ports->ref_count = 1;

                    if (!open_ports_enabling (ctx->self, ports, FALSE, &error)) {
                        mm_warn ("Couldn't open ports during Modem SIM hot swap enabling: %s", error? error->message : "unknown reason");
                        g_error_free (error);
                    } else {
                        ctx->self->priv->sim_hot_swap_ports_ctx = ports_context_ref (ports);
                    }

                    ports_context_unref (ports);
                }
            }
        } else
            mm_dbg ("Ports context for SIM hot swap already available");

        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_IFACE_SIMPLE:
        if (ctx->self->priv->modem_state != MM_MODEM_STATE_FAILED)
            mm_iface_modem_simple_initialize (MM_IFACE_MODEM_SIMPLE (ctx->self));
        /* Fall down to next step */
        ctx->step++;

    case INITIALIZE_STEP_LAST:
        if (ctx->self->priv->modem_state == MM_MODEM_STATE_FAILED) {
            GError *error;

            if (!ctx->self->priv->modem_dbus_skeleton) {
                /* Error setting up ports. Abort without even exporting the
                 * Modem interface */
                error = g_error_new (MM_CORE_ERROR,
                                     MM_CORE_ERROR_ABORTED,
                                     "Modem is unusable, "
                                     "cannot fully initialize");
            } else {
                /* Fatal SIM, firmware, or modem failure :-( */
                gboolean is_sim_hot_swap_supported = FALSE;
                gboolean is_sim_hot_swap_configured = FALSE;

                MMModemStateFailedReason reason =
                    mm_gdbus_modem_get_state_failed_reason (
                        (MmGdbusModem*)ctx->self->priv->modem_dbus_skeleton);

                g_object_get (ctx->self,
                              MM_IFACE_MODEM_SIM_HOT_SWAP_SUPPORTED, &is_sim_hot_swap_supported,
                              MM_IFACE_MODEM_SIM_HOT_SWAP_CONFIGURED, &is_sim_hot_swap_configured,
                              NULL);

                if (reason == MM_MODEM_STATE_FAILED_REASON_SIM_MISSING) {
                    if (!is_sim_hot_swap_supported) {
                        mm_dbg ("SIM is missing, but this modem does not support SIM hot swap.");
                    } else if (!is_sim_hot_swap_configured) {
                        mm_warn ("SIM is missing, but SIM hot swap could not be configured.");
                    } else if (!ctx->self->priv->sim_hot_swap_ports_ctx) {
                        mm_err ("SIM is missing and SIM hot swap is configured, but ports are not opened.");
                    } else {
                        mm_dbg ("SIM is missing, but SIM hot swap is enabled. Waiting for SIM...");
                        error = g_error_new (MM_CORE_ERROR,
                                             MM_CORE_ERROR_WRONG_STATE,
                                             "Modem is unusable due to SIM missing, "
                                             "cannot fully initialize, waiting for SIM insertion.");
                        goto sim_hot_swap_enabled;
                    }
                }

                error = g_error_new (MM_CORE_ERROR,
                                     MM_CORE_ERROR_WRONG_STATE,
                                     "Modem is unusable, "
                                     "cannot fully initialize");
sim_hot_swap_enabled:
                /* Ensure we only leave the Modem, OMA, and Firmware interfaces
                 * around.  A failure could be caused by firmware issues, which
                 * a firmware update, switch, or provisioning could fix.
                 */
                mm_iface_modem_3gpp_shutdown (MM_IFACE_MODEM_3GPP (ctx->self));
                mm_iface_modem_3gpp_ussd_shutdown (MM_IFACE_MODEM_3GPP_USSD (ctx->self));
                mm_iface_modem_cdma_shutdown (MM_IFACE_MODEM_CDMA (ctx->self));
                mm_iface_modem_location_shutdown (MM_IFACE_MODEM_LOCATION (ctx->self));
                mm_iface_modem_messaging_shutdown (MM_IFACE_MODEM_MESSAGING (ctx->self));
                mm_iface_modem_voice_shutdown (MM_IFACE_MODEM_VOICE (ctx->self));
                mm_iface_modem_time_shutdown (MM_IFACE_MODEM_TIME (ctx->self));
                mm_iface_modem_simple_shutdown (MM_IFACE_MODEM_SIMPLE (ctx->self));
            }

            g_task_return_error (task, error);
            g_object_unref (task);
            return;
        }

        if (ctx->self->priv->modem_state == MM_MODEM_STATE_LOCKED) {
            /* We're locked :-/ */
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_WRONG_STATE,
                                     "Modem is currently locked, "
                                     "cannot fully initialize");
            g_object_unref (task);
            return;
        }

        /* All initialized without errors!
         * Set as disabled (a.k.a. initialized) */
        mm_iface_modem_update_state (MM_IFACE_MODEM (ctx->self),
                                     MM_MODEM_STATE_DISABLED,
                                     MM_MODEM_STATE_CHANGE_REASON_UNKNOWN);

        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    g_assert_not_reached ();
}

static void
initialize (MMBaseModem *self,
            GCancellable *cancellable,
            GAsyncReadyCallback callback,
            gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, cancellable, callback, user_data);

    /* Check state before launching modem initialization */
    switch (MM_BROADBAND_MODEM (self)->priv->modem_state) {
    case MM_MODEM_STATE_FAILED:
        /* NOTE: this will only happen if we ever support hot-plugging SIMs */
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_WRONG_STATE,
                                 "Cannot initialize modem: "
                                 "device is unusable");
        break;

    case MM_MODEM_STATE_UNKNOWN:
    case MM_MODEM_STATE_LOCKED: {
        InitializeContext *ctx;

        ctx = g_new0 (InitializeContext, 1);
        ctx->self = g_object_ref (self);
        ctx->step = INITIALIZE_STEP_FIRST;

        g_task_set_task_data (task, ctx, (GDestroyNotify)initialize_context_free);

        /* Set as being initialized, even if we were locked before */
        mm_iface_modem_update_state (MM_IFACE_MODEM (self),
                                     MM_MODEM_STATE_INITIALIZING,
                                     MM_MODEM_STATE_CHANGE_REASON_UNKNOWN);

        initialize_step (task);
        return;
    }

    case MM_MODEM_STATE_INITIALIZING:
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_IN_PROGRESS,
                                 "Cannot initialize modem: "
                                 "already being initialized");
        break;

    case MM_MODEM_STATE_DISABLED:
    case MM_MODEM_STATE_DISABLING:
    case MM_MODEM_STATE_ENABLING:
    case MM_MODEM_STATE_ENABLED:
    case MM_MODEM_STATE_SEARCHING:
    case MM_MODEM_STATE_REGISTERED:
    case MM_MODEM_STATE_DISCONNECTING:
    case MM_MODEM_STATE_CONNECTING:
    case MM_MODEM_STATE_CONNECTED:
        /* Just return success, don't relaunch initialization */
        g_task_return_boolean (task, TRUE);
        break;
    }

    g_object_unref (task);
}

/*****************************************************************************/

gchar *
mm_broadband_modem_take_and_convert_to_utf8 (MMBroadbandModem *self,
                                             gchar *str)
{
    /* should only be used AFTER current charset is set */
    if (self->priv->modem_current_charset == MM_MODEM_CHARSET_UNKNOWN)
        return str;

    return mm_charset_take_and_convert_to_utf8 (str,
                                                self->priv->modem_current_charset);
}

gchar *
mm_broadband_modem_take_and_convert_to_current_charset (MMBroadbandModem *self,
                                                        gchar *str)
{
    /* should only be used AFTER current charset is set */
    if (self->priv->modem_current_charset == MM_MODEM_CHARSET_UNKNOWN)
        return str;

    return mm_utf8_take_and_convert_to_charset (str, self->priv->modem_current_charset);
}

MMModemCharset
mm_broadband_modem_get_current_charset (MMBroadbandModem *self)
{
    return self->priv->modem_current_charset;
}

gchar *
mm_broadband_modem_create_device_identifier (MMBroadbandModem *self,
                                             const gchar *ati,
                                             const gchar *ati1)
{
    return (mm_create_device_identifier (
                mm_base_modem_get_vendor_id (MM_BASE_MODEM (self)),
                mm_base_modem_get_product_id (MM_BASE_MODEM (self)),
                ati,
                ati1,
                mm_gdbus_modem_get_equipment_identifier (
                    MM_GDBUS_MODEM (self->priv->modem_dbus_skeleton)),
                mm_gdbus_modem_get_revision (
                    MM_GDBUS_MODEM (self->priv->modem_dbus_skeleton)),
                mm_gdbus_modem_get_model (
                    MM_GDBUS_MODEM (self->priv->modem_dbus_skeleton)),
                mm_gdbus_modem_get_manufacturer (
                    MM_GDBUS_MODEM (self->priv->modem_dbus_skeleton))));
}


/*****************************************************************************/
static void
after_hotswap_event_disable_ready (MMBaseModem *self,
                                   GAsyncResult *res,
                                   gpointer user_data)
{
    GError *error = NULL;
    mm_base_modem_disable_finish (self, res, &error);
    if (error) {
        mm_err ("Disable modem error: %s", error->message);
        g_error_free (error);
    } else {
        mm_base_modem_set_valid (self, FALSE);
    }
}

void
mm_broadband_modem_update_sim_hot_swap_detected (MMBroadbandModem *self)
{
    if (self->priv->sim_hot_swap_ports_ctx) {
        mm_dbg ("Releasing SIM hot swap ports context");
        ports_context_unref (self->priv->sim_hot_swap_ports_ctx);
        self->priv->sim_hot_swap_ports_ctx = NULL;
    }

    mm_base_modem_set_reprobe (MM_BASE_MODEM (self), TRUE);
    mm_base_modem_disable (MM_BASE_MODEM (self),
                           (GAsyncReadyCallback) after_hotswap_event_disable_ready,
                           NULL);
}

/*****************************************************************************/

MMBroadbandModem *
mm_broadband_modem_new (const gchar *device,
                        const gchar **drivers,
                        const gchar *plugin,
                        guint16 vendor_id,
                        guint16 product_id)
{
    return g_object_new (MM_TYPE_BROADBAND_MODEM,
                         MM_BASE_MODEM_DEVICE, device,
                         MM_BASE_MODEM_DRIVERS, drivers,
                         MM_BASE_MODEM_PLUGIN, plugin,
                         MM_BASE_MODEM_VENDOR_ID, vendor_id,
                         MM_BASE_MODEM_PRODUCT_ID, product_id,
                         NULL);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (object);

    switch (prop_id) {
    case PROP_MODEM_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_dbus_skeleton);
        self->priv->modem_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_3GPP_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_3gpp_dbus_skeleton);
        self->priv->modem_3gpp_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_3GPP_USSD_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_3gpp_ussd_dbus_skeleton);
        self->priv->modem_3gpp_ussd_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_CDMA_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_cdma_dbus_skeleton);
        self->priv->modem_cdma_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_SIMPLE_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_simple_dbus_skeleton);
        self->priv->modem_simple_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_LOCATION_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_location_dbus_skeleton);
        self->priv->modem_location_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_MESSAGING_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_messaging_dbus_skeleton);
        self->priv->modem_messaging_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_VOICE_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_voice_dbus_skeleton);
        self->priv->modem_voice_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_TIME_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_time_dbus_skeleton);
        self->priv->modem_time_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_SIGNAL_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_signal_dbus_skeleton);
        self->priv->modem_signal_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_OMA_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_oma_dbus_skeleton);
        self->priv->modem_oma_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_FIRMWARE_DBUS_SKELETON:
        g_clear_object (&self->priv->modem_firmware_dbus_skeleton);
        self->priv->modem_firmware_dbus_skeleton = g_value_dup_object (value);
        break;
    case PROP_MODEM_SIM:
        g_clear_object (&self->priv->modem_sim);
        self->priv->modem_sim = g_value_dup_object (value);
        break;
    case PROP_MODEM_BEARER_LIST:
        g_clear_object (&self->priv->modem_bearer_list);
        self->priv->modem_bearer_list = g_value_dup_object (value);
        break;
    case PROP_MODEM_STATE:
        self->priv->modem_state = g_value_get_enum (value);
        break;
    case PROP_MODEM_3GPP_REGISTRATION_STATE:
        self->priv->modem_3gpp_registration_state = g_value_get_enum (value);
        break;
    case PROP_MODEM_3GPP_CS_NETWORK_SUPPORTED:
        self->priv->modem_3gpp_cs_network_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_3GPP_PS_NETWORK_SUPPORTED:
        self->priv->modem_3gpp_ps_network_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_3GPP_EPS_NETWORK_SUPPORTED:
        self->priv->modem_3gpp_eps_network_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_3GPP_IGNORED_FACILITY_LOCKS:
        self->priv->modem_3gpp_ignored_facility_locks = g_value_get_flags (value);
        break;
    case PROP_MODEM_CDMA_CDMA1X_REGISTRATION_STATE:
        self->priv->modem_cdma_cdma1x_registration_state = g_value_get_enum (value);
        break;
    case PROP_MODEM_CDMA_EVDO_REGISTRATION_STATE:
        self->priv->modem_cdma_evdo_registration_state = g_value_get_enum (value);
        break;
    case PROP_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED:
        self->priv->modem_cdma_cdma1x_network_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_CDMA_EVDO_NETWORK_SUPPORTED:
        self->priv->modem_cdma_evdo_network_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_MESSAGING_SMS_LIST:
        g_clear_object (&self->priv->modem_messaging_sms_list);
        self->priv->modem_messaging_sms_list = g_value_dup_object (value);
        break;
    case PROP_MODEM_VOICE_CALL_LIST:
        g_clear_object (&self->priv->modem_voice_call_list);
        self->priv->modem_voice_call_list = g_value_dup_object (value);
        break;
    case PROP_MODEM_MESSAGING_SMS_PDU_MODE:
        self->priv->modem_messaging_sms_pdu_mode = g_value_get_boolean (value);
        break;
    case PROP_MODEM_MESSAGING_SMS_DEFAULT_STORAGE:
        self->priv->modem_messaging_sms_default_storage = g_value_get_enum (value);
        break;
    case PROP_MODEM_SIMPLE_STATUS:
        g_clear_object (&self->priv->modem_simple_status);
        self->priv->modem_simple_status = g_value_dup_object (value);
        break;
    case PROP_MODEM_SIM_HOT_SWAP_SUPPORTED:
        self->priv->sim_hot_swap_supported = g_value_get_boolean (value);
        break;
    case PROP_MODEM_SIM_HOT_SWAP_CONFIGURED:
        self->priv->sim_hot_swap_configured = g_value_get_boolean (value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (object);

    switch (prop_id) {
    case PROP_MODEM_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_dbus_skeleton);
        break;
    case PROP_MODEM_3GPP_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_3gpp_dbus_skeleton);
        break;
    case PROP_MODEM_3GPP_USSD_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_3gpp_ussd_dbus_skeleton);
        break;
    case PROP_MODEM_CDMA_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_cdma_dbus_skeleton);
        break;
    case PROP_MODEM_SIMPLE_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_simple_dbus_skeleton);
        break;
    case PROP_MODEM_LOCATION_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_location_dbus_skeleton);
        break;
    case PROP_MODEM_MESSAGING_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_messaging_dbus_skeleton);
        break;
    case PROP_MODEM_VOICE_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_voice_dbus_skeleton);
        break;
    case PROP_MODEM_TIME_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_time_dbus_skeleton);
        break;
    case PROP_MODEM_SIGNAL_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_signal_dbus_skeleton);
        break;
    case PROP_MODEM_OMA_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_oma_dbus_skeleton);
        break;
    case PROP_MODEM_FIRMWARE_DBUS_SKELETON:
        g_value_set_object (value, self->priv->modem_firmware_dbus_skeleton);
        break;
    case PROP_MODEM_SIM:
        g_value_set_object (value, self->priv->modem_sim);
        break;
    case PROP_MODEM_BEARER_LIST:
        g_value_set_object (value, self->priv->modem_bearer_list);
        break;
    case PROP_MODEM_STATE:
        g_value_set_enum (value, self->priv->modem_state);
        break;
    case PROP_MODEM_3GPP_REGISTRATION_STATE:
        g_value_set_enum (value, self->priv->modem_3gpp_registration_state);
        break;
    case PROP_MODEM_3GPP_CS_NETWORK_SUPPORTED:
        g_value_set_boolean (value, self->priv->modem_3gpp_cs_network_supported);
        break;
    case PROP_MODEM_3GPP_PS_NETWORK_SUPPORTED:
        g_value_set_boolean (value, self->priv->modem_3gpp_ps_network_supported);
        break;
    case PROP_MODEM_3GPP_EPS_NETWORK_SUPPORTED:
        g_value_set_boolean (value, self->priv->modem_3gpp_eps_network_supported);
        break;
    case PROP_MODEM_3GPP_IGNORED_FACILITY_LOCKS:
        g_value_set_flags (value, self->priv->modem_3gpp_ignored_facility_locks);
        break;
    case PROP_MODEM_CDMA_CDMA1X_REGISTRATION_STATE:
        g_value_set_enum (value, self->priv->modem_cdma_cdma1x_registration_state);
        break;
    case PROP_MODEM_CDMA_EVDO_REGISTRATION_STATE:
        g_value_set_enum (value, self->priv->modem_cdma_evdo_registration_state);
        break;
    case PROP_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED:
        g_value_set_boolean (value, self->priv->modem_cdma_cdma1x_network_supported);
        break;
    case PROP_MODEM_CDMA_EVDO_NETWORK_SUPPORTED:
        g_value_set_boolean (value, self->priv->modem_cdma_evdo_network_supported);
        break;
    case PROP_MODEM_MESSAGING_SMS_LIST:
        g_value_set_object (value, self->priv->modem_messaging_sms_list);
        break;
    case PROP_MODEM_VOICE_CALL_LIST:
        g_value_set_object (value, self->priv->modem_voice_call_list);
        break;
    case PROP_MODEM_MESSAGING_SMS_PDU_MODE:
        g_value_set_boolean (value, self->priv->modem_messaging_sms_pdu_mode);
        break;
    case PROP_MODEM_MESSAGING_SMS_DEFAULT_STORAGE:
        g_value_set_enum (value, self->priv->modem_messaging_sms_default_storage);
        break;
    case PROP_MODEM_SIMPLE_STATUS:
        g_value_set_object (value, self->priv->modem_simple_status);
        break;
    case PROP_MODEM_SIM_HOT_SWAP_SUPPORTED:
        g_value_set_boolean (value, self->priv->sim_hot_swap_supported);
        break;
    case PROP_MODEM_SIM_HOT_SWAP_CONFIGURED:
        g_value_set_boolean (value, self->priv->sim_hot_swap_configured);
        break;
    case PROP_FLOW_CONTROL:
        g_value_set_flags (value, self->priv->flow_control);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
mm_broadband_modem_init (MMBroadbandModem *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_BROADBAND_MODEM,
                                              MMBroadbandModemPrivate);
    self->priv->modem_state = MM_MODEM_STATE_UNKNOWN;
    self->priv->modem_3gpp_registration_regex = mm_3gpp_creg_regex_get (TRUE);
    self->priv->modem_current_charset = MM_MODEM_CHARSET_UNKNOWN;
    self->priv->modem_3gpp_registration_state = MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;
    self->priv->modem_3gpp_cs_network_supported = TRUE;
    self->priv->modem_3gpp_ps_network_supported = TRUE;
    self->priv->modem_3gpp_eps_network_supported = FALSE;
    self->priv->modem_3gpp_ignored_facility_locks = MM_MODEM_3GPP_FACILITY_NONE;
    self->priv->modem_cdma_cdma1x_registration_state = MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
    self->priv->modem_cdma_evdo_registration_state = MM_MODEM_CDMA_REGISTRATION_STATE_UNKNOWN;
    self->priv->modem_cdma_cdma1x_network_supported = TRUE;
    self->priv->modem_cdma_evdo_network_supported = TRUE;
    self->priv->modem_messaging_sms_default_storage = MM_SMS_STORAGE_UNKNOWN;
    self->priv->current_sms_mem1_storage = MM_SMS_STORAGE_UNKNOWN;
    self->priv->current_sms_mem2_storage = MM_SMS_STORAGE_UNKNOWN;
    self->priv->sim_hot_swap_supported = FALSE;
    self->priv->modem_cmer_enable_mode = MM_3GPP_CMER_MODE_NONE;
    self->priv->modem_cmer_disable_mode = MM_3GPP_CMER_MODE_NONE;
    self->priv->modem_cmer_ind = MM_3GPP_CMER_IND_NONE;
    self->priv->flow_control = MM_FLOW_CONTROL_NONE;
}

static void
finalize (GObject *object)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (object);

    if (self->priv->enabled_ports_ctx)
        ports_context_unref (self->priv->enabled_ports_ctx);

    if (self->priv->sim_hot_swap_ports_ctx)
        ports_context_unref (self->priv->sim_hot_swap_ports_ctx);

    if (self->priv->modem_3gpp_registration_regex)
        mm_3gpp_creg_regex_destroy (self->priv->modem_3gpp_registration_regex);

    G_OBJECT_CLASS (mm_broadband_modem_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
    MMBroadbandModem *self = MM_BROADBAND_MODEM (object);

    if (self->priv->modem_dbus_skeleton) {
        mm_iface_modem_shutdown (MM_IFACE_MODEM (object));
        g_clear_object (&self->priv->modem_dbus_skeleton);
    }

    if (self->priv->modem_3gpp_dbus_skeleton) {
        mm_iface_modem_3gpp_shutdown (MM_IFACE_MODEM_3GPP (object));
        g_clear_object (&self->priv->modem_3gpp_dbus_skeleton);
    }

    if (self->priv->modem_3gpp_ussd_dbus_skeleton) {
        mm_iface_modem_3gpp_ussd_shutdown (MM_IFACE_MODEM_3GPP_USSD (object));
        g_clear_object (&self->priv->modem_3gpp_ussd_dbus_skeleton);
    }

    if (self->priv->modem_cdma_dbus_skeleton) {
        mm_iface_modem_cdma_shutdown (MM_IFACE_MODEM_CDMA (object));
        g_clear_object (&self->priv->modem_cdma_dbus_skeleton);
    }

    if (self->priv->modem_location_dbus_skeleton) {
        mm_iface_modem_location_shutdown (MM_IFACE_MODEM_LOCATION (object));
        g_clear_object (&self->priv->modem_location_dbus_skeleton);
    }

    if (self->priv->modem_messaging_dbus_skeleton) {
        mm_iface_modem_messaging_shutdown (MM_IFACE_MODEM_MESSAGING (object));
        g_clear_object (&self->priv->modem_messaging_dbus_skeleton);
    }

    if (self->priv->modem_voice_dbus_skeleton) {
        mm_iface_modem_voice_shutdown (MM_IFACE_MODEM_VOICE (object));
        g_clear_object (&self->priv->modem_voice_dbus_skeleton);
    }

    if (self->priv->modem_time_dbus_skeleton) {
        mm_iface_modem_time_shutdown (MM_IFACE_MODEM_TIME (object));
        g_clear_object (&self->priv->modem_time_dbus_skeleton);
    }

    if (self->priv->modem_simple_dbus_skeleton) {
        mm_iface_modem_simple_shutdown (MM_IFACE_MODEM_SIMPLE (object));
        g_clear_object (&self->priv->modem_simple_dbus_skeleton);
    }

    g_clear_object (&self->priv->modem_sim);
    g_clear_object (&self->priv->modem_bearer_list);
    g_clear_object (&self->priv->modem_messaging_sms_list);
    g_clear_object (&self->priv->modem_voice_call_list);
    g_clear_object (&self->priv->modem_simple_status);

    G_OBJECT_CLASS (mm_broadband_modem_parent_class)->dispose (object);
}

static void
iface_modem_init (MMIfaceModem *iface)
{
    /* Initialization steps */
    iface->load_current_capabilities = modem_load_current_capabilities;
    iface->load_current_capabilities_finish = modem_load_current_capabilities_finish;
    iface->load_manufacturer = modem_load_manufacturer;
    iface->load_manufacturer_finish = modem_load_manufacturer_finish;
    iface->load_model = modem_load_model;
    iface->load_model_finish = modem_load_model_finish;
    iface->load_revision = modem_load_revision;
    iface->load_revision_finish = modem_load_revision_finish;
    iface->load_equipment_identifier = modem_load_equipment_identifier;
    iface->load_equipment_identifier_finish = modem_load_equipment_identifier_finish;
    iface->load_device_identifier = modem_load_device_identifier;
    iface->load_device_identifier_finish = modem_load_device_identifier_finish;
    iface->load_own_numbers = modem_load_own_numbers;
    iface->load_own_numbers_finish = modem_load_own_numbers_finish;
    iface->load_unlock_required = modem_load_unlock_required;
    iface->load_unlock_required_finish = modem_load_unlock_required_finish;
    iface->create_sim = modem_create_sim;
    iface->create_sim_finish = modem_create_sim_finish;
    iface->load_supported_modes = modem_load_supported_modes;
    iface->load_supported_modes_finish = modem_load_supported_modes_finish;
    iface->load_power_state = modem_load_power_state;
    iface->load_power_state_finish = modem_load_power_state_finish;
    iface->load_supported_ip_families = modem_load_supported_ip_families;
    iface->load_supported_ip_families_finish = modem_load_supported_ip_families_finish;

    /* Enabling steps */
    iface->modem_power_up = modem_power_up;
    iface->modem_power_up_finish = modem_power_up_finish;
    iface->setup_flow_control = modem_setup_flow_control;
    iface->setup_flow_control_finish = modem_setup_flow_control_finish;
    iface->load_supported_charsets = modem_load_supported_charsets;
    iface->load_supported_charsets_finish = modem_load_supported_charsets_finish;
    iface->setup_charset = modem_setup_charset;
    iface->setup_charset_finish = modem_setup_charset_finish;

    /* Additional actions */
    iface->load_signal_quality = modem_load_signal_quality;
    iface->load_signal_quality_finish = modem_load_signal_quality_finish;
    iface->create_bearer = modem_create_bearer;
    iface->create_bearer_finish = modem_create_bearer_finish;
    iface->command = modem_command;
    iface->command_finish = modem_command_finish;

    iface->load_access_technologies = modem_load_access_technologies;
    iface->load_access_technologies_finish = modem_load_access_technologies_finish;
}

static void
iface_modem_3gpp_init (MMIfaceModem3gpp *iface)
{
    /* Initialization steps */
    iface->load_imei = modem_3gpp_load_imei;
    iface->load_imei_finish = modem_3gpp_load_imei_finish;
    iface->load_enabled_facility_locks = modem_3gpp_load_enabled_facility_locks;
    iface->load_enabled_facility_locks_finish = modem_3gpp_load_enabled_facility_locks_finish;

    /* Enabling steps */
    iface->setup_unsolicited_events = modem_3gpp_setup_unsolicited_events;
    iface->setup_unsolicited_events_finish = modem_3gpp_setup_cleanup_unsolicited_events_finish;
    iface->enable_unsolicited_events = modem_3gpp_enable_unsolicited_events;
    iface->enable_unsolicited_events_finish = modem_3gpp_enable_disable_unsolicited_events_finish;
    iface->setup_unsolicited_registration_events = modem_3gpp_setup_unsolicited_registration_events;
    iface->setup_unsolicited_registration_events_finish = modem_3gpp_setup_unsolicited_registration_events_finish;
    iface->enable_unsolicited_registration_events = modem_3gpp_enable_unsolicited_registration_events;
    iface->enable_unsolicited_registration_events_finish = modem_3gpp_enable_disable_unsolicited_registration_events_finish;

    /* Disabling steps */
    iface->disable_unsolicited_events = modem_3gpp_disable_unsolicited_events;
    iface->disable_unsolicited_events_finish = modem_3gpp_enable_disable_unsolicited_events_finish;
    iface->cleanup_unsolicited_events = modem_3gpp_cleanup_unsolicited_events;
    iface->cleanup_unsolicited_events_finish = modem_3gpp_setup_cleanup_unsolicited_events_finish;
    iface->disable_unsolicited_registration_events = modem_3gpp_disable_unsolicited_registration_events;
    iface->disable_unsolicited_registration_events_finish = modem_3gpp_enable_disable_unsolicited_registration_events_finish;
    iface->cleanup_unsolicited_registration_events = modem_3gpp_cleanup_unsolicited_registration_events;
    iface->cleanup_unsolicited_registration_events_finish = modem_3gpp_cleanup_unsolicited_registration_events_finish;

    /* Additional actions */
    iface->load_operator_code = modem_3gpp_load_operator_code;
    iface->load_operator_code_finish = modem_3gpp_load_operator_code_finish;
    iface->load_operator_name = modem_3gpp_load_operator_name;
    iface->load_operator_name_finish = modem_3gpp_load_operator_name_finish;
    iface->load_subscription_state = modem_3gpp_load_subscription_state;
    iface->load_subscription_state_finish = modem_3gpp_load_subscription_state_finish;
    iface->run_registration_checks = modem_3gpp_run_registration_checks;
    iface->run_registration_checks_finish = modem_3gpp_run_registration_checks_finish;
    iface->register_in_network = modem_3gpp_register_in_network;
    iface->register_in_network_finish = modem_3gpp_register_in_network_finish;
    iface->scan_networks = modem_3gpp_scan_networks;
    iface->scan_networks_finish = modem_3gpp_scan_networks_finish;
}

static void
iface_modem_3gpp_ussd_init (MMIfaceModem3gppUssd *iface)
{
    /* Initialization steps */
    iface->check_support = modem_3gpp_ussd_check_support;
    iface->check_support_finish = modem_3gpp_ussd_check_support_finish;

    /* Enabling steps */
    iface->setup_unsolicited_result_codes = modem_3gpp_ussd_setup_unsolicited_result_codes;
    iface->setup_unsolicited_result_codes_finish = modem_3gpp_ussd_setup_cleanup_unsolicited_result_codes_finish;
    iface->enable_unsolicited_result_codes = modem_3gpp_ussd_enable_unsolicited_result_codes;
    iface->enable_unsolicited_result_codes_finish = modem_3gpp_ussd_enable_disable_unsolicited_result_codes_finish;

    /* Disabling steps */
    iface->cleanup_unsolicited_result_codes_finish = modem_3gpp_ussd_setup_cleanup_unsolicited_result_codes_finish;
    iface->cleanup_unsolicited_result_codes = modem_3gpp_ussd_cleanup_unsolicited_result_codes;
    iface->disable_unsolicited_result_codes = modem_3gpp_ussd_disable_unsolicited_result_codes;
    iface->disable_unsolicited_result_codes_finish = modem_3gpp_ussd_enable_disable_unsolicited_result_codes_finish;

    /* Additional actions */
    iface->encode = modem_3gpp_ussd_encode;
    iface->decode = modem_3gpp_ussd_decode;
    iface->send = modem_3gpp_ussd_send;
    iface->send_finish = modem_3gpp_ussd_send_finish;
    iface->cancel = modem_3gpp_ussd_cancel;
    iface->cancel_finish = modem_3gpp_ussd_cancel_finish;
}

static void
iface_modem_cdma_init (MMIfaceModemCdma *iface)
{
    /* Initialization steps */
    iface->load_esn = modem_cdma_load_esn;
    iface->load_esn_finish = modem_cdma_load_esn_finish;
    iface->load_meid = modem_cdma_load_meid;
    iface->load_meid_finish = modem_cdma_load_meid_finish;

    /* Registration check steps */
    iface->setup_unsolicited_events = modem_cdma_setup_unsolicited_events;
    iface->setup_unsolicited_events_finish = modem_cdma_setup_cleanup_unsolicited_events_finish;
    iface->cleanup_unsolicited_events = modem_cdma_cleanup_unsolicited_events;
    iface->cleanup_unsolicited_events_finish = modem_cdma_setup_cleanup_unsolicited_events_finish;
    iface->setup_registration_checks = modem_cdma_setup_registration_checks;
    iface->setup_registration_checks_finish = modem_cdma_setup_registration_checks_finish;
    iface->get_call_manager_state = modem_cdma_get_call_manager_state;
    iface->get_call_manager_state_finish = modem_cdma_get_call_manager_state_finish;
    iface->get_hdr_state = modem_cdma_get_hdr_state;
    iface->get_hdr_state_finish = modem_cdma_get_hdr_state_finish;
    iface->get_service_status = modem_cdma_get_service_status;
    iface->get_service_status_finish = modem_cdma_get_service_status_finish;
    iface->get_cdma1x_serving_system = modem_cdma_get_cdma1x_serving_system;
    iface->get_cdma1x_serving_system_finish = modem_cdma_get_cdma1x_serving_system_finish;
    iface->get_detailed_registration_state = modem_cdma_get_detailed_registration_state;
    iface->get_detailed_registration_state_finish = modem_cdma_get_detailed_registration_state_finish;

    /* Additional actions */
    iface->register_in_network = modem_cdma_register_in_network;
    iface->register_in_network_finish = modem_cdma_register_in_network_finish;
}

static void
iface_modem_simple_init (MMIfaceModemSimple *iface)
{
}

static void
iface_modem_location_init (MMIfaceModemLocation *iface)
{
    iface->load_capabilities = modem_location_load_capabilities;
    iface->load_capabilities_finish = modem_location_load_capabilities_finish;
    iface->enable_location_gathering = enable_location_gathering;
    iface->enable_location_gathering_finish = enable_location_gathering_finish;
}

static void
iface_modem_messaging_init (MMIfaceModemMessaging *iface)
{
    iface->check_support = modem_messaging_check_support;
    iface->check_support_finish = modem_messaging_check_support_finish;
    iface->load_supported_storages = modem_messaging_load_supported_storages;
    iface->load_supported_storages_finish = modem_messaging_load_supported_storages_finish;
    iface->set_default_storage = modem_messaging_set_default_storage;
    iface->set_default_storage_finish = modem_messaging_set_default_storage_finish;
    iface->setup_sms_format = modem_messaging_setup_sms_format;
    iface->setup_sms_format_finish = modem_messaging_setup_sms_format_finish;
    iface->load_initial_sms_parts = modem_messaging_load_initial_sms_parts;
    iface->load_initial_sms_parts_finish = modem_messaging_load_initial_sms_parts_finish;
    iface->setup_unsolicited_events = modem_messaging_setup_unsolicited_events;
    iface->setup_unsolicited_events_finish = modem_messaging_setup_cleanup_unsolicited_events_finish;
    iface->enable_unsolicited_events = modem_messaging_enable_unsolicited_events;
    iface->enable_unsolicited_events_finish = modem_messaging_enable_unsolicited_events_finish;
    iface->cleanup_unsolicited_events = modem_messaging_cleanup_unsolicited_events;
    iface->cleanup_unsolicited_events_finish = modem_messaging_setup_cleanup_unsolicited_events_finish;
    iface->create_sms = modem_messaging_create_sms;
    iface->init_current_storages = modem_messaging_init_current_storages;
    iface->init_current_storages_finish = modem_messaging_init_current_storages_finish;
}

static void
iface_modem_voice_init (MMIfaceModemVoice *iface)
{
    iface->check_support = modem_voice_check_support;
    iface->check_support_finish = modem_voice_check_support_finish;
    iface->setup_unsolicited_events = modem_voice_setup_unsolicited_events;
    iface->setup_unsolicited_events_finish = modem_voice_setup_cleanup_unsolicited_events_finish;
    iface->enable_unsolicited_events = modem_voice_enable_unsolicited_events;
    iface->enable_unsolicited_events_finish = modem_voice_enable_unsolicited_events_finish;
    iface->cleanup_unsolicited_events = modem_voice_cleanup_unsolicited_events;
    iface->cleanup_unsolicited_events_finish = modem_voice_setup_cleanup_unsolicited_events_finish;
    iface->create_call = modem_voice_create_call;
}

static void
iface_modem_time_init (MMIfaceModemTime *iface)
{
    iface->check_support = modem_time_check_support;
    iface->check_support_finish = modem_time_check_support_finish;
    iface->load_network_time = modem_time_load_network_time;
    iface->load_network_time_finish = modem_time_load_network_time_finish;
    iface->load_network_timezone = modem_time_load_network_timezone;
    iface->load_network_timezone_finish = modem_time_load_network_timezone_finish;
}

static void
iface_modem_signal_init (MMIfaceModemSignal *iface)
{
    iface->check_support        = modem_signal_check_support;
    iface->check_support_finish = modem_signal_check_support_finish;
    iface->load_values          = modem_signal_load_values;
    iface->load_values_finish   = modem_signal_load_values_finish;
}

static void
iface_modem_oma_init (MMIfaceModemOma *iface)
{
}

static void
iface_modem_firmware_init (MMIfaceModemFirmware *iface)
{
}

static void
mm_broadband_modem_class_init (MMBroadbandModemClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    MMBaseModemClass *base_modem_class = MM_BASE_MODEM_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMBroadbandModemPrivate));

    /* Virtual methods */
    object_class->set_property = set_property;
    object_class->get_property = get_property;
    object_class->dispose = dispose;
    object_class->finalize = finalize;

    base_modem_class->initialize = initialize;
    base_modem_class->initialize_finish = initialize_finish;
    base_modem_class->enable = enable;
    base_modem_class->enable_finish = enable_finish;
    base_modem_class->disable = disable;
    base_modem_class->disable_finish = disable_finish;

    klass->setup_ports = setup_ports;
    klass->initialization_started = initialization_started;
    klass->initialization_started_finish = initialization_started_finish;
    klass->initialization_stopped = initialization_stopped;
    klass->enabling_started = enabling_started;
    klass->enabling_started_finish = enabling_started_finish;
    klass->enabling_modem_init = enabling_modem_init;
    klass->enabling_modem_init_finish = enabling_modem_init_finish;
    klass->disabling_stopped = disabling_stopped;

    g_object_class_override_property (object_class,
                                      PROP_MODEM_DBUS_SKELETON,
                                      MM_IFACE_MODEM_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_DBUS_SKELETON,
                                      MM_IFACE_MODEM_3GPP_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_USSD_DBUS_SKELETON,
                                      MM_IFACE_MODEM_3GPP_USSD_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_CDMA_DBUS_SKELETON,
                                      MM_IFACE_MODEM_CDMA_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIMPLE_DBUS_SKELETON,
                                      MM_IFACE_MODEM_SIMPLE_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_LOCATION_DBUS_SKELETON,
                                      MM_IFACE_MODEM_LOCATION_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_MESSAGING_DBUS_SKELETON,
                                      MM_IFACE_MODEM_MESSAGING_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_VOICE_DBUS_SKELETON,
                                      MM_IFACE_MODEM_VOICE_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_TIME_DBUS_SKELETON,
                                      MM_IFACE_MODEM_TIME_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIGNAL_DBUS_SKELETON,
                                      MM_IFACE_MODEM_SIGNAL_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_OMA_DBUS_SKELETON,
                                      MM_IFACE_MODEM_OMA_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_FIRMWARE_DBUS_SKELETON,
                                      MM_IFACE_MODEM_FIRMWARE_DBUS_SKELETON);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIM,
                                      MM_IFACE_MODEM_SIM);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_BEARER_LIST,
                                      MM_IFACE_MODEM_BEARER_LIST);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_STATE,
                                      MM_IFACE_MODEM_STATE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_REGISTRATION_STATE,
                                      MM_IFACE_MODEM_3GPP_REGISTRATION_STATE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_CS_NETWORK_SUPPORTED,
                                      MM_IFACE_MODEM_3GPP_CS_NETWORK_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_PS_NETWORK_SUPPORTED,
                                      MM_IFACE_MODEM_3GPP_PS_NETWORK_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_EPS_NETWORK_SUPPORTED,
                                      MM_IFACE_MODEM_3GPP_EPS_NETWORK_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_3GPP_IGNORED_FACILITY_LOCKS,
                                      MM_IFACE_MODEM_3GPP_IGNORED_FACILITY_LOCKS);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_CDMA_CDMA1X_REGISTRATION_STATE,
                                      MM_IFACE_MODEM_CDMA_CDMA1X_REGISTRATION_STATE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_CDMA_EVDO_REGISTRATION_STATE,
                                      MM_IFACE_MODEM_CDMA_EVDO_REGISTRATION_STATE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED,
                                      MM_IFACE_MODEM_CDMA_CDMA1X_NETWORK_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_CDMA_EVDO_NETWORK_SUPPORTED,
                                      MM_IFACE_MODEM_CDMA_EVDO_NETWORK_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_MESSAGING_SMS_LIST,
                                      MM_IFACE_MODEM_MESSAGING_SMS_LIST);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_VOICE_CALL_LIST,
                                      MM_IFACE_MODEM_VOICE_CALL_LIST);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_MESSAGING_SMS_PDU_MODE,
                                      MM_IFACE_MODEM_MESSAGING_SMS_PDU_MODE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_MESSAGING_SMS_DEFAULT_STORAGE,
                                      MM_IFACE_MODEM_MESSAGING_SMS_DEFAULT_STORAGE);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIMPLE_STATUS,
                                      MM_IFACE_MODEM_SIMPLE_STATUS);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIM_HOT_SWAP_SUPPORTED,
                                      MM_IFACE_MODEM_SIM_HOT_SWAP_SUPPORTED);

    g_object_class_override_property (object_class,
                                      PROP_MODEM_SIM_HOT_SWAP_CONFIGURED,
                                      MM_IFACE_MODEM_SIM_HOT_SWAP_CONFIGURED);
    properties[PROP_FLOW_CONTROL] =
        g_param_spec_flags (MM_BROADBAND_MODEM_FLOW_CONTROL,
                            "Flow control",
                            "Flow control settings to use in the connected TTY",
                            MM_TYPE_FLOW_CONTROL,
                            MM_FLOW_CONTROL_NONE,
                            G_PARAM_READABLE);
    g_object_class_install_property (object_class, PROP_FLOW_CONTROL, properties[PROP_FLOW_CONTROL]);
}
