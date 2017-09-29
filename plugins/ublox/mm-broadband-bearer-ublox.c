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
 * Copyright (C) 2016 Aleksander Morgado <aleksander@aleksander.es>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <ModemManager.h>
#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-broadband-bearer-ublox.h"
#include "mm-base-modem-at.h"
#include "mm-log.h"
#include "mm-ublox-enums-types.h"
#include "mm-modem-helpers.h"
#include "mm-modem-helpers-ublox.h"

G_DEFINE_TYPE (MMBroadbandBearerUblox, mm_broadband_bearer_ublox, MM_TYPE_BROADBAND_BEARER)

enum {
    PROP_0,
    PROP_USB_PROFILE,
    PROP_NETWORKING_MODE,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

typedef enum {
    FEATURE_SUPPORT_UNKNOWN,
    FEATURE_SUPPORTED,
    FEATURE_UNSUPPORTED,
} FeatureSupport;

struct _MMBroadbandBearerUbloxPrivate {
    MMUbloxUsbProfile        profile;
    MMUbloxNetworkingMode    mode;
    MMUbloxBearerAllowedAuth allowed_auths;
    FeatureSupport           statistics;
};

/*****************************************************************************/
/* Common connection context and task */

typedef struct {
    MMBroadbandBearerUblox *self;
    MMBroadbandModem       *modem;
    MMPortSerialAt         *primary;
    MMPort                 *data;
    guint                   cid;
    gboolean                auth_required;
    gboolean                secondary;
    guint                   secondary_i;
    /* For route settings */
    gchar                  *unquoted_apn;
    gchar                  *address;
    GList                  *apn_destinations;
    /* For IPv4 settings */
    MMBearerIpConfig       *ip_config;
} CommonConnectContext;

static void
common_connect_context_free (CommonConnectContext *ctx)
{
    g_list_free_full (ctx->apn_destinations, g_free);
    g_free (ctx->unquoted_apn);
    g_free (ctx->address);
    if (ctx->ip_config)
        g_object_unref (ctx->ip_config);
    if (ctx->data)
        g_object_unref (ctx->data);
    g_object_unref (ctx->self);
    g_object_unref (ctx->modem);
    g_object_unref (ctx->primary);
    g_slice_free (CommonConnectContext, ctx);
}

static GTask *
common_connect_task_new (MMBroadbandBearerUblox  *self,
                         MMBroadbandModem        *modem,
                         MMPortSerialAt          *primary,
                         guint                    cid,
                         gboolean                 secondary,
                         guint                    secondary_i,
                         MMPort                  *data,
                         GCancellable            *cancellable,
                         GAsyncReadyCallback      callback,
                         gpointer                 user_data)
{
    CommonConnectContext *ctx;
    GTask                *task;

    ctx = g_slice_new0 (CommonConnectContext);
    ctx->self        = g_object_ref (self);
    ctx->modem       = g_object_ref (modem);
    ctx->primary     = g_object_ref (primary);
    ctx->cid         = cid;
    ctx->secondary   = secondary;
    ctx->secondary_i = secondary_i;
    if (data)
        ctx->data = g_object_ref (data);

    if (!secondary)
        ctx->unquoted_apn = g_strdup (mm_bearer_properties_get_apn (mm_base_bearer_peek_config (MM_BASE_BEARER (self))));
    else
        ctx->unquoted_apn = g_strdup (mm_bearer_properties_get_secondary_apn (mm_base_bearer_peek_config (MM_BASE_BEARER (self)), ctx->secondary_i));

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify) common_connect_context_free);

    return task;
}

/*****************************************************************************/
/* 3GPP IP config (sub-step of the 3GPP Connection sequence) */

static gboolean
get_ip_config_3gpp_finish (MMBroadbandBearer *self,
                           GAsyncResult      *res,
                           MMBearerIpConfig **ipv4_config,
                           MMBearerIpConfig **ipv6_config,
                           GError           **error)
{
    MMBearerConnectResult *configs;
    MMBearerIpConfig *ipv4;

    configs = g_task_propagate_pointer (G_TASK (res), error);
    if (!configs)
        return FALSE;

    /* Just IPv4 for now */
    ipv4 = mm_bearer_connect_result_peek_ipv4_config (configs);
    g_assert (ipv4);
    if (ipv4_config)
        *ipv4_config = g_object_ref (ipv4);
    if (ipv6_config)
        *ipv6_config = NULL;
    mm_bearer_connect_result_unref (configs);
    return TRUE;
}

static void
complete_get_ip_config_3gpp (GTask *task)
{
    CommonConnectContext *ctx;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);
    g_assert (mm_bearer_ip_config_get_method (ctx->ip_config) != MM_BEARER_IP_METHOD_UNKNOWN);
    g_task_return_pointer (task,
                           mm_bearer_connect_result_new (ctx->data, ctx->ip_config, NULL),
                           (GDestroyNotify) mm_bearer_connect_result_unref);
    g_object_unref (task);
}

static void
cgcontrdp_ready (MMBaseModem  *modem,
                 GAsyncResult *res,
                 GTask        *task)
{
    const gchar          *response;
    GError               *error = NULL;
    CommonConnectContext *ctx;
    gchar                *local_address = NULL;
    gchar                *subnet = NULL;
    gchar                *dns_addresses[3] = { NULL, NULL, NULL };

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response || !mm_3gpp_parse_cgcontrdp_response (response,
                                                        NULL, /* cid */
                                                        NULL, /* bearer id */
                                                        NULL, /* apn */
                                                        &local_address,
                                                        &subnet,
                                                        NULL, /* gateway_address */
                                                        &dns_addresses[0],
                                                        &dns_addresses[1],
                                                        &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    mm_dbg ("IPv4 address retrieved: %s", local_address);
    mm_bearer_ip_config_set_address (ctx->ip_config, local_address);
    mm_dbg ("IPv4 subnet retrieved: %s", subnet);
    mm_bearer_ip_config_set_prefix (ctx->ip_config, mm_netmask_to_cidr (subnet));
    if (dns_addresses[0])
        mm_dbg ("Primary DNS retrieved: %s", dns_addresses[0]);
    if (dns_addresses[1])
        mm_dbg ("Secondary DNS retrieved: %s", dns_addresses[1]);
    mm_bearer_ip_config_set_dns (ctx->ip_config, (const gchar **) dns_addresses);

    g_free (local_address);
    g_free (subnet);
    g_free (dns_addresses[0]);
    g_free (dns_addresses[1]);

    mm_dbg ("finished IP settings retrieval for PDP context #%u...", ctx->cid);

    complete_get_ip_config_3gpp (task);
}

static void
uipaddr_ready (MMBaseModem  *modem,
               GAsyncResult *res,
               GTask        *task)
{
    const gchar          *response;
    gchar                *cmd;
    GError               *error = NULL;
    CommonConnectContext *ctx;
    gchar                *gw_ipv4_address = NULL;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response || !mm_ublox_parse_uipaddr_response (response,
                                                       NULL, /* cid */
                                                       NULL, /* if_name */
                                                       &gw_ipv4_address,
                                                       NULL, /* ipv4_subnet */
                                                       NULL, /* ipv6_global_address */
                                                       NULL, /* ipv6_link_local_address */
                                                       &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    mm_dbg ("IPv4 gateway address retrieved: %s", gw_ipv4_address);
    mm_bearer_ip_config_set_gateway (ctx->ip_config, gw_ipv4_address);
    g_free (gw_ipv4_address);

    cmd = g_strdup_printf ("+CGCONTRDP=%u", ctx->cid);
    mm_dbg ("gathering IP and DNS information for PDP context #%u...", ctx->cid);
    mm_base_modem_at_command (MM_BASE_MODEM (modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) cgcontrdp_ready,
                              task);
    g_free (cmd);
}

static void
get_ip_config_3gpp (MMBroadbandBearer   *self,
                    MMBroadbandModem    *modem,
                    MMPortSerialAt      *primary,
                    MMPortSerialAt      *secondary,
                    MMPort              *data,
                    guint                cid,
                    MMBearerIpFamily     ip_family,
                    GAsyncReadyCallback  callback,
                    gpointer             user_data)
{
    GTask                *task;
    CommonConnectContext *ctx;

    if (!(task = common_connect_task_new (MM_BROADBAND_BEARER_UBLOX (self),
                                          MM_BROADBAND_MODEM (modem),
                                          primary,
                                          cid,
                                          FALSE, 0, /* unused */
                                          data,
                                          NULL,
                                          callback,
                                          user_data)))
        return;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);
    ctx->ip_config = mm_bearer_ip_config_new ();

    /* If we're in BRIDGE mode, we need to ask for static IP addressing details:
     *  - AT+UIPADDR=[CID] will give us the default gateway address.
     *  - +CGCONTRDP?[CID] will give us the IP address, subnet and DNS addresses.
     */
    if (ctx->self->priv->mode == MM_UBLOX_NETWORKING_MODE_BRIDGE) {
        gchar *cmd;

        mm_bearer_ip_config_set_method (ctx->ip_config, MM_BEARER_IP_METHOD_STATIC);

        cmd = g_strdup_printf ("+UIPADDR=%u", cid);
        mm_dbg ("gathering gateway information for PDP context #%u...", cid);
        mm_base_modem_at_command (MM_BASE_MODEM (modem),
                                  cmd,
                                  10,
                                  FALSE,
                                  (GAsyncReadyCallback) uipaddr_ready,
                                  task);
        g_free (cmd);
        return;
    }

    /* If we're in ROUTER networking mode, we just need to request DHCP on the
     * network interface. Early return with that result. */
    if (ctx->self->priv->mode == MM_UBLOX_NETWORKING_MODE_ROUTER) {
        mm_bearer_ip_config_set_method (ctx->ip_config, MM_BEARER_IP_METHOD_DHCP);
        complete_get_ip_config_3gpp (task);
        return;
    }

    g_assert_not_reached ();
}

/*****************************************************************************/
/* 3GPP Dialing (sub-step of the 3GPP Connection sequence) */

static MMPort *
dial_3gpp_finish (MMBroadbandBearer  *self,
                  GAsyncResult       *res,
                  GError           **error)
{
    return MM_PORT (g_task_propagate_pointer (G_TASK (res), error));
}

static gboolean
dial_secondary_3gpp_finish (MMBroadbandBearer  *self,
                            GAsyncResult       *res,
                            GError           **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
complete_connected (GTask *task)
{
    CommonConnectContext *ctx;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    if (!ctx->secondary)
        /* primary context */
        g_task_return_pointer (task, g_object_ref (ctx->data), g_object_unref);
    else
        /* secondary context */
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void uiproute_add_destination (GTask *task);

static void
uiproute_add_destination_ready (MMBaseModem  *modem,
                                GAsyncResult *res,
                                GTask        *task)
{
    GError               *error = NULL;
    CommonConnectContext *ctx;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    if (!mm_base_modem_at_command_finish (modem, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    uiproute_add_destination (task);
}

static void
uiproute_add_destination (GTask *task)
{
    CommonConnectContext *ctx;
    gchar                *cmd;
    gchar                *next_destination;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    if (!ctx->apn_destinations) {
        complete_connected (task);
        return;
    }

    next_destination = ctx->apn_destinations->data;
    ctx->apn_destinations = g_list_delete_link (ctx->apn_destinations, ctx->apn_destinations);

    /* Add destination route */
    mm_dbg ("Adding default route for destination %s...", next_destination);
    g_assert (ctx->cid >= 1);
    cmd = g_strdup_printf ("+UIPROUTE=\"add -host %s gw %s netmask 0.0.0.0 dev inm%u\"",
                           next_destination, ctx->address, ctx->cid - 1);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) uiproute_add_destination_ready,
                              task);
    g_free (cmd);
    g_free (next_destination);
}

static void
uiproute_del_default_ready (MMBaseModem  *modem,
                            GAsyncResult *res,
                            GTask        *task)
{
    GError               *error = NULL;
    CommonConnectContext *ctx;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    if (!mm_base_modem_at_command_finish (modem, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    uiproute_add_destination (task);
}

static void
uiproute_del_default (GTask *task)
{
    CommonConnectContext *ctx;
    gchar                *cmd;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    mm_dbg ("Removing default route through %s...", ctx->address);
    g_assert (ctx->cid >= 1);
    cmd = g_strdup_printf ("+UIPROUTE=\"del -net default gw %s netmask 0.0.0.0 dev inm%u\"", ctx->address, ctx->cid - 1);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) uiproute_del_default_ready,
                              task);
    g_free (cmd);
}


static void
uiproute_ready (MMBaseModem  *modem,
                GAsyncResult *res,
                GTask        *task)
{
    const gchar          *response;
    GError               *error = NULL;
    CommonConnectContext *ctx;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    if (!mm_ublox_parse_uiproute_response_find_default_route_for_ipaddr (response, ctx->address, &error)) {
        mm_dbg ("Couldn't find default route: %s", error->message);
        g_free (error);
        /* Try to add destination right away */
        uiproute_add_destination (task);
        return;
    }

    uiproute_del_default (task);
}

static void
cgpaddr_ready (MMBaseModem  *modem,
               GAsyncResult *res,
               GTask        *task)
{
    const gchar          *response;
    GError               *error = NULL;
    CommonConnectContext *ctx;
    GList                *pdp_addresses;
    GList                *l;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    pdp_addresses = mm_3gpp_parse_cgpaddr_exec_response (response, &error);
    if (!pdp_addresses) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    for (l = pdp_addresses; !ctx->address && l; l = g_list_next (l)) {
        const MM3gppPdpContextAddress *item;

        item = l->data;
        if (ctx->cid == item->cid) {
            mm_dbg ("IP address for PDP context %u found: %s", ctx->cid, item->address);
            ctx->address = g_strdup (item->address);
        }
    }

    mm_3gpp_pdp_context_address_list_free (pdp_addresses);

    if (!ctx->address) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_FAILED,
                                 "No IP address specified for PDP context %u", ctx->cid);
        g_object_unref (task);
        return;
    }

    mm_dbg ("querying current routes...");
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              "+UIPROUTE?",
                              10,
                              FALSE,
                              (GAsyncReadyCallback) uiproute_ready,
                              task);
}

static void
cgact_activate_ready (MMBaseModem  *modem,
                      GAsyncResult *res,
                      GTask        *task)
{
    const gchar          *response;
    GError               *error = NULL;
    CommonConnectContext *ctx;
    gchar                *cmd;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    ctx->apn_destinations = mm_ublox_get_apn_destinations (ctx->unquoted_apn, &error);
    if (error) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    /* If there are no custom APN destinations, then we're just fine with the
     * default route generated */
    if (!ctx->apn_destinations) {
        complete_connected (task);
        return;
    }

    mm_dbg ("querying PDP context %u IP address...", ctx->cid);
    cmd = g_strdup_printf ("+CGPADDR=%u", ctx->cid);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) cgpaddr_ready,
                              task);
    g_free (cmd);
}

static void
activate_3gpp (GTask *task)
{
    CommonConnectContext *ctx;
    gchar                *cmd;

    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    cmd = g_strdup_printf ("+CGACT=1,%u", ctx->cid);
    mm_dbg ("activating PDP context #%u...", ctx->cid);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              120,
                              FALSE,
                              (GAsyncReadyCallback) cgact_activate_ready,
                              task);
    g_free (cmd);
}

static void
cgdcont_again_ready (MMBaseModem  *modem,
                     GAsyncResult *res,
                     GTask        *task)
{
    GError *error = NULL;

    if (!mm_base_modem_at_command_finish (modem, res, &error)) {
        CommonConnectContext *ctx;

        ctx = (CommonConnectContext *) g_task_get_task_data (task);
        /* If authentication required and the +UAUTHREQ failed, abort */
        if (ctx->auth_required) {
            g_task_return_error (task, error);
            g_object_unref (task);
            return;
        }
        /* Otherwise, ignore */
        g_error_free (error);
    }

    activate_3gpp (task);
}

static void
uauthreq_ready (MMBaseModem  *modem,
                GAsyncResult *res,
                GTask        *task)
{
    MMBroadbandBearerUblox *self;
    const gchar            *response;
    GError                 *error = NULL;
    gchar                  *cmd;
    const gchar            *pdp_type;
    gchar                  *apn;
    MMBearerIpFamily        ip_family;
    CommonConnectContext   *ctx;

    self = g_task_get_source_object (task);
    ctx  = g_task_get_task_data (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response) {
        /* If authentication required and the +UAUTHREQ failed, abort */
        if (ctx->auth_required) {
            g_task_return_error (task, error);
            g_object_unref (task);
            return;
        }
        /* Otherwise, ignore */
        g_error_free (error);
    }

    /* TOBY-L4 engineering releases (<= 40-16) have a bug where the PDP context
     * must be re-defined after configuring authentication, so just repeat the
     * CGDCONT command now */
    ip_family = mm_broadband_bearer_get_3gpp_ip_family (MM_BROADBAND_BEARER (self));
    pdp_type = mm_3gpp_get_pdp_type_from_ip_family (ip_family);
    if (!pdp_type) {
        gchar * str;

        str = mm_bearer_ip_family_build_string_from_mask (ip_family);
        g_task_return_new_error (task,
                                 MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                                 "Unsupported IP type requested: '%s'", str);
        g_object_unref (task);
        g_free (str);
        return;
    }

    apn = mm_port_serial_at_quote_string (ctx->unquoted_apn);
    cmd = g_strdup_printf ("+CGDCONT=%u,\"%s\",%s",
                           ctx->cid, pdp_type, apn);
    g_free (apn);

    mm_dbg ("re-sending PDP context %u setup...", ctx->cid);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) cgdcont_again_ready,
                              task);
    g_free (cmd);
}

static void
authenticate_3gpp (GTask *task)
{
    MMBroadbandBearerUblox *self;
    CommonConnectContext   *ctx;
    gchar                  *cmd = NULL;
    MMBearerAllowedAuth     allowed_auth;
    gint                    ublox_auth = -1;

    self = g_task_get_source_object (task);
    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    allowed_auth = mm_bearer_properties_get_allowed_auth (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));

    if (!ctx->auth_required) {
        mm_dbg ("Not using authentication");
        ublox_auth = 0;
        goto out;
    }

    if (allowed_auth == MM_BEARER_ALLOWED_AUTH_UNKNOWN || allowed_auth == (MM_BEARER_ALLOWED_AUTH_PAP | MM_BEARER_ALLOWED_AUTH_CHAP)) {
        mm_dbg ("Using automatic authentication method");
        if (self->priv->allowed_auths & MM_UBLOX_BEARER_ALLOWED_AUTH_AUTO)
            ublox_auth = 3;
        else if (self->priv->allowed_auths & MM_UBLOX_BEARER_ALLOWED_AUTH_PAP)
            ublox_auth = 1;
        else if (self->priv->allowed_auths & MM_UBLOX_BEARER_ALLOWED_AUTH_CHAP)
            ublox_auth = 2;
        else if (self->priv->allowed_auths & MM_UBLOX_BEARER_ALLOWED_AUTH_NONE)
            ublox_auth = 0;
    } else if (allowed_auth & MM_BEARER_ALLOWED_AUTH_PAP) {
        mm_dbg ("Using PAP authentication method");
        ublox_auth = 1;
    } else if (allowed_auth & MM_BEARER_ALLOWED_AUTH_CHAP) {
        mm_dbg ("Using CHAP authentication method");
        ublox_auth = 2;
    }

out:

    if (ublox_auth < 0) {
        gchar *str;

        str = mm_bearer_allowed_auth_build_string_from_mask (allowed_auth);
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
                                 "Cannot use any of the specified authentication methods (%s)", str);
        g_object_unref (task);
        g_free (str);
        return;
    }

    if (ublox_auth > 0) {
        const gchar *user;
        const gchar *password;
        gchar       *quoted_user;
        gchar       *quoted_password;

        if (!ctx->secondary) {
            user     = mm_bearer_properties_get_user     (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));
            password = mm_bearer_properties_get_password (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));
        } else {
            user     = mm_bearer_properties_get_secondary_user     (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)), ctx->secondary_i);
            password = mm_bearer_properties_get_secondary_password (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)), ctx->secondary_i);
        }

        quoted_user     = mm_port_serial_at_quote_string (user);
        quoted_password = mm_port_serial_at_quote_string (password);

        cmd = g_strdup_printf ("+UAUTHREQ=%u,%u,%s,%s",
                               ctx->cid,
                               ublox_auth,
                               quoted_password,
                               quoted_user);

        g_free (quoted_user);
        g_free (quoted_password);
    } else
        cmd = g_strdup_printf ("+UAUTHREQ=%u,0", ctx->cid);

    mm_dbg ("setting up authentication preferences in PDP context #%u...", ctx->cid);
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              cmd,
                              10,
                              FALSE,
                              (GAsyncReadyCallback) uauthreq_ready,
                              task);
    g_free (cmd);
}

static void
uauthreq_test_ready (MMBaseModem  *modem,
                     GAsyncResult *res,
                     GTask        *task)
{
    MMBroadbandBearerUblox *self;
    const gchar            *response;
    GError                 *error = NULL;

    self = g_task_get_source_object (task);

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response)
        goto out;

    self->priv->allowed_auths = mm_ublox_parse_uauthreq_test (response, &error);
out:
    if (error) {
        CommonConnectContext *ctx;

        ctx = (CommonConnectContext *) g_task_get_task_data (task);
        /* If authentication required and the +UAUTHREQ test failed, abort */
        if (ctx->auth_required) {
            g_task_return_error (task, error);
            g_object_unref (task);
            return;
        }
        /* Otherwise, ignore and jump to activate_3gpp directly as no auth setup
         * is needed */
        g_error_free (error);
        activate_3gpp (task);
        return;
    }

    authenticate_3gpp (task);
}

static void
check_supported_authentication_methods (GTask *task)
{
    MMBroadbandBearerUblox *self;
    CommonConnectContext   *ctx;
    const gchar            *user;
    const gchar            *password;
    MMBearerAllowedAuth     allowed_auth;

    self = g_task_get_source_object (task);
    ctx = (CommonConnectContext *) g_task_get_task_data (task);

    allowed_auth = mm_bearer_properties_get_allowed_auth (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));
    if (!ctx->secondary) {
        user     = mm_bearer_properties_get_user     (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));
        password = mm_bearer_properties_get_password (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)));
    } else {
        user     = mm_bearer_properties_get_secondary_user     (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)), ctx->secondary_i);
        password = mm_bearer_properties_get_secondary_password (mm_base_bearer_peek_config (MM_BASE_BEARER (ctx->self)), ctx->secondary_i);
    }

    /* Flag whether authentication is required. If it isn't, we won't fail
     * connection attempt if the +UAUTHREQ command fails */
    ctx->auth_required = (user && password && allowed_auth != MM_BEARER_ALLOWED_AUTH_NONE);

    /* If we already cached the support, not do it again */
    if (self->priv->allowed_auths != MM_UBLOX_BEARER_ALLOWED_AUTH_UNKNOWN) {
        authenticate_3gpp (task);
        return;
    }

    mm_dbg ("checking supported authentication methods...");
    mm_base_modem_at_command (MM_BASE_MODEM (ctx->modem),
                              "+UAUTHREQ=?",
                              10,
                              TRUE, /* allow cached */
                              (GAsyncReadyCallback) uauthreq_test_ready,
                              task);
}

static void
dial_3gpp (MMBroadbandBearer   *self,
           MMBaseModem         *modem,
           MMPortSerialAt      *primary,
           guint                cid,
           GCancellable        *cancellable,
           GAsyncReadyCallback  callback,
           gpointer             user_data)
{
    GTask                *task;
    CommonConnectContext *ctx;

    task = common_connect_task_new (MM_BROADBAND_BEARER_UBLOX (self),
                                    MM_BROADBAND_MODEM (modem),
                                    primary,
                                    cid,
                                    FALSE,
                                    0,
                                    NULL,
                                    cancellable,
                                    callback,
                                    user_data);

    /* Data port mandatory in primary context */
    ctx = g_task_get_task_data (task);
    ctx->data = mm_base_modem_get_best_data_port (MM_BASE_MODEM (modem), MM_PORT_TYPE_NET);
    if (!ctx->data) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_NOT_FOUND,
                                 "No valid data port found to launch connection");
        g_object_unref (task);
        return;
    }

    check_supported_authentication_methods (task);
}

static void
dial_secondary_3gpp (MMBroadbandBearer   *self,
                     MMBaseModem         *modem,
                     MMPortSerialAt      *primary,
                     guint                cid,
                     guint                secondary_i,
                     GCancellable        *cancellable,
                     GAsyncReadyCallback  callback,
                     gpointer             user_data)
{
    GTask *task;

    task = common_connect_task_new (MM_BROADBAND_BEARER_UBLOX (self),
                                    MM_BROADBAND_MODEM (modem),
                                    primary,
                                    cid,
                                    TRUE,
                                    secondary_i,
                                    NULL,
                                    cancellable,
                                    callback,
                                    user_data);

    /* Data port NOT set in secondary context */

    check_supported_authentication_methods (task);
}

/*****************************************************************************/
/* 3GPP disconnection */

static gboolean
disconnect_3gpp_finish (MMBroadbandBearer  *self,
                        GAsyncResult       *res,
                        GError            **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
cgact_deactivate_ready (MMBaseModem  *modem,
                        GAsyncResult *res,
                        GTask        *task)
{
    const gchar *response;
    GError      *error = NULL;

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response)
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
disconnect_3gpp  (MMBroadbandBearer   *self,
                  MMBroadbandModem    *modem,
                  MMPortSerialAt      *primary,
                  MMPortSerialAt      *secondary,
                  MMPort              *data,
                  guint                cid,
                  GAsyncReadyCallback  callback,
                  gpointer             user_data)
{
    GTask *task;
    gchar *cmd;

    if (!(task = common_connect_task_new (MM_BROADBAND_BEARER_UBLOX (self),
                                          MM_BROADBAND_MODEM (modem),
                                          primary,
                                          cid,
                                          FALSE, 0, /* unused */
                                          data,
                                          NULL,
                                          callback,
                                          user_data)))
        return;

    cmd = g_strdup_printf ("+CGACT=0,%u", cid);
    mm_dbg ("deactivating PDP context #%u...", cid);
    mm_base_modem_at_command (MM_BASE_MODEM (modem),
                              cmd,
                              120,
                              FALSE,
                              (GAsyncReadyCallback) cgact_deactivate_ready,
                              task);
    g_free (cmd);
}

/*****************************************************************************/
/* Reload statistics */

typedef struct {
    guint64 bytes_rx;
    guint64 bytes_tx;
} StatsResult;

static gboolean
reload_stats_finish (MMBaseBearer  *self,
                     guint64       *bytes_rx,
                     guint64       *bytes_tx,
                     GAsyncResult  *res,
                     GError       **error)
{
    StatsResult *result;

    result = g_task_propagate_pointer (G_TASK (res), error);
    if (!result)
        return FALSE;

    if (bytes_rx)
        *bytes_rx = result->bytes_rx;
    if (bytes_tx)
        *bytes_tx = result->bytes_tx;
    g_free (result);
    return TRUE;
}

static void
ugcntrd_ready (MMBaseModem  *modem,
               GAsyncResult *res,
               GTask        *task)
{
    MMBroadbandBearerUblox *self;
    const gchar            *response;
    GError                 *error = NULL;
    guint                   tx_bytes = 0;
    guint                   rx_bytes = 0;
    guint                   total_tx_bytes = 0;
    guint                   total_rx_bytes = 0;
    guint                   cid;
    guint                   i, n;
    StatsResult            *result;

    self = MM_BROADBAND_BEARER_UBLOX (g_task_get_source_object (task));

    response = mm_base_modem_at_command_finish (modem, res, &error);
    if (!response) {
        g_prefix_error (&error, "Couldn't load PDP context statistics: ");
        g_task_return_error (task, error);
        g_object_unref  (task);
        return;
    }

    cid = mm_broadband_bearer_get_3gpp_cid (MM_BROADBAND_BEARER (self));
    if (!mm_ublox_parse_ugcntrd_response_for_cid (response,
                                                  cid,
                                                  &total_tx_bytes, &total_rx_bytes,
                                                  NULL, NULL,
                                                  &error)) {
        g_prefix_error (&error, "Couldn't load primary PDP context %u statistics: ", cid);
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    mm_dbg ("Primary context (cid %u) statistics: tx %u bytes, rx %u bytes", cid, total_tx_bytes, total_rx_bytes);

    n = mm_bearer_properties_get_n_secondary (mm_base_bearer_peek_config (MM_BASE_BEARER (self)));
    for (i = 0; i < n; i++) {
        cid = mm_broadband_bearer_get_3gpp_secondary_cid (MM_BROADBAND_BEARER (self), i);
        if (!mm_ublox_parse_ugcntrd_response_for_cid (response,
                                                      cid,
                                                      &tx_bytes, &rx_bytes,
                                                      NULL, NULL,
                                                      NULL)) {
            mm_dbg ("Couldn't load statistics for secondary context (cid %u)", cid);
            continue;
        }

        mm_dbg ("Secondary context (cid %u) statistics: tx %u bytes, rx %u bytes", cid, tx_bytes, rx_bytes);

        total_tx_bytes += tx_bytes;
        total_rx_bytes += rx_bytes;
    }

    mm_dbg ("Total context statistics: tx %u bytes, rx %u bytes", total_tx_bytes, total_rx_bytes);

    result = g_new (StatsResult, 1);
    result->bytes_rx = total_rx_bytes;
    result->bytes_tx = total_tx_bytes;
    g_task_return_pointer (task, result, g_free);
    g_object_unref (task);
}

static void
run_reload_stats (MMBroadbandBearerUblox *self,
                  GTask                  *task)
{
    /* Unsupported? */
    if (self->priv->statistics == FEATURE_UNSUPPORTED) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
                                 "Loading statistics isn't supported by this device");
        g_object_unref (task);
        return;
    }

    /* Supported */
    if (self->priv->statistics == FEATURE_SUPPORTED) {
        MMBaseModem *modem = NULL;

        g_object_get (MM_BASE_BEARER (self),
                      MM_BASE_BEARER_MODEM, &modem,
                      NULL);
        mm_base_modem_at_command (MM_BASE_MODEM (modem),
                                  "+UGCNTRD",
                                  3,
                                  FALSE,
                                  (GAsyncReadyCallback) ugcntrd_ready,
                                  task);
        g_object_unref (modem);
        return;
    }

    g_assert_not_reached ();
}

static void
ugcntrd_test_ready (MMBaseModem  *modem,
                    GAsyncResult *res,
                    GTask        *task)
{
    MMBroadbandBearerUblox *self;

    self = MM_BROADBAND_BEARER_UBLOX (g_task_get_source_object (task));

    if (!mm_base_modem_at_command_finish (modem, res, NULL))
        self->priv->statistics = FEATURE_UNSUPPORTED;
    else
        self->priv->statistics = FEATURE_SUPPORTED;

    run_reload_stats (self, task);
}

static void
reload_stats (MMBaseBearer        *self,
              GAsyncReadyCallback  callback,
              gpointer             user_data)
{
    GTask *task;

    task = g_task_new (self, NULL, callback, user_data);

    if (MM_BROADBAND_BEARER_UBLOX (self)->priv->statistics == FEATURE_SUPPORT_UNKNOWN) {
        MMBaseModem *modem = NULL;

        g_object_get (MM_BASE_BEARER (self),
                      MM_BASE_BEARER_MODEM, &modem,
                      NULL);

        mm_base_modem_at_command (MM_BASE_MODEM (modem),
                                  "+UGCNTRD=?",
                                  3,
                                  FALSE,
                                  (GAsyncReadyCallback) ugcntrd_test_ready,
                                  task);
        g_object_unref (modem);
        return;
    }

    run_reload_stats (MM_BROADBAND_BEARER_UBLOX (self), task);
}

/*****************************************************************************/

MMBaseBearer *
mm_broadband_bearer_ublox_new_finish (GAsyncResult  *res,
                                      GError       **error)
{
    GObject *source;
    GObject *bearer;

    source = g_async_result_get_source_object (res);
    bearer = g_async_initable_new_finish (G_ASYNC_INITABLE (source), res, error);
    g_object_unref (source);

    if (!bearer)
        return NULL;

    /* Only export valid bearers */
    mm_base_bearer_export (MM_BASE_BEARER (bearer));

    return MM_BASE_BEARER (bearer);
}

void
mm_broadband_bearer_ublox_new (MMBroadbandModem      *modem,
                               MMUbloxUsbProfile      profile,
                               MMUbloxNetworkingMode  mode,
                               MMBearerProperties    *config,
                               GCancellable          *cancellable,
                               GAsyncReadyCallback    callback,
                               gpointer               user_data)
{
    g_assert (mode == MM_UBLOX_NETWORKING_MODE_ROUTER || mode == MM_UBLOX_NETWORKING_MODE_BRIDGE);

    g_async_initable_new_async (
        MM_TYPE_BROADBAND_BEARER_UBLOX,
        G_PRIORITY_DEFAULT,
        cancellable,
        callback,
        user_data,
        MM_BASE_BEARER_MODEM, modem,
        MM_BASE_BEARER_CONFIG, config,
        MM_BROADBAND_BEARER_UBLOX_USB_PROFILE, profile,
        MM_BROADBAND_BEARER_UBLOX_NETWORKING_MODE, mode,
        NULL);
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
    MMBroadbandBearerUblox *self = MM_BROADBAND_BEARER_UBLOX (object);

    switch (prop_id) {
    case PROP_USB_PROFILE:
        self->priv->profile = g_value_get_enum (value);
        break;
    case PROP_NETWORKING_MODE:
        self->priv->mode = g_value_get_enum (value);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
get_property (GObject    *object,
              guint       prop_id,
              GValue     *value,
              GParamSpec *pspec)
{
    MMBroadbandBearerUblox *self = MM_BROADBAND_BEARER_UBLOX (object);

    switch (prop_id) {
    case PROP_USB_PROFILE:
        g_value_set_enum (value, self->priv->profile);
        break;
    case PROP_NETWORKING_MODE:
        g_value_set_enum (value, self->priv->mode);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
mm_broadband_bearer_ublox_init (MMBroadbandBearerUblox *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_BROADBAND_BEARER_UBLOX,
                                              MMBroadbandBearerUbloxPrivate);

    /* Defaults */
    self->priv->profile       = MM_UBLOX_USB_PROFILE_UNKNOWN;
    self->priv->mode          = MM_UBLOX_NETWORKING_MODE_UNKNOWN;
    self->priv->allowed_auths = MM_UBLOX_BEARER_ALLOWED_AUTH_UNKNOWN;
    self->priv->statistics    = FEATURE_SUPPORT_UNKNOWN;
}

static void
mm_broadband_bearer_ublox_class_init (MMBroadbandBearerUbloxClass *klass)
{
    GObjectClass           *object_class           = G_OBJECT_CLASS (klass);
    MMBaseBearerClass      *base_bearer_class      = MM_BASE_BEARER_CLASS (klass);
    MMBroadbandBearerClass *broadband_bearer_class = MM_BROADBAND_BEARER_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMBroadbandBearerUbloxPrivate));

    object_class->get_property = get_property;
    object_class->set_property = set_property;

    /* Note: the ublox plugin uses the generic AT+CGACT? based check to monitor
     * the connection status (i.e. default load_connection_status()) */
    base_bearer_class->reload_stats = reload_stats;
    base_bearer_class->reload_stats_finish = reload_stats_finish;

    broadband_bearer_class->disconnect_3gpp = disconnect_3gpp;
    broadband_bearer_class->disconnect_3gpp_finish = disconnect_3gpp_finish;
    broadband_bearer_class->dial_3gpp = dial_3gpp;
    broadband_bearer_class->dial_3gpp_finish = dial_3gpp_finish;
    broadband_bearer_class->dial_secondary_3gpp = dial_secondary_3gpp;
    broadband_bearer_class->dial_secondary_3gpp_finish = dial_secondary_3gpp_finish;
    broadband_bearer_class->get_ip_config_3gpp = get_ip_config_3gpp;
    broadband_bearer_class->get_ip_config_3gpp_finish = get_ip_config_3gpp_finish;

    properties[PROP_USB_PROFILE] =
        g_param_spec_enum (MM_BROADBAND_BEARER_UBLOX_USB_PROFILE,
                           "USB profile",
                           "USB profile in use",
                           MM_TYPE_UBLOX_USB_PROFILE,
                           MM_UBLOX_USB_PROFILE_UNKNOWN,
                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_USB_PROFILE, properties[PROP_USB_PROFILE]);

    properties[PROP_NETWORKING_MODE] =
        g_param_spec_enum (MM_BROADBAND_BEARER_UBLOX_NETWORKING_MODE,
                           "Networking mode",
                           "Networking mode in use",
                           MM_TYPE_UBLOX_NETWORKING_MODE,
                           MM_UBLOX_NETWORKING_MODE_UNKNOWN,
                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_NETWORKING_MODE, properties[PROP_NETWORKING_MODE]);
}
