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
 * Copyright (C) 2008 - 2010 Ericsson AB
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 * Copyright (C) 2012 Lanedo GmbH
 * Copyright (C) 2017 Aleksander Morgado <aleksander@aleksander.es>
 *
 * Author: Per Hallsmark <per.hallsmark@ericsson.com>
 *         Bjorn Runaker <bjorn.runaker@ericsson.com>
 *         Torgny Johansson <torgny.johansson@ericsson.com>
 *         Jonas Sjöquist <jonas.sjoquist@ericsson.com>
 *         Dan Williams <dcbw@redhat.com>
 *         Aleksander Morgado <aleksander@aleksander.es>
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

#include "mm-base-modem-at.h"
#include "mm-broadband-bearer-mbm.h"
#include "mm-log.h"
#include "mm-modem-helpers.h"
#include "mm-modem-helpers-mbm.h"
#include "mm-daemon-enums-types.h"

G_DEFINE_TYPE (MMBroadbandBearerMbm, mm_broadband_bearer_mbm, MM_TYPE_BROADBAND_BEARER)

struct _MMBroadbandBearerMbmPrivate {
    GTask *connect_pending;
    GTask *disconnect_pending;
};

/*****************************************************************************/
/* 3GPP Dialing (sub-step of the 3GPP Connection sequence) */

typedef struct {
    MMBaseModem    *modem;
    MMPortSerialAt *primary;
    guint           cid;
    MMPort         *data;
    guint           poll_count;
    guint           poll_id;
    GError         *saved_error;
} Dial3gppContext;

static void
dial_3gpp_context_free (Dial3gppContext *ctx)
{
    g_assert (!ctx->poll_id);
    g_assert (!ctx->saved_error);
    g_clear_object (&ctx->data);
    g_clear_object (&ctx->primary);
    g_clear_object (&ctx->modem);
    g_slice_free (Dial3gppContext, ctx);
}

static MMPort *
dial_3gpp_finish (MMBroadbandBearer  *self,
                  GAsyncResult       *res,
                  GError            **error)
{
    return MM_PORT (g_task_propagate_pointer (G_TASK (res), error));
}

static void
connect_reset_ready (MMBroadbandBearer *self,
                     GAsyncResult      *res,
                     GTask             *task)
{
    Dial3gppContext *ctx;

    ctx = g_task_get_task_data (task);

    MM_BROADBAND_BEARER_GET_CLASS (self)->disconnect_3gpp_finish (self, res, NULL);

    /* When reset is requested, it was either cancelled or an error was stored */
    if (!g_task_return_error_if_cancelled (task)) {
        g_assert (ctx->saved_error);
        g_task_return_error (task, ctx->saved_error);
        ctx->saved_error = NULL;
    }

    g_object_unref (task);
}

static void
connect_reset (GTask *task)
{
    MMBroadbandBearerMbm *self;
    Dial3gppContext      *ctx;

    self = g_task_get_source_object (task);
    ctx  = g_task_get_task_data     (task);

    MM_BROADBAND_BEARER_GET_CLASS (self)->disconnect_3gpp (
        MM_BROADBAND_BEARER (self),
        MM_BROADBAND_MODEM (ctx->modem),
        ctx->primary,
        NULL,
        ctx->data,
        ctx->cid,
        (GAsyncReadyCallback) connect_reset_ready,
        task);
}

static void
process_pending_connect_attempt (MMBroadbandBearerMbm     *self,
                                 MMBearerConnectionStatus  status)
{
    GTask           *task;
    Dial3gppContext *ctx;

    /* Recover connection task */
    task = self->priv->connect_pending;
    self->priv->connect_pending = NULL;
    g_assert (task != NULL);

    ctx = g_task_get_task_data (task);

    if (ctx->poll_id) {
        g_source_remove (ctx->poll_id);
        ctx->poll_id = 0;
    }

    /* Received 'CONNECTED' during a connection attempt? */
    if (status == MM_BEARER_CONNECTION_STATUS_CONNECTED) {
        /* If we wanted to get cancelled before, do it now. */
        if (g_cancellable_is_cancelled (g_task_get_cancellable (task))) {
            connect_reset (task);
            return;
        }

        g_task_return_pointer (task, g_object_ref (ctx->data), g_object_unref);
        g_object_unref (task);
        return;
    }

    /* If we wanted to get cancelled before and now we couldn't connect,
     * use the cancelled error and return */
    if (g_task_return_error_if_cancelled (task)) {
        g_object_unref (task);
        return;
    }

    /* Otherwise, received 'DISCONNECTED' during a connection attempt? */
    g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_FAILED, "Call setup failed");
    g_object_unref (task);
}

static gboolean connect_poll_cb (MMBroadbandBearerMbm *self);

static void
connect_poll_ready (MMBaseModem          *modem,
                    GAsyncResult         *res,
                    MMBroadbandBearerMbm *self)
{
    GTask           *task;
    Dial3gppContext *ctx;
    GError          *error = NULL;
    const gchar     *response;
    guint            state;

    task = self->priv->connect_pending;
    self->priv->connect_pending = NULL;

    if (!task) {
        mm_dbg ("Connection context was finished already by an unsolicited message");
        /* Run _finish() to finalize the async call, even if we don't care
         * the result */
        mm_base_modem_at_command_full_finish (modem, res, NULL);
        return;
    }

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_full_finish (modem, res, &error);
    if (!response) {
        ctx->saved_error = error;
        connect_reset (task);
        return;
    }

    if (sscanf (response, "*ENAP: %d", &state) == 1 && state == 1) {
        /* Success!  Connected... */
        g_task_return_pointer (task, g_object_ref (ctx->data), g_object_unref);
        g_object_unref (task);
        return;
    }

    /* Restore pending task and check again in one second */
    self->priv->connect_pending = task;
    g_assert (ctx->poll_id == 0);
    ctx->poll_id = g_timeout_add_seconds (1, (GSourceFunc) connect_poll_cb, self);
}

static gboolean
connect_poll_cb (MMBroadbandBearerMbm *self)
{
    GTask           *task;
    Dial3gppContext *ctx;

    task = self->priv->connect_pending;
    self->priv->connect_pending = NULL;

    g_assert (task);
    ctx = g_task_get_task_data (task);

    ctx->poll_id = 0;

    /* Complete if we were cancelled */
    if (g_cancellable_is_cancelled (g_task_get_cancellable (task))) {
        connect_reset (task);
        return G_SOURCE_REMOVE;
    }

    /* Too many retries... */
    if (ctx->poll_count > 50) {
        g_assert (!ctx->saved_error);
        ctx->saved_error = g_error_new (MM_MOBILE_EQUIPMENT_ERROR,
                                        MM_MOBILE_EQUIPMENT_ERROR_NETWORK_TIMEOUT,
                                        "Connection attempt timed out");
        connect_reset (task);
        return G_SOURCE_REMOVE;
    }

    /* Restore pending task and poll */
    self->priv->connect_pending = task;
    ctx->poll_count++;
    mm_base_modem_at_command_full (ctx->modem,
                                   ctx->primary,
                                   "AT*ENAP?",
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   g_task_get_cancellable (task),
                                   (GAsyncReadyCallback)connect_poll_ready,
                                   self);
    return G_SOURCE_REMOVE;
}

static void
activate_ready (MMBaseModem          *modem,
                GAsyncResult         *res,
                MMBroadbandBearerMbm *self)
{
    GTask           *task;
    Dial3gppContext *ctx;
    GError          *error = NULL;

    /* Try to recover the connection context. If none found, it means the
     * context was already completed and we have nothing else to do. */
    task = self->priv->connect_pending;
    self->priv->connect_pending = NULL;

    if (!task) {
        mm_dbg ("Connection context was finished already by an unsolicited message");
        /* Run _finish() to finalize the async call, even if we don't care
         * the result */
        mm_base_modem_at_command_full_finish (modem, res, NULL);
        goto out;
    }

    /* From now on, if we get cancelled, we'll need to run the connection
     * reset ourselves just in case */
    if (!mm_base_modem_at_command_full_finish (modem, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        goto out;
    }

    ctx = g_task_get_task_data (task);

    /* No unsolicited E2NAP status yet; wait for it and periodically poll
     * to handle very old F3507g/MD300 firmware that may not send E2NAP. */
    self->priv->connect_pending = task;
    ctx->poll_id = g_timeout_add_seconds (1, (GSourceFunc)connect_poll_cb, self);

 out:
    /* Balance refcount with the extra ref we passed to command_full() */
    g_object_unref (self);
}

static void
activate (GTask *task)
{
    MMBroadbandBearerMbm *self;
    Dial3gppContext      *ctx;
    gchar                *command;

    self = g_task_get_source_object (task);
    ctx  = g_task_get_task_data     (task);

    /* The unsolicited response to ENAP may come before the OK does.
     * We will keep the connection context in the bearer private data so
     * that it is accessible from the unsolicited message handler. */
    g_assert (self->priv->connect_pending == NULL);
    self->priv->connect_pending = task;

    /* Activate the PDP context and start the data session */
    command = g_strdup_printf ("AT*ENAP=1,%d", ctx->cid);
    mm_base_modem_at_command_full (ctx->modem,
                                   ctx->primary,
                                   command,
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   g_task_get_cancellable (task),
                                   (GAsyncReadyCallback)activate_ready,
                                   g_object_ref (self)); /* we pass the bearer object! */
    g_free (command);
}

static void
authenticate_ready (MMBaseModem  *modem,
                    GAsyncResult *res,
                    GTask        *task)
{
    GError *error = NULL;

    if (!mm_base_modem_at_command_full_finish (modem, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    activate (task);
}

static void
authenticate (GTask *task)
{
    MMBroadbandBearerMbm *self;
    Dial3gppContext      *ctx;
    const gchar          *user;
    const gchar          *password;

    self = g_task_get_source_object (task);
    ctx  = g_task_get_task_data     (task);

    user     = mm_bearer_properties_get_user     (mm_base_bearer_peek_config (MM_BASE_BEARER (self)));
    password = mm_bearer_properties_get_password (mm_base_bearer_peek_config (MM_BASE_BEARER (self)));

    /* Both user and password are required; otherwise firmware returns an error */
    if (user || password) {
        gchar *command;
        gchar *encoded_user;
        gchar *encoded_password;

        encoded_user = mm_broadband_modem_take_and_convert_to_current_charset (MM_BROADBAND_MODEM (ctx->modem),
                                                                               g_strdup (user));
        encoded_password = mm_broadband_modem_take_and_convert_to_current_charset (MM_BROADBAND_MODEM (ctx->modem),
                                                                                   g_strdup (password));

        command = g_strdup_printf ("AT*EIAAUW=%d,1,\"%s\",\"%s\"",
                                   ctx->cid,
                                   encoded_user ? encoded_user : "",
                                   encoded_password ? encoded_password : "");
        g_free (encoded_user);
        g_free (encoded_password);

        mm_base_modem_at_command_full (ctx->modem,
                                       ctx->primary,
                                       command,
                                       3,
                                       FALSE,
                                       FALSE, /* raw */
                                       g_task_get_cancellable (task),
                                       (GAsyncReadyCallback) authenticate_ready,
                                       task);
        g_free (command);
        return;
    }

    mm_dbg ("Authentication not needed");
    activate (task);
}

static void
dial_3gpp (MMBroadbandBearer   *_self,
           MMBaseModem         *modem,
           MMPortSerialAt      *primary,
           guint                cid,
           GCancellable        *cancellable,
           GAsyncReadyCallback  callback,
           gpointer             user_data)
{
    MMBroadbandBearerMbm *self = MM_BROADBAND_BEARER_MBM (_self);
    GTask                *task;
    Dial3gppContext      *ctx;

    g_assert (primary != NULL);

    task = g_task_new (self, cancellable, callback, user_data);

    ctx = g_slice_new0 (Dial3gppContext);
    ctx->modem   = g_object_ref (modem);
    ctx->primary = g_object_ref (primary);
    ctx->cid     = cid;
    g_task_set_task_data (task, ctx, (GDestroyNotify)dial_3gpp_context_free);

    /* We need a net data port */
    ctx->data = mm_base_modem_get_best_data_port (modem, MM_PORT_TYPE_NET);
    if (!ctx->data) {
        g_task_return_new_error (task,
                                 MM_CORE_ERROR,
                                 MM_CORE_ERROR_NOT_FOUND,
                                 "No valid data port found to launch connection");
        g_object_unref (task);
        return;
    }

    authenticate (task);
}

/*****************************************************************************/
/* 3GPP IP config retrieval (sub-step of the 3GPP Connection sequence) */

typedef struct {
    MMBaseModem *modem;
    MMPortSerialAt *primary;
    MMBearerIpFamily family;
} GetIpConfig3gppContext;

static void
get_ip_config_context_free (GetIpConfig3gppContext *ctx)
{
    g_object_unref (ctx->primary);
    g_object_unref (ctx->modem);
    g_free (ctx);
}

static gboolean
get_ip_config_3gpp_finish (MMBroadbandBearer *self,
                           GAsyncResult *res,
                           MMBearerIpConfig **ipv4_config,
                           MMBearerIpConfig **ipv6_config,
                           GError **error)
{
    MMBearerConnectResult *configs;
    MMBearerIpConfig *ipv4, *ipv6;

    configs = g_task_propagate_pointer (G_TASK (res), error);
    if (!configs)
        return FALSE;

    ipv4 = mm_bearer_connect_result_peek_ipv4_config (configs);
    ipv6 = mm_bearer_connect_result_peek_ipv6_config (configs);
    g_assert (ipv4 || ipv6);
    if (ipv4_config && ipv4)
        *ipv4_config = g_object_ref (ipv4);
    if (ipv6_config && ipv6)
        *ipv6_config = g_object_ref (ipv6);

    mm_bearer_connect_result_unref (configs);
    return TRUE;
}

static void
ip_config_ready (MMBaseModem *modem,
                 GAsyncResult *res,
                 GTask *task)
{
    GetIpConfig3gppContext *ctx;
    MMBearerIpConfig *ipv4_config = NULL;
    MMBearerIpConfig *ipv6_config = NULL;
    const gchar *response;
    GError *error = NULL;
    MMBearerConnectResult *connect_result;

    ctx = g_task_get_task_data (task);

    response = mm_base_modem_at_command_full_finish (modem, res, &error);
    if (error) {
        g_error_free (error);

        /* Fall back to DHCP configuration; early devices don't support *E2IPCFG */
        if (ctx->family == MM_BEARER_IP_FAMILY_IPV4 || ctx->family == MM_BEARER_IP_FAMILY_IPV4V6) {
            ipv4_config = mm_bearer_ip_config_new ();
            mm_bearer_ip_config_set_method (ipv4_config, MM_BEARER_IP_METHOD_DHCP);
        }
        if (ctx->family == MM_BEARER_IP_FAMILY_IPV6 || ctx->family == MM_BEARER_IP_FAMILY_IPV4V6) {
            ipv6_config = mm_bearer_ip_config_new ();
            mm_bearer_ip_config_set_method (ipv6_config, MM_BEARER_IP_METHOD_DHCP);
        }
    } else {
        if (!mm_mbm_parse_e2ipcfg_response (response,
                                            &ipv4_config,
                                            &ipv6_config,
                                            &error)) {
            g_task_return_error (task, error);
            goto out;
        }

        if (!ipv4_config && !ipv6_config) {
            g_task_return_new_error (task,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "Couldn't get IP config: couldn't parse response '%s'",
                                     response);
            goto out;
        }
    }

    connect_result = mm_bearer_connect_result_new (MM_PORT (ctx->primary),
                                                   ipv4_config,
                                                   ipv6_config);
    g_task_return_pointer (task,
                           connect_result,
                           (GDestroyNotify)mm_bearer_connect_result_unref);

out:
    g_object_unref (task);
    g_clear_object (&ipv4_config);
    g_clear_object (&ipv6_config);
}

static void
get_ip_config_3gpp (MMBroadbandBearer *self,
                    MMBroadbandModem *modem,
                    MMPortSerialAt *primary,
                    MMPortSerialAt *secondary,
                    MMPort *data,
                    guint cid,
                    MMBearerIpFamily ip_family,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
    GetIpConfig3gppContext *ctx;
    GTask *task;

    ctx = g_new0 (GetIpConfig3gppContext, 1);
    ctx->modem = g_object_ref (modem);
    ctx->primary = g_object_ref (primary);
    ctx->family = ip_family;

    task = g_task_new (self, NULL, callback, user_data);
    g_task_set_task_data (task, ctx, (GDestroyNotify)get_ip_config_context_free);

    mm_base_modem_at_command_full (MM_BASE_MODEM (modem),
                                   primary,
                                   "*E2IPCFG?",
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   NULL, /* cancellable */
                                   (GAsyncReadyCallback)ip_config_ready,
                                   task);
}

/*****************************************************************************/
/* 3GPP disconnect */

typedef struct {
    MMBaseModem    *modem;
    MMPortSerialAt *primary;
    guint           poll_count;
    guint           poll_id;
} DisconnectContext;

static void
disconnect_context_free (DisconnectContext *ctx)
{
    g_assert (!ctx->poll_id);
    g_clear_object (&ctx->primary);
    g_clear_object (&ctx->modem);
    g_free (ctx);
}

static gboolean
disconnect_3gpp_finish (MMBroadbandBearer  *self,
                        GAsyncResult       *res,
                        GError           **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
process_pending_disconnect_attempt (MMBroadbandBearerMbm     *self,
                                    MMBearerConnectionStatus  status)
{
    GTask             *task;
    DisconnectContext *ctx;

    /* Recover disconnection task */
    task = self->priv->disconnect_pending;
    self->priv->disconnect_pending = NULL;
    g_assert (task != NULL);

    ctx = g_task_get_task_data (task);

    if (ctx->poll_id) {
        g_source_remove (ctx->poll_id);
        ctx->poll_id = 0;
    }

    /* Received 'DISCONNECTED' during a disconnection attempt? */
    if (status == MM_BEARER_CONNECTION_STATUS_DISCONNECTED) {
        mm_dbg ("Connection disconnect indicated by an unsolicited message");
        g_task_return_boolean (task, TRUE);
    } else {
        /* Otherwise, report error */
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_FAILED, "Disconnection failed");
    }
    g_object_unref (task);
}

static gboolean disconnect_poll_cb (MMBroadbandBearerMbm *self);

static void
disconnect_poll_ready (MMBaseModem          *modem,
                       GAsyncResult         *res,
                       MMBroadbandBearerMbm *self)

{
    GTask             *task;
    DisconnectContext *ctx;
    GError            *error = NULL;
    const gchar       *response;
    guint              state;

    task = self->priv->disconnect_pending;
    self->priv->disconnect_pending = NULL;

    if (!task) {
        mm_dbg ("Disconnection context was finished already by an unsolicited message");
        /* Run _finish() to finalize the async call, even if we don't care
         * the result */
        mm_base_modem_at_command_full_finish (modem, res, NULL);
        goto out;
    }

    response = mm_base_modem_at_command_full_finish (modem, res, &error);
    if (!response) {
        g_task_return_error (task, error);
        g_object_unref (task);
        goto out;
    }

    if (sscanf (response, "*ENAP: %d", &state) == 1 && state == 0) {
        /* Disconnected */
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        goto out;
    }

    /* Restore pending task and check in 1s */
    self->priv->disconnect_pending = task;
    ctx = g_task_get_task_data (task);
    g_assert (ctx->poll_id == 0);
    ctx->poll_id = g_timeout_add_seconds (1, (GSourceFunc) disconnect_poll_cb, self);

 out:
    /* Balance refcount with the extra ref we passed to command_full() */
    g_object_unref (self);
}

static gboolean
disconnect_poll_cb (MMBroadbandBearerMbm *self)
{
    GTask             *task;
    DisconnectContext *ctx;

    task = self->priv->disconnect_pending;
    self->priv->disconnect_pending = NULL;

    g_assert (task);
    ctx = g_task_get_task_data (task);

    ctx->poll_id = 0;

    /* Too many retries... */
    if (ctx->poll_count > 20) {
        g_task_return_new_error (task,
                                 MM_MOBILE_EQUIPMENT_ERROR,
                                 MM_MOBILE_EQUIPMENT_ERROR_NETWORK_TIMEOUT,
                                 "Disconnection attempt timed out");
        g_object_unref (task);
        return G_SOURCE_REMOVE;
    }

    /* Restore pending task and poll */
    self->priv->disconnect_pending = task;
    ctx->poll_count++;
    mm_base_modem_at_command_full (ctx->modem,
                                   ctx->primary,
                                   "AT*ENAP?",
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   NULL, /* cancellable */
                                   (GAsyncReadyCallback) disconnect_poll_ready,
                                   g_object_ref (self)); /* we pass the bearer object! */
    return G_SOURCE_REMOVE;
}

static void
disconnect_enap_ready (MMBaseModem          *modem,
                       GAsyncResult         *res,
                       MMBroadbandBearerMbm *self)
{
    DisconnectContext *ctx;
    GTask             *task;
    GError            *error = NULL;

    task = self->priv->disconnect_pending;
    self->priv->disconnect_pending = NULL;

    /* Try to recover the disconnection context. If none found, it means the
     * context was already completed and we have nothing else to do. */
    if (!task) {
        mm_base_modem_at_command_full_finish (modem, res, NULL);
        goto out;
    }

    ctx = g_task_get_task_data (task);

    /* Ignore errors for now */
    mm_base_modem_at_command_full_finish (modem, res, &error);
    if (error) {
        mm_dbg ("Disconnection failed (not fatal): %s", error->message);
        g_error_free (error);
    }

    /* No unsolicited E2NAP status yet; wait for it and periodically poll
     * to handle very old F3507g/MD300 firmware that may not send E2NAP. */
    self->priv->disconnect_pending = task;
    ctx->poll_id = g_timeout_add_seconds (1, (GSourceFunc)disconnect_poll_cb, self);

 out:
    /* Balance refcount with the extra ref we passed to command_full() */
    g_object_unref (self);
}

static void
disconnect_3gpp (MMBroadbandBearer   *_self,
                 MMBroadbandModem    *modem,
                 MMPortSerialAt      *primary,
                 MMPortSerialAt      *secondary,
                 MMPort              *data,
                 guint                cid,
                 GAsyncReadyCallback  callback,
                 gpointer             user_data)
{
    MMBroadbandBearerMbm *self = MM_BROADBAND_BEARER_MBM (_self);
    GTask                *task;
    DisconnectContext    *ctx;

    g_assert (primary != NULL);

    task = g_task_new (self, NULL, callback, user_data);

    ctx = g_new0 (DisconnectContext, 1);
    ctx->modem = MM_BASE_MODEM (g_object_ref (modem));
    ctx->primary = g_object_ref (primary);
    g_task_set_task_data (task, ctx, (GDestroyNotify) disconnect_context_free);

    /* The unsolicited response to ENAP may come before the OK does.
     * We will keep the disconnection context in the bearer private data so
     * that it is accessible from the unsolicited message handler. */
    g_assert (self->priv->disconnect_pending == NULL);
    self->priv->disconnect_pending = task;

    mm_base_modem_at_command_full (MM_BASE_MODEM (modem),
                                   primary,
                                   "*ENAP=0",
                                   3,
                                   FALSE,
                                   FALSE, /* raw */
                                   NULL, /* cancellable */
                                   (GAsyncReadyCallback)disconnect_enap_ready,
                                   g_object_ref (self)); /* we pass the bearer object! */
}

/*****************************************************************************/

static void
report_connection_status (MMBaseBearer             *_self,
                          MMBearerConnectionStatus  status)
{
    MMBroadbandBearerMbm *self = MM_BROADBAND_BEARER_MBM (_self);

    g_assert (status == MM_BEARER_CONNECTION_STATUS_CONNECTED ||
              status == MM_BEARER_CONNECTION_STATUS_CONNECTION_FAILED ||
              status == MM_BEARER_CONNECTION_STATUS_DISCONNECTED);

    /* Process pending connection attempt */
    if (self->priv->connect_pending) {
        process_pending_connect_attempt (self, status);
        return;
    }

    /* Process pending disconnection attempt */
    if (self->priv->disconnect_pending) {
        process_pending_disconnect_attempt (self, status);
        return;
    }

    mm_dbg ("Received spontaneous E2NAP (%s)",
            mm_bearer_connection_status_get_string (status));

    /* Received a random 'DISCONNECTED'...*/
    if (status == MM_BEARER_CONNECTION_STATUS_DISCONNECTED ||
        status == MM_BEARER_CONNECTION_STATUS_CONNECTION_FAILED) {
        /* If no connection/disconnection attempt on-going, make sure we mark ourselves as
         * disconnected. Make sure we only pass 'DISCONNECTED' to the parent */
        MM_BASE_BEARER_CLASS (mm_broadband_bearer_mbm_parent_class)->report_connection_status (
            _self,
            MM_BEARER_CONNECTION_STATUS_DISCONNECTED);
    }
}

/*****************************************************************************/

MMBaseBearer *
mm_broadband_bearer_mbm_new_finish (GAsyncResult *res,
                                    GError **error)
{
    GObject *bearer;
    GObject *source;

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
mm_broadband_bearer_mbm_new (MMBroadbandModemMbm *modem,
                             MMBearerProperties *config,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
    g_async_initable_new_async (
        MM_TYPE_BROADBAND_BEARER_MBM,
        G_PRIORITY_DEFAULT,
        cancellable,
        callback,
        user_data,
        MM_BASE_BEARER_MODEM, modem,
        MM_BASE_BEARER_CONFIG, config,
        NULL);
}

static void
mm_broadband_bearer_mbm_init (MMBroadbandBearerMbm *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_BROADBAND_BEARER_MBM,
                                              MMBroadbandBearerMbmPrivate);
}

static void
mm_broadband_bearer_mbm_class_init (MMBroadbandBearerMbmClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    MMBaseBearerClass *base_bearer_class = MM_BASE_BEARER_CLASS (klass);
    MMBroadbandBearerClass *broadband_bearer_class = MM_BROADBAND_BEARER_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMBroadbandBearerMbmPrivate));

    base_bearer_class->report_connection_status = report_connection_status;
    base_bearer_class->load_connection_status = NULL;
    base_bearer_class->load_connection_status_finish = NULL;

    broadband_bearer_class->dial_3gpp = dial_3gpp;
    broadband_bearer_class->dial_3gpp_finish = dial_3gpp_finish;
    broadband_bearer_class->get_ip_config_3gpp = get_ip_config_3gpp;
    broadband_bearer_class->get_ip_config_3gpp_finish = get_ip_config_3gpp_finish;
    broadband_bearer_class->disconnect_3gpp = disconnect_3gpp;
    broadband_bearer_class->disconnect_3gpp_finish = disconnect_3gpp_finish;
}
