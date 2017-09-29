/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * mmcli -- Control bearer status & access information from the command line
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2011 Aleksander Morgado <aleksander@gnu.org>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#define _LIBMM_INSIDE_MMCLI
#include <libmm-glib.h>

#include "mmcli.h"
#include "mmcli-common.h"

/* Context */
typedef struct {
    MMManager *manager;
    MMObject *object;
    GCancellable *cancellable;
    MMBearer *bearer;
} Context;
static Context *ctx;

/* Options */
static gboolean info_flag; /* set when no action found */
static gboolean connect_flag;
static gboolean disconnect_flag;

static GOptionEntry entries[] = {
    { "connect", 'c', 0, G_OPTION_ARG_NONE, &connect_flag,
      "Connect a given bearer.",
      NULL
    },
    { "disconnect", 'x', 0, G_OPTION_ARG_NONE, &disconnect_flag,
      "Disconnect a given bearer.",
      NULL
    },
    { NULL }
};

GOptionGroup *
mmcli_bearer_get_option_group (void)
{
    GOptionGroup *group;

    /* Status options */
    group = g_option_group_new ("bearer",
                                "Bearer options",
                                "Show bearer options",
                                NULL,
                                NULL);
    g_option_group_add_entries (group, entries);

    return group;
}

gboolean
mmcli_bearer_options_enabled (void)
{
    static guint n_actions = 0;
    static gboolean checked = FALSE;

    if (checked)
        return !!n_actions;

    n_actions = (connect_flag +
                 disconnect_flag);

    if (n_actions == 0 && mmcli_get_common_bearer_string ()) {
        /* default to info */
        info_flag = TRUE;
        n_actions++;
    }

    if (n_actions > 1) {
        g_printerr ("error: too many bearer actions requested\n");
        exit (EXIT_FAILURE);
    }

    if (info_flag)
        mmcli_force_sync_operation ();

    checked = TRUE;
    return !!n_actions;
}

static void
context_free (Context *ctx)
{
    if (!ctx)
        return;

    if (ctx->cancellable)
        g_object_unref (ctx->cancellable);
    if (ctx->bearer)
        g_object_unref (ctx->bearer);
    if (ctx->object)
        g_object_unref (ctx->object);
    if (ctx->manager)
        g_object_unref (ctx->manager);
    g_free (ctx);
}

void
mmcli_bearer_shutdown (void)
{
    context_free (ctx);
}

static void
print_bearer_info (MMBearer *bearer)
{
    MMBearerIpConfig *ipv4_config;
    MMBearerIpConfig *ipv6_config;
    MMBearerProperties *properties;
    MMBearerStats *stats;
    gchar *connected_apns_string;

    ipv4_config = mm_bearer_get_ipv4_config (bearer);
    ipv6_config = mm_bearer_get_ipv6_config (bearer);
    properties = mm_bearer_get_properties (bearer);
    stats = mm_bearer_get_stats (bearer);

    if (mm_bearer_get_connected_apns (bearer)) {
        connected_apns_string = g_strjoinv (", ", (gchar **)mm_bearer_get_connected_apns (ctx->bearer));
        if (!connected_apns_string[0]) {
            g_free (connected_apns_string);
            connected_apns_string = NULL;
        }
    } else
        connected_apns_string = NULL;

    /* Not the best thing to do, as we may be doing _get() calls twice, but
     * easiest to maintain */
#undef VALIDATE_UNKNOWN
#define VALIDATE_UNKNOWN(str) (str ? str : "unknown")
#undef VALIDATE_NONE
#define VALIDATE_NONE(str) (str ? str : "none")

    g_print ("Bearer '%s'\n",
             mm_bearer_get_path (bearer));
    g_print ("  -------------------------\n"
             "  Status             |       connected: '%s'\n"
             "                     |       suspended: '%s'\n"
             "                     |       interface: '%s'\n"
             "                     |      IP timeout: '%u'\n"
             "                     |  connected APNs: '%s'\n",
             mm_bearer_get_connected (bearer) ? "yes" : "no",
             mm_bearer_get_suspended (bearer) ? "yes" : "no",
             VALIDATE_UNKNOWN (mm_bearer_get_interface (bearer)),
             mm_bearer_get_ip_timeout (bearer),
             VALIDATE_UNKNOWN (connected_apns_string));

    if (properties) {
        gchar *ip_family_str;
        guint  n_secondary, i;

        ip_family_str = (mm_bearer_ip_family_build_string_from_mask (
                             mm_bearer_properties_get_ip_type (properties)));
        g_print ("  -------------------------\n"
                 "  Properties         |         apn: '%s'\n"
                 "                     |     roaming: '%s'\n"
                 "                     |     IP type: '%s'\n"
                 "                     |        user: '%s'\n"
                 "                     |    password: '%s'\n"
                 "                     |      number: '%s'\n"
                 "                     | Rm protocol: '%s'\n",
                 VALIDATE_NONE (mm_bearer_properties_get_apn (properties)),
                 mm_bearer_properties_get_allow_roaming (properties) ? "allowed" : "forbidden",
                 VALIDATE_UNKNOWN (ip_family_str),
                 VALIDATE_NONE (mm_bearer_properties_get_user (properties)),
                 VALIDATE_NONE (mm_bearer_properties_get_password (properties)),
                 VALIDATE_NONE (mm_bearer_properties_get_number (properties)),
                 VALIDATE_UNKNOWN (mm_modem_cdma_rm_protocol_get_string (
                                       mm_bearer_properties_get_rm_protocol (properties))));
        g_free (ip_family_str);

        n_secondary = mm_bearer_properties_get_n_secondary (properties);
        for (i = 0; i < n_secondary; i++) {
            g_print ("  Secondary context  |         apn: '%s'\n"
                     "                     |        user: '%s'\n"
                     "                     |    password: '%s'\n",
                     VALIDATE_NONE (mm_bearer_properties_get_secondary_apn (properties, i)),
                     VALIDATE_NONE (mm_bearer_properties_get_secondary_user (properties, i)),
                     VALIDATE_NONE (mm_bearer_properties_get_secondary_password (properties, i)));
        }
    }

    /* IPv4 */
    g_print ("  -------------------------\n"
             "  IPv4 configuration |   method: '%s'\n",
             (ipv4_config ?
              mm_bearer_ip_method_get_string (mm_bearer_ip_config_get_method (ipv4_config)) :
              "none"));
    if (ipv4_config &&
        mm_bearer_ip_config_get_method (ipv4_config) != MM_BEARER_IP_METHOD_UNKNOWN) {
        const gchar **dns = mm_bearer_ip_config_get_dns (ipv4_config);
        guint i, mtu;

        g_print ("                     |  address: '%s'\n"
                 "                     |   prefix: '%u'\n"
                 "                     |  gateway: '%s'\n",
                 VALIDATE_UNKNOWN (mm_bearer_ip_config_get_address (ipv4_config)),
                 mm_bearer_ip_config_get_prefix (ipv4_config),
                 VALIDATE_UNKNOWN (mm_bearer_ip_config_get_gateway (ipv4_config)));

        if (dns && dns[0]) {
            g_print (
                 "                     |      DNS: '%s'", dns[0]);
            /* Additional DNS addresses */
            for (i = 1; dns[i]; i++)
                g_print (", '%s'", dns[i]);
        } else {
            g_print (
                 "                     |      DNS: none");
        }
        g_print ("\n");

        mtu = mm_bearer_ip_config_get_mtu (ipv4_config);
        if (mtu)
            g_print ("                     |      MTU: '%u'\n", mtu);
    }

    /* IPv6 */
    g_print ("  -------------------------\n"
             "  IPv6 configuration |   method: '%s'\n",
             (ipv6_config ?
              mm_bearer_ip_method_get_string (mm_bearer_ip_config_get_method (ipv6_config)) :
              "none"));
    if (ipv6_config &&
        mm_bearer_ip_config_get_method (ipv6_config) != MM_BEARER_IP_METHOD_UNKNOWN) {
        const gchar **dns = mm_bearer_ip_config_get_dns (ipv6_config);
        guint i, mtu;

        g_print ("                     |  address: '%s'\n"
                 "                     |   prefix: '%u'\n"
                 "                     |  gateway: '%s'\n",
                 VALIDATE_UNKNOWN(mm_bearer_ip_config_get_address (ipv6_config)),
                 mm_bearer_ip_config_get_prefix (ipv6_config),
                 VALIDATE_UNKNOWN(mm_bearer_ip_config_get_gateway (ipv6_config)));

        if (dns && dns[0]) {
            g_print (
                 "                     |      DNS: '%s'", dns[0]);
            /* Additional DNS addresses */
            for (i = 1; dns[i]; i++)
                g_print (", '%s'", dns[i]);
        } else {
            g_print (
                 "                     |      DNS: none");
        }
        g_print ("\n");

        mtu = mm_bearer_ip_config_get_mtu (ipv6_config);
        if (mtu)
            g_print ("                     |      MTU: '%u'\n", mtu);
    }

    if (stats) {
        guint64 val;

        g_print ("  -------------------------\n"
                 "  Stats              |          Duration: '%u'\n", mm_bearer_stats_get_duration (stats));

        val = mm_bearer_stats_get_rx_bytes (stats);
        if (val > 0)
            g_print ("                     |    Bytes received: '%" G_GUINT64_FORMAT "'\n", val);
        else
            g_print ("                     |    Bytes received: 'N/A'\n");

        val = mm_bearer_stats_get_tx_bytes (stats);
        if (val > 0)
            g_print ("                     | Bytes transmitted: '%" G_GUINT64_FORMAT "'\n", val);
        else
            g_print ("                     | Bytes transmitted: 'N/A'\n");
    }

    g_clear_object (&stats);
    g_clear_object (&properties);
    g_clear_object (&ipv4_config);
    g_clear_object (&ipv6_config);
}

static void
connect_process_reply (gboolean      result,
                       const GError *error)
{
    if (!result) {
        g_printerr ("error: couldn't connect the bearer: '%s'\n",
                    error ? error->message : "unknown error");
        exit (EXIT_FAILURE);
    }

    g_print ("successfully connected the bearer\n");
}

static void
connect_ready (MMBearer      *bearer,
               GAsyncResult *result,
               gpointer      nothing)
{
    gboolean operation_result;
    GError *error = NULL;

    operation_result = mm_bearer_connect_finish (bearer, result, &error);
    connect_process_reply (operation_result, error);

    mmcli_async_operation_done ();
}

static void
disconnect_process_reply (gboolean      result,
                          const GError *error)
{
    if (!result) {
        g_printerr ("error: couldn't disconnect the bearer: '%s'\n",
                    error ? error->message : "unknown error");
        exit (EXIT_FAILURE);
    }

    g_print ("successfully disconnected the bearer\n");
}

static void
disconnect_ready (MMBearer      *bearer,
                  GAsyncResult *result,
                  gpointer      nothing)
{
    gboolean operation_result;
    GError *error = NULL;

    operation_result = mm_bearer_disconnect_finish (bearer, result, &error);
    disconnect_process_reply (operation_result, error);

    mmcli_async_operation_done ();
}

static void
get_bearer_ready (GObject      *source,
                  GAsyncResult *result,
                  gpointer      none)
{
    ctx->bearer = mmcli_get_bearer_finish (result,
                                           &ctx->manager,
                                           &ctx->object);

    if (info_flag)
        g_assert_not_reached ();

    /* Request to connect the bearer? */
    if (connect_flag) {
        g_debug ("Asynchronously connecting bearer...");
        mm_bearer_connect (ctx->bearer,
                           ctx->cancellable,
                           (GAsyncReadyCallback)connect_ready,
                           NULL);
        return;
    }

    /* Request to disconnect the bearer? */
    if (disconnect_flag) {
        g_debug ("Asynchronously disconnecting bearer...");
        mm_bearer_disconnect (ctx->bearer,
                              ctx->cancellable,
                              (GAsyncReadyCallback)disconnect_ready,
                              NULL);
        return;
    }

    g_warn_if_reached ();
}

void
mmcli_bearer_run_asynchronous (GDBusConnection *connection,
                               GCancellable    *cancellable)
{
    /* Initialize context */
    ctx = g_new0 (Context, 1);
    if (cancellable)
        ctx->cancellable = g_object_ref (cancellable);

    /* Get proper bearer */
    mmcli_get_bearer (connection,
                      mmcli_get_common_bearer_string (),
                      cancellable,
                      (GAsyncReadyCallback)get_bearer_ready,
                      NULL);
}

void
mmcli_bearer_run_synchronous (GDBusConnection *connection)
{
    GError *error = NULL;

    /* Initialize context */
    ctx = g_new0 (Context, 1);
    ctx->bearer = mmcli_get_bearer_sync (connection,
                                         mmcli_get_common_bearer_string (),
                                         &ctx->manager,
                                         &ctx->object);

    /* Request to get info from bearer? */
    if (info_flag) {
        g_debug ("Printing bearer info...");
        print_bearer_info (ctx->bearer);
        return;
    }

    /* Request to connect the bearer? */
    if (connect_flag) {
        gboolean result;

        g_debug ("Synchronously connecting bearer...");
        result = mm_bearer_connect_sync (ctx->bearer,
                                         NULL,
                                         &error);
        connect_process_reply (result, error);
        return;
    }

    /* Request to disconnect the bearer? */
    if (disconnect_flag) {
        gboolean result;

        g_debug ("Synchronously disconnecting bearer...");
        result = mm_bearer_disconnect_sync (ctx->bearer, NULL, &error);
        disconnect_process_reply (result, error);
        return;
    }

    g_warn_if_reached ();
}
