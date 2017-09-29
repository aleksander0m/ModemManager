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

 * Copyright (C) 2011 Google, Inc.
 * Copyright (C) 2015 Azimut Electronics
 * Copyright (C) 2011 - 2015 Aleksander Morgado <aleksander@aleksander.es>
 */

#ifndef MM_BASE_BEARER_H
#define MM_BASE_BEARER_H

#include <glib.h>
#include <glib-object.h>

#include <ModemManager.h>
#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-base-modem.h"

/*****************************************************************************/
/* Helpers to implement connect() */

typedef struct _MMBearerConnectResult MMBearerConnectResult;
MMBearerConnectResult *mm_bearer_connect_result_new              (MMPort *data,
                                                                  MMBearerIpConfig *ipv4_config,
                                                                  MMBearerIpConfig *ipv6_config);
void                   mm_bearer_connect_result_unref            (MMBearerConnectResult *result);
MMBearerConnectResult *mm_bearer_connect_result_ref              (MMBearerConnectResult *result);
MMPort                *mm_bearer_connect_result_peek_data        (MMBearerConnectResult *result);
MMBearerIpConfig      *mm_bearer_connect_result_peek_ipv4_config (MMBearerConnectResult *result);
MMBearerIpConfig      *mm_bearer_connect_result_peek_ipv6_config (MMBearerConnectResult *result);

/*****************************************************************************/

#define MM_TYPE_BASE_BEARER            (mm_base_bearer_get_type ())
#define MM_BASE_BEARER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BASE_BEARER, MMBaseBearer))
#define MM_BASE_BEARER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_BASE_BEARER, MMBaseBearerClass))
#define MM_IS_BASE_BEARER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BASE_BEARER))
#define MM_IS_BASE_BEARER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_BASE_BEARER))
#define MM_BASE_BEARER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_BASE_BEARER, MMBaseBearerClass))

typedef struct _MMBaseBearer MMBaseBearer;
typedef struct _MMBaseBearerClass MMBaseBearerClass;
typedef struct _MMBaseBearerPrivate MMBaseBearerPrivate;

#define MM_BASE_BEARER_PATH              "bearer-path"
#define MM_BASE_BEARER_CONNECTION        "bearer-connection"
#define MM_BASE_BEARER_MODEM             "bearer-modem"
#define MM_BASE_BEARER_STATUS            "bearer-status"
#define MM_BASE_BEARER_CONFIG            "bearer-config"
#define MM_BASE_BEARER_DEFAULT_IP_FAMILY "bearer-default-ip-family"

typedef enum { /*< underscore_name=mm_bearer_status >*/
    MM_BEARER_STATUS_DISCONNECTED,
    MM_BEARER_STATUS_DISCONNECTING,
    MM_BEARER_STATUS_CONNECTING,
    MM_BEARER_STATUS_CONNECTED,
} MMBearerStatus;

typedef enum { /*< underscore_name=mm_bearer_connection_status >*/
    MM_BEARER_CONNECTION_STATUS_UNKNOWN,
    MM_BEARER_CONNECTION_STATUS_DISCONNECTED,
    MM_BEARER_CONNECTION_STATUS_DISCONNECTING,
    MM_BEARER_CONNECTION_STATUS_CONNECTED,
    MM_BEARER_CONNECTION_STATUS_CONNECTION_FAILED,
} MMBearerConnectionStatus;

struct _MMBaseBearer {
    MmGdbusBearerSkeleton parent;
    MMBaseBearerPrivate *priv;
};

struct _MMBaseBearerClass {
    MmGdbusBearerSkeletonClass parent;

    /* Connect this bearer */
    void (* connect) (MMBaseBearer *bearer,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data);
    MMBearerConnectResult * (* connect_finish) (MMBaseBearer *bearer,
                                                GAsyncResult *res,
                                                GError **error);

    void (* connect_secondary) (MMBaseBearer *bearer,
                                guint secondary_i,
                                GCancellable *cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data);
    gboolean (* connect_secondary_finish) (MMBaseBearer *bearer,
                                           GAsyncResult *res,
                                           GError **error);

    /* Disconnect this bearer */
    void (* disconnect) (MMBaseBearer *bearer,
                         GAsyncReadyCallback callback,
                         gpointer user_data);
    gboolean (* disconnect_finish) (MMBaseBearer *bearer,
                                    GAsyncResult *res,
                                    GError **error);

    void (* disconnect_secondary) (MMBaseBearer *bearer,
                                   guint secondary_i,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data);
    gboolean (* disconnect_secondary_finish) (MMBaseBearer *bearer,
                                              GAsyncResult *res,
                                              GError **error);

    /* Monitor connection status:
     * NOTE: only CONNECTED or DISCONNECTED should be reported here; this method
     * is used to poll for connection status once the connection has been
     * established */
    void (* load_connection_status) (MMBaseBearer *bearer,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data);
    MMBearerConnectionStatus (* load_connection_status_finish) (MMBaseBearer *bearer,
                                                                GAsyncResult *res,
                                                                GError **error);

    void (* load_connection_status_secondary) (MMBaseBearer *bearer,
                                               guint secondary_i,
                                               GAsyncReadyCallback callback,
                                               gpointer user_data);
    MMBearerConnectionStatus (* load_connection_status_secondary_finish) (MMBaseBearer *bearer,
                                                                          GAsyncResult *res,
                                                                          GError **error);

    /* Reload statistics */
    void (* reload_stats) (MMBaseBearer *bearer,
                           GAsyncReadyCallback callback,
                           gpointer user_data);
    gboolean (* reload_stats_finish) (MMBaseBearer *bearer,
                                      guint64 *bytes_rx,
                                      guint64 *bytes_tx,
                                      GAsyncResult *res,
                                      GError **error);

    /* Report connection status of this bearer */
    void (* report_connection_status) (MMBaseBearer *bearer,
                                       MMBearerConnectionStatus status);
};

GType mm_base_bearer_get_type (void);

void         mm_base_bearer_export   (MMBaseBearer *self);

const gchar        *mm_base_bearer_get_path              (MMBaseBearer *self);
MMBearerStatus      mm_base_bearer_get_status            (MMBaseBearer *self);
MMBearerProperties *mm_base_bearer_peek_config           (MMBaseBearer *self);
MMBearerProperties *mm_base_bearer_get_config            (MMBaseBearer *self);
MMBearerIpFamily    mm_base_bearer_get_default_ip_family (MMBaseBearer *self);


void     mm_base_bearer_connect        (MMBaseBearer *self,
                                        GAsyncReadyCallback callback,
                                        gpointer user_data);
gboolean mm_base_bearer_connect_finish (MMBaseBearer *self,
                                        GAsyncResult *res,
                                        GError **error);

void     mm_base_bearer_disconnect        (MMBaseBearer *self,
                                           GAsyncReadyCallback callback,
                                           gpointer user_data);
gboolean mm_base_bearer_disconnect_finish (MMBaseBearer *self,
                                           GAsyncResult *res,
                                           GError **error);

void mm_base_bearer_disconnect_force (MMBaseBearer *self);

void mm_base_bearer_report_connection_status (MMBaseBearer *self,
                                              MMBearerConnectionStatus status);

#endif /* MM_BASE_BEARER_H */
