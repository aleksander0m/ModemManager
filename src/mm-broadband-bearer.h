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
 * Author: Aleksander Morgado <aleksander@lanedo.com>
 *
 * Copyright (C) 2011 - 2012 Google, Inc.
 * Copyright (C) 2011 - 2013 Aleksander Morgado <aleksander@gnu.org>
 */

#ifndef MM_BROADBAND_BEARER_H
#define MM_BROADBAND_BEARER_H

#include <glib.h>
#include <glib-object.h>

#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-modem-helpers.h"
#include "mm-base-bearer.h"
#include "mm-broadband-modem.h"

#define MM_TYPE_BROADBAND_BEARER            (mm_broadband_bearer_get_type ())
#define MM_BROADBAND_BEARER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BROADBAND_BEARER, MMBroadbandBearer))
#define MM_BROADBAND_BEARER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_BROADBAND_BEARER, MMBroadbandBearerClass))
#define MM_IS_BROADBAND_BEARER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BROADBAND_BEARER))
#define MM_IS_BROADBAND_BEARER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_BROADBAND_BEARER))
#define MM_BROADBAND_BEARER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_BROADBAND_BEARER, MMBroadbandBearerClass))

typedef struct _MMBroadbandBearer MMBroadbandBearer;
typedef struct _MMBroadbandBearerClass MMBroadbandBearerClass;
typedef struct _MMBroadbandBearerPrivate MMBroadbandBearerPrivate;

#define MM_BROADBAND_BEARER_FLOW_CONTROL "broadband-bearer-flow-control"

struct _MMBroadbandBearer {
    MMBaseBearer parent;
    MMBroadbandBearerPrivate *priv;
};

struct _MMBroadbandBearerClass {
    MMBaseBearerClass parent;

    /* Full 3GPP connection sequence (cid selection, dial, get ip config) */
    void     (* connect_3gpp)        (MMBroadbandBearer *self,
                                      MMBroadbandModem *modem,
                                      MMPortSerialAt *primary,
                                      MMPortSerialAt *secondary,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data);
    MMBearerConnectResult * (* connect_3gpp_finish) (MMBroadbandBearer *self,
                                                     GAsyncResult *res,
                                                     GError **error);

    /* CID selection sub-part of 3GPP connection */
    void  (* cid_selection_3gpp)        (MMBroadbandBearer *self,
                                         MMBaseModem *modem,
                                         MMPortSerialAt *primary,
                                         const gchar *apn,
                                         MMBearerIpFamily ip_family,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data);
    guint (* cid_selection_3gpp_finish) (MMBroadbandBearer *self,
                                         GAsyncResult *res,
                                         GError **error);

    /* Dialing sub-part of 3GPP connection */
    void     (* dial_3gpp)        (MMBroadbandBearer *self,
                                   MMBaseModem *modem,
                                   MMPortSerialAt *primary,
                                   guint cid,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data);
    MMPort * (* dial_3gpp_finish) (MMBroadbandBearer *self,
                                   GAsyncResult *res,
                                   GError **error);
    void     (* dial_secondary_3gpp)        (MMBroadbandBearer *self,
                                             MMBaseModem *modem,
                                             MMPortSerialAt *primary,
                                             guint cid,
                                             guint secondary_i,
                                             GCancellable *cancellable,
                                             GAsyncReadyCallback callback,
                                             gpointer user_data);
    gboolean (* dial_secondary_3gpp_finish) (MMBroadbandBearer *self,
                                             GAsyncResult *res,
                                             GError **error);

    /* IP config retrieval sub-part of 3GPP connection.
     * Only really required when using net port + static IP address. */
    void     (* get_ip_config_3gpp) (MMBroadbandBearer *self,
                                     MMBroadbandModem *modem,
                                     MMPortSerialAt *primary,
                                     MMPortSerialAt *secondary,
                                     MMPort *data,
                                     guint cid,
                                     MMBearerIpFamily ip_family,
                                     GAsyncReadyCallback callback,
                                     gpointer user_data);
    gboolean (* get_ip_config_3gpp_finish) (MMBroadbandBearer *self,
                                            GAsyncResult *res,
                                            MMBearerIpConfig **ipv4_config,
                                            MMBearerIpConfig **ipv6_config,
                                            GError **error);

    /* Full 3GPP disconnection sequence */
    void     (* disconnect_3gpp)        (MMBroadbandBearer *self,
                                         MMBroadbandModem *modem,
                                         MMPortSerialAt *primary,
                                         MMPortSerialAt *secondary,
                                         MMPort *data,
                                         guint cid,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data);
    gboolean (* disconnect_3gpp_finish) (MMBroadbandBearer *self,
                                         GAsyncResult *res,
                                         GError **error);

    /* Full CDMA connection sequence */
    void     (* connect_cdma)        (MMBroadbandBearer *self,
                                      MMBroadbandModem *modem,
                                      MMPortSerialAt *primary,
                                      MMPortSerialAt *secondary,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data);
    MMBearerConnectResult * (* connect_cdma_finish) (MMBroadbandBearer *self,
                                                     GAsyncResult *res,
                                                     GError **error);

    /* Full CDMA disconnection sequence */
    void     (* disconnect_cdma)        (MMBroadbandBearer *self,
                                         MMBroadbandModem *modem,
                                         MMPortSerialAt *primary,
                                         MMPortSerialAt *secondary,
                                         MMPort *data,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data);
    gboolean (* disconnect_cdma_finish) (MMBroadbandBearer *self,
                                         GAsyncResult *res,
                                         GError **error);
};

GType mm_broadband_bearer_get_type (void);

/* Default 3GPP bearer creation implementation */
void          mm_broadband_bearer_new        (MMBroadbandModem *modem,
                                              MMBearerProperties *properties,
                                              GCancellable *cancellable,
                                              GAsyncReadyCallback callback,
                                              gpointer user_data);
MMBaseBearer *mm_broadband_bearer_new_finish (GAsyncResult *res,
                                              GError **error);

MMBearerIpFamily mm_broadband_bearer_get_3gpp_ip_family     (MMBroadbandBearer *self);
guint            mm_broadband_bearer_get_3gpp_cid           (MMBroadbandBearer *self);
guint            mm_broadband_bearer_get_3gpp_secondary_cid (MMBroadbandBearer *self,
                                                             guint              i);

#endif /* MM_BROADBAND_BEARER_H */
