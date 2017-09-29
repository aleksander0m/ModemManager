/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * libmm -- Access modem status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2011 - 2012 Aleksander Morgado <aleksander@gnu.org>
 * Copyright (C) 2012 Google, Inc.
 */

#ifndef _MM_BEARER_H_
#define _MM_BEARER_H_

#if !defined (__LIBMM_GLIB_H_INSIDE__) && !defined (LIBMM_GLIB_COMPILATION)
#error "Only <libmm-glib.h> can be included directly."
#endif

#include <ModemManager.h>

#include "mm-gdbus-bearer.h"
#include "mm-bearer-properties.h"
#include "mm-bearer-ip-config.h"
#include "mm-bearer-stats.h"

G_BEGIN_DECLS

#define MM_TYPE_BEARER            (mm_bearer_get_type ())
#define MM_BEARER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BEARER, MMBearer))
#define MM_BEARER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), MM_TYPE_BEARER, MMBearerClass))
#define MM_IS_BEARER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BEARER))
#define MM_IS_BEARER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), MM_TYPE_BEARER))
#define MM_BEARER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), MM_TYPE_BEARER, MMBearerClass))

typedef struct _MMBearer MMBearer;
typedef struct _MMBearerClass MMBearerClass;
typedef struct _MMBearerPrivate MMBearerPrivate;

/**
 * MMBearer:
 *
 * The #MMBearer structure contains private data and should only be accessed
 * using the provided API.
 */
struct _MMBearer {
    /*< private >*/
    MmGdbusBearerProxy parent;
    MMBearerPrivate *priv;
};

struct _MMBearerClass {
    /*< private >*/
    MmGdbusBearerProxyClass parent;
};

GType mm_bearer_get_type (void);

const gchar *mm_bearer_get_path       (MMBearer *self);
gchar       *mm_bearer_dup_path       (MMBearer *self);

const gchar *mm_bearer_get_interface  (MMBearer *self);
gchar       *mm_bearer_dup_interface  (MMBearer *self);

gboolean     mm_bearer_get_connected  (MMBearer *self);

gboolean     mm_bearer_get_suspended  (MMBearer *self);

guint        mm_bearer_get_ip_timeout (MMBearer *self);

void     mm_bearer_connect        (MMBearer *self,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data);
gboolean mm_bearer_connect_finish (MMBearer *self,
                                   GAsyncResult *res,
                                   GError **error);
gboolean mm_bearer_connect_sync   (MMBearer *self,
                                   GCancellable *cancellable,
                                   GError **error);

void     mm_bearer_disconnect        (MMBearer *self,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data);
gboolean mm_bearer_disconnect_finish (MMBearer *self,
                                      GAsyncResult *res,
                                      GError **error);
gboolean mm_bearer_disconnect_sync   (MMBearer *self,
                                      GCancellable *cancellable,
                                      GError **error);

MMBearerProperties *mm_bearer_get_properties   (MMBearer *self);
MMBearerProperties *mm_bearer_peek_properties  (MMBearer *self);

MMBearerIpConfig   *mm_bearer_get_ipv4_config  (MMBearer *self);
MMBearerIpConfig   *mm_bearer_peek_ipv4_config (MMBearer *self);

MMBearerIpConfig   *mm_bearer_get_ipv6_config  (MMBearer *self);
MMBearerIpConfig   *mm_bearer_peek_ipv6_config (MMBearer *self);

MMBearerStats      *mm_bearer_get_stats        (MMBearer *self);
MMBearerStats      *mm_bearer_peek_stats       (MMBearer *self);

const gchar * const  *mm_bearer_get_connected_apns (MMBearer *self);
gchar               **mm_bearer_dup_connected_apns (MMBearer *self);

G_END_DECLS

#endif /* _MM_BEARER_H_ */
