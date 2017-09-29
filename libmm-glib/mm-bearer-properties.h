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
 * Copyright (C) 2011 Aleksander Morgado <aleksander@gnu.org>
 */

#ifndef MM_BEARER_PROPERTIES_H
#define MM_BEARER_PROPERTIES_H

#include <ModemManager.h>
#include <glib-object.h>

#if !defined (__LIBMM_GLIB_H_INSIDE__) && !defined (LIBMM_GLIB_COMPILATION)
#error "Only <libmm-glib.h> can be included directly."
#endif

#define MM_BEARER_PROPERTY_SEPARATOR "|"

G_BEGIN_DECLS

#define MM_TYPE_BEARER_PROPERTIES            (mm_bearer_properties_get_type ())
#define MM_BEARER_PROPERTIES(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_BEARER_PROPERTIES, MMBearerProperties))
#define MM_BEARER_PROPERTIES_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_BEARER_PROPERTIES, MMBearerPropertiesClass))
#define MM_IS_BEARER_PROPERTIES(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_BEARER_PROPERTIES))
#define MM_IS_BEARER_PROPERTIES_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_BEARER_PROPERTIES))
#define MM_BEARER_PROPERTIES_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_BEARER_PROPERTIES, MMBearerPropertiesClass))

typedef struct _MMBearerProperties MMBearerProperties;
typedef struct _MMBearerPropertiesClass MMBearerPropertiesClass;
typedef struct _MMBearerPropertiesPrivate MMBearerPropertiesPrivate;

/**
 * MMBearerProperties:
 *
 * The #MMBearerProperties structure contains private data and should
 * only be accessed using the provided API.
 */
struct _MMBearerProperties {
    /*< private >*/
    GObject parent;
    MMBearerPropertiesPrivate *priv;
};

struct _MMBearerPropertiesClass {
    /*< private >*/
    GObjectClass parent;
};

GType mm_bearer_properties_get_type (void);

MMBearerProperties *mm_bearer_properties_new (void);

void mm_bearer_properties_set_apn           (MMBearerProperties *self,
                                             const gchar *apn);
void mm_bearer_properties_set_allowed_auth  (MMBearerProperties *self,
                                             MMBearerAllowedAuth allowed_auth);
void mm_bearer_properties_set_user          (MMBearerProperties *self,
                                             const gchar *user);
void mm_bearer_properties_set_password      (MMBearerProperties *self,
                                             const gchar *password);
void mm_bearer_properties_set_ip_type       (MMBearerProperties *self,
                                             MMBearerIpFamily ip_type);
void mm_bearer_properties_set_allow_roaming (MMBearerProperties *self,
                                             gboolean allow_roaming);
void mm_bearer_properties_set_number        (MMBearerProperties *self,
                                             const gchar *number);
void mm_bearer_properties_set_rm_protocol   (MMBearerProperties *self,
                                             MMModemCdmaRmProtocol protocol);

const gchar           *mm_bearer_properties_get_apn           (MMBearerProperties *self);
const gchar           *mm_bearer_properties_get_user          (MMBearerProperties *self);
const gchar           *mm_bearer_properties_get_password      (MMBearerProperties *self);
MMBearerAllowedAuth    mm_bearer_properties_get_allowed_auth  (MMBearerProperties *self);
MMBearerIpFamily       mm_bearer_properties_get_ip_type       (MMBearerProperties *self);
gboolean               mm_bearer_properties_get_allow_roaming (MMBearerProperties *self);
const gchar           *mm_bearer_properties_get_number        (MMBearerProperties *self);
MMModemCdmaRmProtocol  mm_bearer_properties_get_rm_protocol   (MMBearerProperties *self);

guint                  mm_bearer_properties_get_n_secondary        (MMBearerProperties *self);
const gchar           *mm_bearer_properties_get_secondary_apn      (MMBearerProperties *self, guint i);
const gchar           *mm_bearer_properties_get_secondary_user     (MMBearerProperties *self, guint i);
const gchar           *mm_bearer_properties_get_secondary_password (MMBearerProperties *self, guint i);

/*****************************************************************************/
/* ModemManager/libmm-glib/mmcli specific methods */

#if defined (_LIBMM_INSIDE_MM) ||    \
    defined (_LIBMM_INSIDE_MMCLI) || \
    defined (LIBMM_GLIB_COMPILATION)

MMBearerProperties *mm_bearer_properties_new_from_string (const gchar *str,
                                                          GError **error);
MMBearerProperties *mm_bearer_properties_new_from_dictionary (GVariant *dictionary,
                                                              GError **error);

MMBearerProperties *mm_bearer_properties_dup (MMBearerProperties *orig);

gboolean mm_bearer_properties_consume_string (MMBearerProperties *self,
                                              const gchar *key,
                                              const gchar *value,
                                              GError **error);

gboolean mm_bearer_properties_consume_variant (MMBearerProperties *properties,
                                               const gchar *key,
                                               GVariant *value,
                                               GError **error);

GVariant *mm_bearer_properties_get_dictionary (MMBearerProperties *self);

gboolean mm_bearer_properties_cmp (MMBearerProperties *a,
                                   MMBearerProperties *b);

#endif

G_END_DECLS

#endif /* MM_BEARER_PROPERTIES_H */
