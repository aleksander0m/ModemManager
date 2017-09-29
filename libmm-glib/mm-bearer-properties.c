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

#include <string.h>

#include "mm-errors-types.h"
#include "mm-common-helpers.h"
#include "mm-bearer-properties.h"

/**
 * SECTION: mm-bearer-properties
 * @title: MMBearerProperties
 * @short_description: Helper object to handle bearer properties.
 *
 * The #MMBearerProperties is an object handling the properties requested
 * to ModemManager when creating a new bearer.
 *
 * This object is created by the user and passed to ModemManager with either
 * mm_modem_create_bearer() or mm_modem_create_bearer_sync().
 */

G_DEFINE_TYPE (MMBearerProperties, mm_bearer_properties, G_TYPE_OBJECT);

#define PROPERTY_APN             "apn"
#define PROPERTY_ALLOWED_AUTH    "allowed-auth"
#define PROPERTY_USER            "user"
#define PROPERTY_PASSWORD        "password"
#define PROPERTY_IP_TYPE         "ip-type"
#define PROPERTY_NUMBER          "number"
#define PROPERTY_ALLOW_ROAMING   "allow-roaming"
#define PROPERTY_RM_PROTOCOL     "rm-protocol"

struct _MMBearerPropertiesPrivate {
    /* APN */
    gchar **apn;
    /* IP type */
    MMBearerIpFamily ip_type;
    /* Allowed auth */
    MMBearerAllowedAuth allowed_auth;
    /* User */
    gchar **user;
    /* Password */
    gchar **password;
    /* Number */
    gchar *number;
    /* Roaming allowance */
    gboolean allow_roaming_set;
    gboolean allow_roaming;
    /* Protocol of the Rm interface */
    MMModemCdmaRmProtocol rm_protocol;
};

/*****************************************************************************/

guint
mm_bearer_properties_get_n_secondary (MMBearerProperties *self)
{
    guint total;

    total = self->priv->apn ? g_strv_length (self->priv->apn) : 0;
    return (total > 1 ? total - 1 : 0);
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_apn:
 * @self: a #MMBearerProperties.
 * @apn: Name of the access point.
 *
 * Sets the name of the access point to use when connecting.
 */
void
mm_bearer_properties_set_apn (MMBearerProperties *self,
                              const gchar *apn)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    g_strfreev (self->priv->apn);
    self->priv->apn = g_strsplit (apn, MM_BEARER_PROPERTY_SEPARATOR, -1);
}

/**
 * mm_bearer_properties_get_apn:
 * @self: a #MMBearerProperties.
 *
 * Gets the name of the access point to use when connecting.
 *
 * Returns: (transfer none): the access point, or #NULL if not set. Do not free the returned value, it is owned by @self.
 */
const gchar *
mm_bearer_properties_get_apn (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return (self->priv->apn ? self->priv->apn[0] : NULL);
}

const gchar *
mm_bearer_properties_get_secondary_apn (MMBearerProperties *self, guint i)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return ((self->priv->apn && g_strv_length (self->priv->apn) > (i + 1)) ? self->priv->apn[i + 1] : NULL);
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_allowed_auth:
 * @self: a #MMBearerProperties.
 * @allowed_auth: a bitmask of #MMBearerAllowedAuth values. %MM_BEARER_ALLOWED_AUTH_UNKNOWN may be given to request the modem-default method.
 *
 * Sets the authentication method to use.
 */
void
mm_bearer_properties_set_allowed_auth (MMBearerProperties *self,
                                       MMBearerAllowedAuth allowed_auth)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    self->priv->allowed_auth = allowed_auth;
}

/**
 * mm_bearer_properties_get_allowed_auth:
 * @self: a #MMBearerProperties.
 *
 * Gets the authentication methods allowed in the connection.
 *
 * Returns: a bitmask of #MMBearerAllowedAuth values, or %MM_BEARER_ALLOWED_AUTH_UNKNOWN to request the modem-default method.
 */
MMBearerAllowedAuth
mm_bearer_properties_get_allowed_auth (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), MM_BEARER_ALLOWED_AUTH_UNKNOWN);

    return self->priv->allowed_auth;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_user:
 * @self: a #MMBearerProperties.
 * @user: the username
 *
 * Sets the username used to authenticate with the access point.
 */
void
mm_bearer_properties_set_user (MMBearerProperties *self,
                               const gchar *user)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    g_strfreev (self->priv->user);
    self->priv->user = g_strsplit (user, MM_BEARER_PROPERTY_SEPARATOR, -1);
}

/**
 * mm_bearer_properties_get_user:
 * @self: a #MMBearerProperties.
 *
 * Gets the username used to authenticate with the access point.
 *
 * Returns: (transfer none): the username, or #NULL if not set. Do not free the returned value, it is owned by @self.
 */
const gchar *
mm_bearer_properties_get_user (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return (self->priv->user ? self->priv->user[0] : NULL);
}

const gchar *
mm_bearer_properties_get_secondary_user (MMBearerProperties *self, guint i)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return ((self->priv->user && g_strv_length (self->priv->user) > (i + 1)) ? self->priv->user[i + 1] : NULL);
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_password:
 * @self: a #MMBearerProperties.
 * @password: the password
 *
 * Sets the password used to authenticate with the access point.
 */
void
mm_bearer_properties_set_password (MMBearerProperties *self,
                                   const gchar *password)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    g_strfreev (self->priv->password);
    self->priv->password = g_strsplit (password, MM_BEARER_PROPERTY_SEPARATOR, -1);
}

/**
 * mm_bearer_properties_get_password:
 * @self: a #MMBearerProperties.
 *
 * Gets the password used to authenticate with the access point.
 *
 * Returns: (transfer none): the password, or #NULL if not set. Do not free the returned value, it is owned by @self.
 */
const gchar *
mm_bearer_properties_get_password (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return (self->priv->password ? self->priv->password[0] : NULL);
}

const gchar *
mm_bearer_properties_get_secondary_password (MMBearerProperties *self, guint i)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return ((self->priv->password && g_strv_length (self->priv->password) > (i + 1)) ? self->priv->password[i + 1] : NULL);
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_ip_type:
 * @self: a #MMBearerProperties.
 * @ip_type: a #MMBearerIpFamily.
 *
 * Sets the IP type to use.
 */
void
mm_bearer_properties_set_ip_type (MMBearerProperties *self,
                                  MMBearerIpFamily ip_type)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    self->priv->ip_type = ip_type;
}

/**
 * mm_bearer_properties_get_ip_type:
 * @self: a #MMBearerProperties.
 *
 * Sets the IP type to use.
 *
 * Returns: a #MMBearerIpFamily.
 */
MMBearerIpFamily
mm_bearer_properties_get_ip_type (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), MM_BEARER_IP_FAMILY_NONE);

    return self->priv->ip_type;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_allow_roaming:
 * @self: a #MMBearerProperties.
 * @allow_roaming: boolean value.
 *
 * Sets the flag to indicate whether roaming is allowed or not in the
 * connection.
 */
void
mm_bearer_properties_set_allow_roaming (MMBearerProperties *self,
                                        gboolean allow_roaming)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    self->priv->allow_roaming = allow_roaming;
    self->priv->allow_roaming_set = TRUE;
}

/**
 * mm_bearer_properties_get_allow_roaming:
 * @self: a #MMBearerProperties.
 *
 * Checks whether roaming is allowed in the connection.
 *
 * Returns: %TRUE if roaming is allowed, %FALSE otherwise..
 */
gboolean
mm_bearer_properties_get_allow_roaming (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), FALSE);

    return self->priv->allow_roaming;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_number:
 * @self: a #MMBearerProperties.
 * @number: the number.
 *
 * Sets the number to use when performing the connection.
 */
void
mm_bearer_properties_set_number (MMBearerProperties *self,
                                 const gchar *number)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    g_free (self->priv->number);
    self->priv->number = g_strdup (number);
}

/**
 * mm_bearer_properties_get_number:
 * @self: a #MMBearerProperties.
 *
 * Gets the number to use when performing the connection.
 *
 * Returns: (transfer none): the number, or #NULL if not set. Do not free the returned value, it is owned by @self.
 */
const gchar *
mm_bearer_properties_get_number (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    return self->priv->number;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_set_rm_protocol:
 * @self: a #MMBearerProperties.
 * @protocol: a #MMModemCdmaRmProtocol.
 *
 * Sets the RM protocol to use in the CDMA connection.
 */
void
mm_bearer_properties_set_rm_protocol (MMBearerProperties *self,
                                      MMModemCdmaRmProtocol protocol)
{
    g_return_if_fail (MM_IS_BEARER_PROPERTIES (self));

    self->priv->rm_protocol = protocol;
}

/**
 * mm_bearer_properties_get_rm_protocol:
 * @self: a #MMBearerProperties.
 *
 * Gets the RM protocol requested to use in the CDMA connection.
 *
 * Returns: a #MMModemCdmaRmProtocol.
 */
MMModemCdmaRmProtocol
mm_bearer_properties_get_rm_protocol (MMBearerProperties *self)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), MM_MODEM_CDMA_RM_PROTOCOL_UNKNOWN);

    return self->priv->rm_protocol;
}

/*****************************************************************************/

GVariant *
mm_bearer_properties_get_dictionary (MMBearerProperties *self)
{
    GVariantBuilder builder;

    /* We do allow NULL */
    if (!self)
        return NULL;

    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), NULL);

    g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

    if (self->priv->apn)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_APN,
                               g_variant_new_take_string (g_strjoinv (MM_BEARER_PROPERTY_SEPARATOR, self->priv->apn)));

    if (self->priv->allowed_auth != MM_BEARER_ALLOWED_AUTH_UNKNOWN)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_ALLOWED_AUTH,
                               g_variant_new_uint32 (self->priv->allowed_auth));

    if (self->priv->user)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_USER,
                               g_variant_new_take_string (g_strjoinv (MM_BEARER_PROPERTY_SEPARATOR, self->priv->user)));

    if (self->priv->password)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_PASSWORD,
                               g_variant_new_take_string (g_strjoinv (MM_BEARER_PROPERTY_SEPARATOR, self->priv->password)));

    if (self->priv->ip_type != MM_BEARER_IP_FAMILY_NONE)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_IP_TYPE,
                               g_variant_new_uint32 (self->priv->ip_type));

    if (self->priv->number)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_NUMBER,
                               g_variant_new_string (self->priv->number));

    if (self->priv->allow_roaming_set)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_ALLOW_ROAMING,
                               g_variant_new_boolean (self->priv->allow_roaming));

    if (self->priv->rm_protocol)
        g_variant_builder_add (&builder,
                               "{sv}",
                               PROPERTY_RM_PROTOCOL,
                               g_variant_new_uint32 (self->priv->rm_protocol));

    return g_variant_ref_sink (g_variant_builder_end (&builder));
}

/*****************************************************************************/


/**
 * mm_bearer_properties_consume_string:
 * @self: a #MMBearerProperties
 * @key: the key string.
 * @value: the value string.
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_properties_consume_string (MMBearerProperties *self,
                                     const gchar *key,
                                     const gchar *value,
                                     GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (self), FALSE);

    if (g_str_equal (key, PROPERTY_APN))
        mm_bearer_properties_set_apn (self, value);
    else if (g_str_equal (key, PROPERTY_ALLOWED_AUTH)) {
        GError *inner_error = NULL;
        MMBearerAllowedAuth allowed_auth;

        allowed_auth = mm_common_get_allowed_auth_from_string (value, &inner_error);
        if (inner_error) {
            g_propagate_error (error, inner_error);
            return FALSE;
        }
        mm_bearer_properties_set_allowed_auth (self, allowed_auth);
    } else if (g_str_equal (key, PROPERTY_USER))
        mm_bearer_properties_set_user (self, value);
    else if (g_str_equal (key, PROPERTY_PASSWORD))
        mm_bearer_properties_set_password (self, value);
    else if (g_str_equal (key, PROPERTY_IP_TYPE)) {
        GError *inner_error = NULL;
        MMBearerIpFamily ip_type;

        ip_type = mm_common_get_ip_type_from_string (value, &inner_error);
        if (inner_error) {
            g_propagate_error (error, inner_error);
            return FALSE;
        }
        mm_bearer_properties_set_ip_type (self, ip_type);
    } else if (g_str_equal (key, PROPERTY_ALLOW_ROAMING)) {
        GError *inner_error = NULL;
        gboolean allow_roaming;

        allow_roaming = mm_common_get_boolean_from_string (value, &inner_error);
        if (inner_error) {
            g_propagate_error (error, inner_error);
            return FALSE;
        }
        mm_bearer_properties_set_allow_roaming (self, allow_roaming);
    } else if (g_str_equal (key, PROPERTY_NUMBER))
        mm_bearer_properties_set_number (self, value);
    else if (g_str_equal (key, PROPERTY_RM_PROTOCOL)) {
        GError *inner_error = NULL;
        MMModemCdmaRmProtocol protocol;

        protocol = mm_common_get_rm_protocol_from_string (value, &inner_error);
        if (inner_error) {
            g_propagate_error (error, inner_error);
            return FALSE;
        }
        mm_bearer_properties_set_rm_protocol (self, protocol);
    } else {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_INVALID_ARGS,
                     "Invalid properties string, unexpected key '%s'",
                     key);
        return FALSE;
    }

    return TRUE;
}

typedef struct {
    MMBearerProperties *properties;
    GError *error;
} ParseKeyValueContext;

static gboolean
key_value_foreach (const gchar *key,
                   const gchar *value,
                   ParseKeyValueContext *ctx)
{
    return mm_bearer_properties_consume_string (ctx->properties,
                                                key,
                                                value,
                                                &ctx->error);
}

MMBearerProperties *
mm_bearer_properties_new_from_string (const gchar *str,
                                      GError **error)
{
    ParseKeyValueContext ctx;

    ctx.error = NULL;
    ctx.properties = mm_bearer_properties_new ();

    mm_common_parse_key_value_string (str,
                                      &ctx.error,
                                      (MMParseKeyValueForeachFn)key_value_foreach,
                                      &ctx);
    /* If error, destroy the object */
    if (ctx.error) {
        g_propagate_error (error, ctx.error);
        g_object_unref (ctx.properties);
        ctx.properties = NULL;
    }

    return ctx.properties;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_consume_variant:
 * @properties: a #MMBearerProperties
 * @key: the key string.
 * @value: a #GVariant
 * @error: (allow-none): Return location for error or %NULL.
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_properties_consume_variant (MMBearerProperties *properties,
                                      const gchar *key,
                                      GVariant *value,
                                      GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (properties), FALSE);

    if (g_str_equal (key, PROPERTY_APN))
        mm_bearer_properties_set_apn (
            properties,
            g_variant_get_string (value, NULL));
    else if (g_str_equal (key, PROPERTY_ALLOWED_AUTH))
        mm_bearer_properties_set_allowed_auth (
            properties,
            g_variant_get_uint32 (value));
    else if (g_str_equal (key, PROPERTY_USER))
        mm_bearer_properties_set_user (
            properties,
            g_variant_get_string (value, NULL));
    else if (g_str_equal (key, PROPERTY_PASSWORD))
        mm_bearer_properties_set_password (
            properties,
            g_variant_get_string (value, NULL));
    else if (g_str_equal (key, PROPERTY_IP_TYPE))
        mm_bearer_properties_set_ip_type (
            properties,
            g_variant_get_uint32 (value));
    else if (g_str_equal (key, PROPERTY_NUMBER))
        mm_bearer_properties_set_number (
            properties,
            g_variant_get_string (value, NULL));
    else if (g_str_equal (key, PROPERTY_ALLOW_ROAMING))
        mm_bearer_properties_set_allow_roaming (
            properties,
            g_variant_get_boolean (value));
    else {
        /* Set error */
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_INVALID_ARGS,
                     "Invalid properties dictionary, unexpected key '%s'",
                     key);
        return FALSE;
    }

    return TRUE;
}

MMBearerProperties *
mm_bearer_properties_new_from_dictionary (GVariant *dictionary,
                                          GError **error)
{
    GError *inner_error = NULL;
    GVariantIter iter;
    gchar *key;
    GVariant *value;
    MMBearerProperties *properties;

    properties = mm_bearer_properties_new ();
    if (!dictionary)
        return properties;

    if (!g_variant_is_of_type (dictionary, G_VARIANT_TYPE ("a{sv}"))) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_INVALID_ARGS,
                     "Cannot create Bearer properties from dictionary: "
                     "invalid variant type received");
        g_object_unref (properties);
        return NULL;
    }

    g_variant_iter_init (&iter, dictionary);
    while (!inner_error &&
           g_variant_iter_next (&iter, "{sv}", &key, &value)) {
        mm_bearer_properties_consume_variant (properties,
                                                     key,
                                                     value,
                                                     &inner_error);
        g_free (key);
        g_variant_unref (value);
    }

    /* If error, destroy the object */
    if (inner_error) {
        g_propagate_error (error, inner_error);
        g_object_unref (properties);
        properties = NULL;
    }

    return properties;
}

/*****************************************************************************/

/**
 * mm_bearer_properties_dup:
 * @orig: a #MMBearerProperties
 *
 * Creates a copy of @orig.
 *
 * Returns: (transfer full): a newly created #MMBearerProperties
 */
MMBearerProperties *
mm_bearer_properties_dup (MMBearerProperties *orig)
{
    GVariant *dict;
    MMBearerProperties *copy;
    GError *error = NULL;

    g_return_val_if_fail (MM_IS_BEARER_PROPERTIES (orig), NULL);

    dict = mm_bearer_properties_get_dictionary (orig);
    copy = mm_bearer_properties_new_from_dictionary (dict, &error);
    g_assert_no_error (error);
    g_variant_unref (dict);

    return copy;
}

/*****************************************************************************/

static gboolean
strv_equal (const gchar **a, const gchar **b)
{
    guint alen, blen, i;

    alen = (a ? g_strv_length ((GStrv)a) : 0);
    blen = (b ? g_strv_length ((GStrv)b) : 0);

    if (alen != blen)
        return FALSE;

    for (i = 0; i < alen; i++) {
        if (!g_str_equal (a[i], b[i]))
            return FALSE;
    }
    return TRUE;
}

gboolean
mm_bearer_properties_cmp (MMBearerProperties *a,
                          MMBearerProperties *b)
{
    return ((strv_equal ((const gchar **)a->priv->apn, (const gchar **)b->priv->apn)) &&
            (a->priv->ip_type == b->priv->ip_type) &&
            (!g_strcmp0 (a->priv->number, b->priv->number)) &&
            (a->priv->allowed_auth == b->priv->allowed_auth) &&
            (strv_equal ((const gchar **)a->priv->user, (const gchar **)b->priv->user)) &&
            (strv_equal ((const gchar **)a->priv->password, (const gchar **)b->priv->password)) &&
            (a->priv->allow_roaming == b->priv->allow_roaming) &&
            (a->priv->allow_roaming_set == b->priv->allow_roaming_set) &&
            (a->priv->rm_protocol == b->priv->rm_protocol));
}

/*****************************************************************************/

/**
 * mm_bearer_properties_new:
 *
 * Creates a new empty #MMBearerProperties.
 *
 * Returns: (transfer full): a #MMBearerProperties. The returned value should be freed with g_object_unref().
 */
MMBearerProperties *
mm_bearer_properties_new (void)
{
    return (MM_BEARER_PROPERTIES (
                g_object_new (MM_TYPE_BEARER_PROPERTIES, NULL)));
}

static void
mm_bearer_properties_init (MMBearerProperties *self)
{
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE ((self),
                                              MM_TYPE_BEARER_PROPERTIES,
                                              MMBearerPropertiesPrivate);

    /* Some defaults */
    self->priv->allow_roaming = TRUE;
    self->priv->rm_protocol = MM_MODEM_CDMA_RM_PROTOCOL_UNKNOWN;
    self->priv->allowed_auth = MM_BEARER_ALLOWED_AUTH_UNKNOWN;
    self->priv->ip_type = MM_BEARER_IP_FAMILY_NONE;
}

static void
finalize (GObject *object)
{
    MMBearerProperties *self = MM_BEARER_PROPERTIES (object);

    g_strfreev (self->priv->apn);
    g_strfreev (self->priv->user);
    g_strfreev (self->priv->password);
    g_free (self->priv->number);

    G_OBJECT_CLASS (mm_bearer_properties_parent_class)->finalize (object);
}

static void
mm_bearer_properties_class_init (MMBearerPropertiesClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMBearerPropertiesPrivate));

    object_class->finalize = finalize;
}
