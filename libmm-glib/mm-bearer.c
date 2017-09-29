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

#include "mm-helpers.h"
#include "mm-bearer.h"

/**
 * SECTION: mm-bearer
 * @title: MMBearer
 * @short_description: The Bearer interface
 *
 * The #MMBearer is an object providing access to the methods, signals and
 * properties of the Bearer interface.
 *
 * When the bearer is exposed and available in the bus, it is ensured that at
 * least this interface is also available.
 */

G_DEFINE_TYPE (MMBearer, mm_bearer, MM_GDBUS_TYPE_BEARER_PROXY)

struct _MMBearerPrivate {
    /* IPv4 config */
    GMutex ipv4_config_mutex;
    guint ipv4_config_id;
    MMBearerIpConfig *ipv4_config;

    /* IPv6 config */
    GMutex ipv6_config_mutex;
    guint ipv6_config_id;
    MMBearerIpConfig *ipv6_config;

    /* Properties */
    GMutex properties_mutex;
    guint properties_id;
    MMBearerProperties *properties;

    /* Stats */
    GMutex stats_mutex;
    guint stats_id;
    MMBearerStats *stats;
};

/*****************************************************************************/

/**
 * mm_bearer_get_path:
 * @self: A #MMBearer.
 *
 * Gets the DBus path of the #MMBearer object.
 *
 * Returns: (transfer none): The DBus path of the #MMBearer object.
 */
const gchar *
mm_bearer_get_path (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    RETURN_NON_EMPTY_CONSTANT_STRING (
        g_dbus_proxy_get_object_path (G_DBUS_PROXY (self)));
}

/**
 * mm_bearer_dup_path:
 * @self: A #MMBearer.
 *
 * Gets a copy of the DBus path of the #MMBearer object.
 *
 * Returns: (transfer full): The DBus path of the #MMBearer object. The returned value should be freed with g_free().
 */
gchar *
mm_bearer_dup_path (MMBearer *self)
{
    gchar *value;

    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    g_object_get (G_OBJECT (self),
                  "g-object-path", &value,
                  NULL);

    RETURN_NON_EMPTY_STRING (value);
}

/*****************************************************************************/

/**
 * mm_bearer_get_interface:
 * @self: A #MMBearer.
 *
 * Gets the operating system name for the network data interface that provides
 * packet data using this #MMBearer. This will only be available once the #MMBearer
 * is in connected state.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_dup_interface() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): The name of the interface, or %NULL if it couldn't be retrieved.
 */
const gchar *
mm_bearer_get_interface (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    RETURN_NON_EMPTY_CONSTANT_STRING (
        mm_gdbus_bearer_get_interface (MM_GDBUS_BEARER (self)));
}

/**
 * mm_bearer_dup_interface:
 * @self: A #MMBearer.
 *
 * Gets a copy of the operating system name for the network data interface that provides
 * packet data using this #MMBearer. This will only be available once the #MMBearer
 * is in connected state.
 *
 * Returns: (transfer full): The name of the interface, or %NULL if it couldn't be retrieved. The returned value should be freed with g_free().
 */
gchar *
mm_bearer_dup_interface (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    RETURN_NON_EMPTY_STRING (
        mm_gdbus_bearer_dup_interface (MM_GDBUS_BEARER (self)));
}

/*****************************************************************************/

/**
 * mm_bearer_get_connected:
 * @self: A #MMBearer.
 *
 * Checks whether or not the #MMBearer is connected and thus whether packet data
 * communication is possible.
 *
 * Returns: %TRUE if the #MMBearer is connected, #FALSE otherwise.
 */
gboolean
mm_bearer_get_connected (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_get_connected (MM_GDBUS_BEARER (self));
}

/*****************************************************************************/

/**
 * mm_bearer_get_suspended:
 * @self: A #MMBearer.
 *
 * Checks whether or not the #MMBearer is suspended (but not deactivated) while the
 * device is handling other communications, like a voice call.
 *
 * Returns: %TRUE if packet data service is suspended in the #MMBearer, #FALSE otherwise.
 */
gboolean
mm_bearer_get_suspended (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_get_suspended (MM_GDBUS_BEARER (self));
}

/*****************************************************************************/

/**
 * mm_bearer_get_ip_timeout:
 * @self: A #MMBearer.
 *
 * Gets the maximum time to wait for the bearer to retrieve a valid IP address.
 *
 * Returns: The IP timeout, or 0 if no specific one given.
 */
guint
mm_bearer_get_ip_timeout (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), 0);

    return mm_gdbus_bearer_get_ip_timeout (MM_GDBUS_BEARER (self));
}

/*****************************************************************************/

static void
ipv4_config_updated (MMBearer *self,
                     GParamSpec *pspec)
{
    g_mutex_lock (&self->priv->ipv4_config_mutex);
    {
        GVariant *dictionary;

        g_clear_object (&self->priv->ipv4_config);

        /* TODO: update existing object instead of re-creating? */
        dictionary = mm_gdbus_bearer_get_ip4_config (MM_GDBUS_BEARER (self));
        if (dictionary) {
            GError *error = NULL;

            self->priv->ipv4_config = mm_bearer_ip_config_new_from_dictionary (dictionary, &error);
            if (error) {
                g_warning ("Invalid IPv4 configuration update received: %s", error->message);
                g_error_free (error);
            }
        }
    }
    g_mutex_unlock (&self->priv->ipv4_config_mutex);
}

static void
ensure_internal_ipv4_config (MMBearer *self,
                             MMBearerIpConfig **dup)
{
    g_mutex_lock (&self->priv->ipv4_config_mutex);
    {
        /* If this is the first time ever asking for the object, setup the
         * update listener and the initial object, if any. */
        if (!self->priv->ipv4_config_id) {
            GVariant *dictionary;

            dictionary = mm_gdbus_bearer_dup_ip4_config (MM_GDBUS_BEARER (self));
            if (dictionary) {
                GError *error = NULL;

                self->priv->ipv4_config = mm_bearer_ip_config_new_from_dictionary (dictionary, &error);
                if (error) {
                    g_warning ("Invalid initial IPv4 configuration: %s", error->message);
                    g_error_free (error);
                }
                g_variant_unref (dictionary);
            }

            /* No need to clear this signal connection when freeing self */
            self->priv->ipv4_config_id =
                g_signal_connect (self,
                                  "notify::ip4-config",
                                  G_CALLBACK (ipv4_config_updated),
                                  NULL);
        }

        if (dup && self->priv->ipv4_config)
            *dup = g_object_ref (self->priv->ipv4_config);
    }
    g_mutex_unlock (&self->priv->ipv4_config_mutex);
}

/**
 * mm_bearer_get_ipv4_config:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerIpConfig object specifying the IPv4 configuration to use in
 * the bearer.
 *
 * <warning>The values reported by @self are not updated when the values in the
 * interface change. Instead, the client is expected to call
 * mm_bearer_get_ipv4_config() again to get a new #MMBearerIpConfig with the
 * new values.</warning>
 *
 * Returns: (transfer full): A #MMBearerIpConfig that must be freed with g_object_unref() or %NULL if unknown.
 */
MMBearerIpConfig *
mm_bearer_get_ipv4_config (MMBearer *self)
{
    MMBearerIpConfig *config = NULL;

    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_ipv4_config (self, &config);
    return config;
}

/**
 * mm_bearer_peek_ipv4_config:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerIpConfig object specifying the IPv4 configuration to use in
 * the bearer.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_get_ipv4_config() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): A #MMBearerIpConfig. Do not free the returned value, it belongs to @self.
 */
MMBearerIpConfig *
mm_bearer_peek_ipv4_config (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_ipv4_config (self, NULL);
    return self->priv->ipv4_config;
}

/*****************************************************************************/

static void
ipv6_config_updated (MMBearer *self,
                     GParamSpec *pspec)
{
    g_mutex_lock (&self->priv->ipv6_config_mutex);
    {
        GVariant *dictionary;

        g_clear_object (&self->priv->ipv6_config);

        /* TODO: update existing object instead of re-creating? */
        dictionary = mm_gdbus_bearer_get_ip6_config (MM_GDBUS_BEARER (self));
        if (dictionary) {
            GError *error = NULL;

            self->priv->ipv6_config = mm_bearer_ip_config_new_from_dictionary (dictionary, &error);
            if (error) {
                g_warning ("Invalid IPv6 configuration update received: %s", error->message);
                g_error_free (error);
            }
        }
    }
    g_mutex_unlock (&self->priv->ipv6_config_mutex);
}

static void
ensure_internal_ipv6_config (MMBearer *self,
                             MMBearerIpConfig **dup)
{
    g_mutex_lock (&self->priv->ipv6_config_mutex);
    {
        /* If this is the first time ever asking for the object, setup the
         * update listener and the initial object, if any. */
        if (!self->priv->ipv6_config_id) {
            GVariant *dictionary;

            dictionary = mm_gdbus_bearer_dup_ip6_config (MM_GDBUS_BEARER (self));
            if (dictionary) {
                GError *error = NULL;

                self->priv->ipv6_config = mm_bearer_ip_config_new_from_dictionary (dictionary, &error);
                if (error) {
                    g_warning ("Invalid initial IPv6 configuration: %s", error->message);
                    g_error_free (error);
                }
                g_variant_unref (dictionary);
            }

            /* No need to clear this signal connection when freeing self */
            self->priv->ipv6_config_id =
                g_signal_connect (self,
                                  "notify::ip6-config",
                                  G_CALLBACK (ipv6_config_updated),
                                  NULL);
        }

        if (dup && self->priv->ipv6_config)
            *dup = g_object_ref (self->priv->ipv6_config);
    }
    g_mutex_unlock (&self->priv->ipv6_config_mutex);
}

/**
 * mm_bearer_get_ipv6_config:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerIpConfig object specifying the IPv6 configuration to use in
 * the bearer.
 *
 * <warning>The values reported by @self are not updated when the values in the
 * interface change. Instead, the client is expected to call
 * mm_bearer_get_ipv6_config() again to get a new #MMBearerIpConfig with the
 * new values.</warning>
 *
 * Returns: (transfer full): A #MMBearerIpConfig that must be freed with g_object_unref() or %NULL if unknown.
 */
MMBearerIpConfig *
mm_bearer_get_ipv6_config (MMBearer *self)
{
    MMBearerIpConfig *config = NULL;

    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_ipv6_config (self, &config);
    return config;
}

/**
 * mm_bearer_peek_ipv6_config:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerIpConfig object specifying the IPv6 configuration to use in
 * the bearer.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_get_ipv6_config() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): A #MMBearerIpConfig. Do not free the returned value, it belongs to @self.
 */
MMBearerIpConfig *
mm_bearer_peek_ipv6_config (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_ipv6_config (self, NULL);
    return self->priv->ipv6_config;
}

/*****************************************************************************/

static void
properties_updated (MMBearer *self,
                    GParamSpec *pspec)
{
    g_mutex_lock (&self->priv->properties_mutex);
    {
        GVariant *dictionary;

        g_clear_object (&self->priv->properties);

        /* TODO: update existing object instead of re-creating? */
        dictionary = mm_gdbus_bearer_get_properties (MM_GDBUS_BEARER (self));
        if (dictionary) {
            GError *error = NULL;

            self->priv->properties = mm_bearer_properties_new_from_dictionary (dictionary, &error);
            if (error) {
                g_warning ("Invalid bearer properties received: %s", error->message);
                g_error_free (error);
            }
        }
    }
    g_mutex_unlock (&self->priv->properties_mutex);
}

static void
ensure_internal_properties (MMBearer *self,
                            MMBearerProperties **dup)
{
    g_mutex_lock (&self->priv->properties_mutex);
    {
        /* If this is the first time ever asking for the object, setup the
         * update listener and the initial object, if any. */
        if (!self->priv->properties_id) {
            GVariant *dictionary;

            dictionary = mm_gdbus_bearer_dup_properties (MM_GDBUS_BEARER (self));
            if (dictionary) {
                GError *error = NULL;

                self->priv->properties = mm_bearer_properties_new_from_dictionary (dictionary, &error);
                if (error) {
                    g_warning ("Invalid initial bearer properties: %s", error->message);
                    g_error_free (error);
                }
                g_variant_unref (dictionary);
            }

            /* No need to clear this signal connection when freeing self */
            self->priv->properties_id =
                g_signal_connect (self,
                                  "notify::properties",
                                  G_CALLBACK (properties_updated),
                                  NULL);
        }

        if (dup && self->priv->properties)
            *dup = g_object_ref (self->priv->properties);
    }
    g_mutex_unlock (&self->priv->properties_mutex);
}

/**
 * mm_bearer_get_properties:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerProperties object specifying the properties which were used
 * to create the bearer.
 *
 * <warning>The values reported by @self are not updated when the values in the
 * interface change. Instead, the client is expected to call
 * mm_bearer_get_properties() again to get a new #MMBearerProperties with the
 * new values.</warning>
 *
 * Returns: (transfer full): A #MMBearerProperties that must be freed with g_object_unref() or %NULL if unknown.
 */
MMBearerProperties *
mm_bearer_get_properties (MMBearer *self)
{
    MMBearerProperties *props = NULL;

    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_properties (self, &props);
    return props;
}

/**
 * mm_bearer_peek_properties:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerProperties object specifying the properties which were used
 * to create the bearer.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_get_properties() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): A #MMBearerProperties. Do not free the returned value, it belongs to @self.
 */
MMBearerProperties *
mm_bearer_peek_properties (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_properties (self, NULL);
    return self->priv->properties;
}

/*****************************************************************************/

static void
stats_updated (MMBearer *self,
               GParamSpec *pspec)
{
    g_mutex_lock (&self->priv->stats_mutex);
    {
        GVariant *dictionary;

        g_clear_object (&self->priv->stats);

        dictionary = mm_gdbus_bearer_get_stats (MM_GDBUS_BEARER (self));
        if (dictionary) {
            GError *error = NULL;

            self->priv->stats = mm_bearer_stats_new_from_dictionary (dictionary, &error);
            if (error) {
                g_warning ("Invalid bearer stats update received: %s", error->message);
                g_error_free (error);
            }
        }
    }
    g_mutex_unlock (&self->priv->stats_mutex);
}

static void
ensure_internal_stats (MMBearer *self,
                       MMBearerStats **dup)
{
    g_mutex_lock (&self->priv->stats_mutex);
    {
        /* If this is the first time ever asking for the object, setup the
         * update listener and the initial object, if any. */
        if (!self->priv->stats_id) {
            GVariant *dictionary;

            dictionary = mm_gdbus_bearer_dup_stats (MM_GDBUS_BEARER (self));
            if (dictionary) {
                GError *error = NULL;

                self->priv->stats = mm_bearer_stats_new_from_dictionary (dictionary, &error);
                if (error) {
                    g_warning ("Invalid initial bearer stats: %s", error->message);
                    g_error_free (error);
                }
                g_variant_unref (dictionary);
            }

            /* No need to clear this signal connection when freeing self */
            self->priv->stats_id =
                g_signal_connect (self,
                                  "notify::stats",
                                  G_CALLBACK (stats_updated),
                                  NULL);
        }

        if (dup && self->priv->stats)
            *dup = g_object_ref (self->priv->stats);
    }
    g_mutex_unlock (&self->priv->stats_mutex);
}

/**
 * mm_bearer_get_stats:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerStats object specifying the statistics of the current bearer
 * connection.
 *
 * <warning>The values reported by @self are not updated when the values in the
 * interface change. Instead, the client is expected to call
 * mm_bearer_get_stats() again to get a new #MMBearerStats with the
 * new values.</warning>
 *
 * Returns: (transfer full): A #MMBearerStats that must be freed with g_object_unref() or %NULL if unknown.
 */
MMBearerStats *
mm_bearer_get_stats (MMBearer *self)
{
    MMBearerStats *config = NULL;

    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_stats (self, &config);
    return config;
}

/**
 * mm_bearer_peek_stats:
 * @self: A #MMBearer.
 *
 * Gets a #MMBearerStats object specifying the statistics of the current bearer
 * connection.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_get_stats() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): A #MMBearerStats. Do not free the returned value, it belongs to @self.
 */
MMBearerStats *
mm_bearer_peek_stats (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    ensure_internal_stats (self, NULL);
    return self->priv->stats;
}

/*****************************************************************************/

/**
 * mm_bearer_get_connected_apns:
 * @self: A #MMBearer.
 *
 * Gets the list of connected APNs.
 *
 * <warning>The returned value is only valid until the property changes so
 * it is only safe to use this function on the thread where
 * @self was constructed. Use mm_bearer_dup_connected_apns() if on another
 * thread.</warning>
 *
 * Returns: (transfer none): The connected apns, or %NULL if none available. Do not free the returned value, it belongs to @self.
 */
const gchar * const *
mm_bearer_get_connected_apns (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    return mm_gdbus_bearer_get_connected_apns (MM_GDBUS_BEARER (self));
}

/**
 * mm_bearer_dup_connected_apns:
 * @self: A #MMBearer.
 *
 * Gets a copy of the list of connected APNs.
 *
 * Returns: (transfer full): The connected apns, or %NULL if none available. The returned value should be freed with g_strfreev().
 */
gchar **
mm_bearer_dup_connected_apns (MMBearer *self)
{
    g_return_val_if_fail (MM_IS_BEARER (self), NULL);

    return mm_gdbus_bearer_dup_connected_apns (MM_GDBUS_BEARER (self));
}

/*****************************************************************************/

/**
 * mm_bearer_connect_finish:
 * @self: A #MMBearer.
 * @res: The #GAsyncResult obtained from the #GAsyncReadyCallback passed to mm_bearer_connect().
 * @error: Return location for error or %NULL.
 *
 * Finishes an operation started with mm_bearer_connect().
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_connect_finish (MMBearer *self,
                          GAsyncResult *res,
                          GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_call_connect_finish (MM_GDBUS_BEARER (self), res, error);
}

/**
 * mm_bearer_connect:
 * @self: A #MMBearer.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied or %NULL.
 * @user_data: User data to pass to @callback.
 *
 * Asynchronously requests activation of a packet data connection with the
 * network using this #MMBearer properties.
 *
 * When the operation is finished, @callback will be invoked in the <link linkend="g-main-context-push-thread-default">thread-default main loop</link> of the thread you are calling this method from.
 * You can then call mm_bearer_connect_finish() to get the result of the operation.
 *
 * See mm_bearer_connect_sync() for the synchronous, blocking version of this method.
 */
void
mm_bearer_connect (MMBearer *self,
                   GCancellable *cancellable,
                   GAsyncReadyCallback callback,
                   gpointer user_data)
{
    g_return_if_fail (MM_IS_BEARER (self));

    mm_gdbus_bearer_call_connect (MM_GDBUS_BEARER (self), cancellable, callback, user_data);
}

/**
 * mm_bearer_connect_sync:
 * @self: A #MMBearer.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Synchronously requests activation of a packet data connection with the
 * network using this #MMBearer properties.
 *
 * The calling thread is blocked until a reply is received.
 * See mm_bearer_connect() for the asynchronous version of this method.
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_connect_sync (MMBearer *self,
                        GCancellable *cancellable,
                        GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_call_connect_sync (MM_GDBUS_BEARER (self), cancellable, error);
}

/*****************************************************************************/

/**
 * mm_bearer_disconnect:
 * @self: A #MMBearer.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @callback: A #GAsyncReadyCallback to call when the request is satisfied or %NULL.
 * @user_data: User data to pass to @callback.
 *
 * Synchronously requests disconnection and deactivation of the packet data connection.
 *
 * When the operation is finished, @callback will be invoked in the <link linkend="g-main-context-push-thread-default">thread-default main loop</link> of the thread you are calling this method from.
 * You can then call mm_bearer_disconnect_finish() to get the result of the operation.
 *
 * See mm_bearer_disconnect_sync() for the synchronous, blocking version of this method.
 */
void
mm_bearer_disconnect (MMBearer *self,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    g_return_if_fail (MM_IS_BEARER (self));

    mm_gdbus_bearer_call_disconnect (MM_GDBUS_BEARER (self), cancellable, callback, user_data);
}

/**
 * mm_bearer_disconnect_finish:
 * @self: A #MMBearer.
 * @res: The #GAsyncResult obtained from the #GAsyncReadyCallback passed to mm_bearer_disconnect().
 * @error: Return location for error or %NULL.
 *
 * Finishes an operation started with mm_bearer_disconnect().
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_disconnect_finish (MMBearer *self,
                             GAsyncResult *res,
                             GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_call_disconnect_finish (MM_GDBUS_BEARER (self), res, error);
}

/**
 * mm_bearer_disconnect_sync:
 * @self: A #MMBearer.
 * @cancellable: (allow-none): A #GCancellable or %NULL.
 * @error: Return location for error or %NULL.
 *
 * Synchronously requests disconnection and deactivation of the packet data connection.
 *
 * The calling thread is blocked until a reply is received.
 * See mm_bearer_disconnect() for the asynchronous version of this method.
 *
 * Returns: %TRUE if the operation succeded, %FALSE if @error is set.
 */
gboolean
mm_bearer_disconnect_sync (MMBearer *self,
                           GCancellable *cancellable,
                           GError **error)
{
    g_return_val_if_fail (MM_IS_BEARER (self), FALSE);

    return mm_gdbus_bearer_call_disconnect_sync (MM_GDBUS_BEARER (self), cancellable, error);
}

/*****************************************************************************/

static void
mm_bearer_init (MMBearer *self)
{
    /* Setup private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_BEARER,
                                              MMBearerPrivate);
    g_mutex_init (&self->priv->ipv4_config_mutex);
    g_mutex_init (&self->priv->ipv6_config_mutex);
    g_mutex_init (&self->priv->properties_mutex);
}

static void
finalize (GObject *object)
{
    MMBearer *self = MM_BEARER (object);

    g_mutex_clear (&self->priv->ipv4_config_mutex);
    g_mutex_clear (&self->priv->ipv6_config_mutex);
    g_mutex_clear (&self->priv->properties_mutex);

    G_OBJECT_CLASS (mm_bearer_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
    MMBearer *self = MM_BEARER (object);

    g_clear_object (&self->priv->ipv4_config);
    g_clear_object (&self->priv->ipv6_config);
    g_clear_object (&self->priv->properties);

    G_OBJECT_CLASS (mm_bearer_parent_class)->dispose (object);
}

static void
mm_bearer_class_init (MMBearerClass *bearer_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (bearer_class);

    g_type_class_add_private (object_class, sizeof (MMBearerPrivate));

    /* Virtual methods */
    object_class->dispose = dispose;
    object_class->finalize = finalize;
}
