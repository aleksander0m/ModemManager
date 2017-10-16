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
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 * Copyright (C) 2011 Google, Inc.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ModemManager.h>
#include <mm-errors-types.h>
#include <mm-gdbus-modem.h>

#include "mm-context.h"
#include "mm-base-modem.h"

#include "mm-log.h"
#include "mm-port-enums-types.h"
#include "mm-serial-parsers.h"
#include "mm-modem-helpers.h"

G_DEFINE_ABSTRACT_TYPE (MMBaseModem, mm_base_modem, MM_GDBUS_TYPE_OBJECT_SKELETON);

enum {
    PROP_0,
    PROP_VALID,
    PROP_MAX_TIMEOUTS,
    PROP_DEVICE,
    PROP_DRIVERS,
    PROP_PLUGIN,
    PROP_VENDOR_ID,
    PROP_PRODUCT_ID,
    PROP_CONNECTION,
    PROP_REPROBE,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

struct _MMBaseModemPrivate {
    /* The connection to the system bus */
    GDBusConnection *connection;

    /* Modem-wide cancellable. If it ever gets cancelled, no further operations
     * should be done by the modem. */
    GCancellable *cancellable;
    gulong invalid_if_cancelled;

    gchar *device;
    gchar **drivers;
    gchar *plugin;

    guint vendor_id;
    guint product_id;

    gboolean hotplugged;
    gboolean valid;
    gboolean reprobe;

    guint max_timeouts;

    /* The authorization provider */
    MMAuthProvider *authp;
    GCancellable *authp_cancellable;

    GHashTable *ports;
    MMPortSerialAt *primary;
    MMPortSerialAt *secondary;
    MMPortSerialQcdm *qcdm;
    GList *data;

    /* GPS-enabled modems will have an AT port for control, and a raw serial
     * port to receive all GPS traces */
    MMPortSerialAt *gps_control;
    MMPortSerialGps *gps;

#if defined WITH_QMI
    /* QMI ports */
    GList *qmi;
#endif

#if defined WITH_MBIM
    /* MBIM ports */
    GList *mbim;
#endif
};

static gchar *
get_hash_key (const gchar *subsys,
              const gchar *name)
{
    return g_strdup_printf ("%s%s", subsys, name);
}

static void
serial_port_timed_out_cb (MMPortSerial *port,
                          guint n_consecutive_timeouts,
                          gpointer user_data)
{
    MMBaseModem *self = (MM_BASE_MODEM (user_data));

    if (self->priv->max_timeouts > 0 &&
        n_consecutive_timeouts >= self->priv->max_timeouts) {
        mm_warn ("(%s/%s) port timed out %u times, marking modem '%s' as disabled",
                 mm_port_type_get_string (mm_port_get_port_type (MM_PORT (port))),
                 mm_port_get_device (MM_PORT (port)),
                 n_consecutive_timeouts,
                 g_dbus_object_get_object_path (G_DBUS_OBJECT (self)));

        /* Only set action to invalidate modem if not already done */
        g_cancellable_cancel (self->priv->cancellable);
    }
}

gboolean
mm_base_modem_grab_port (MMBaseModem         *self,
                         MMKernelDevice      *kernel_device,
                         MMPortType           ptype,
                         MMPortSerialAtFlag   at_pflags,
                         GError             **error)
{
    MMPort      *port;
    gchar       *key;
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_BASE_MODEM (self), FALSE);
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (kernel_device), FALSE);

    subsys = mm_kernel_device_get_subsystem (kernel_device);
    name   = mm_kernel_device_get_name      (kernel_device);

    g_return_val_if_fail (subsys != NULL, FALSE);
    g_return_val_if_fail (name != NULL, FALSE);

    /* Only allow 'tty', 'net' and 'cdc-wdm' ports */
    if (!g_str_equal (subsys, "net") &&
        !g_str_equal (subsys, "tty") &&
        !(g_str_has_prefix (subsys, "usb") && g_str_has_prefix (name, "cdc-wdm")) &&
        !g_str_equal (subsys, "virtual")) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_UNSUPPORTED,
                     "Cannot add port '%s/%s', unhandled subsystem",
                     subsys,
                     name);
        return FALSE;
    }

    /* Check whether we already have it stored */
    key = get_hash_key (subsys, name);
    port = g_hash_table_lookup (self->priv->ports, key);
    if (port) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_UNSUPPORTED,
                     "Cannot add port '%s/%s', already exists",
                     subsys,
                     name);
        g_free (key);
        return FALSE;
    }

    /* Explicitly ignored ports, grab them but explicitly flag them as ignored
     * right away, all the same way (i.e. regardless of subsystem). */
    if (ptype == MM_PORT_TYPE_IGNORED) {
        port = MM_PORT (g_object_new (MM_TYPE_PORT,
                                      MM_PORT_DEVICE, name,
                                      MM_PORT_TYPE, MM_PORT_TYPE_IGNORED,
                                      NULL));
    }
    /* Serial ports... */
    else if (g_str_equal (subsys, "tty")) {
        if (ptype == MM_PORT_TYPE_QCDM)
            /* QCDM port */
            port = MM_PORT (mm_port_serial_qcdm_new (name));
        else if (ptype == MM_PORT_TYPE_AT) {
            /* AT port */
            port = MM_PORT (mm_port_serial_at_new (name, MM_PORT_SUBSYS_TTY));

            /* Set common response parser */
            mm_port_serial_at_set_response_parser (MM_PORT_SERIAL_AT (port),
                                                   mm_serial_parser_v1_parse,
                                                   mm_serial_parser_v1_new (),
                                                   mm_serial_parser_v1_destroy);
            /* Store flags already */
            mm_port_serial_at_set_flags (MM_PORT_SERIAL_AT (port), at_pflags);
        } else if (ptype == MM_PORT_TYPE_GPS) {
            /* Raw GPS port */
            port = MM_PORT (mm_port_serial_gps_new (name));
        } else {
            g_set_error (error,
                         MM_CORE_ERROR,
                         MM_CORE_ERROR_UNSUPPORTED,
                         "Cannot add port '%s/%s', unhandled serial type",
                         subsys,
                         name);
            g_free (key);
            return FALSE;
        }

        /* For serial ports, enable port timeout checks */
        g_signal_connect (port,
                          "timed-out",
                          G_CALLBACK (serial_port_timed_out_cb),
                          self);

        /* For serial ports, optionally use a specific baudrate */
        if (mm_kernel_device_has_property (kernel_device, "ID_MM_TTY_BAUDRATE"))
            g_object_set (port,
                          MM_PORT_SERIAL_BAUD, mm_kernel_device_get_property_as_int (kernel_device, "ID_MM_TTY_BAUDRATE"),
                          NULL);
    }
    /* Net ports... */
    else if (g_str_equal (subsys, "net")) {
        port = MM_PORT (g_object_new (MM_TYPE_PORT,
                                      MM_PORT_DEVICE, name,
                                      MM_PORT_SUBSYS, MM_PORT_SUBSYS_NET,
                                      MM_PORT_TYPE, MM_PORT_TYPE_NET,
                                      NULL));
    }
    /* cdc-wdm ports... */
    else if (g_str_has_prefix (subsys, "usb") &&
             g_str_has_prefix (name, "cdc-wdm")) {
#if defined WITH_QMI
        if (ptype == MM_PORT_TYPE_QMI)
            port = MM_PORT (mm_port_qmi_new (name));
#endif
#if defined WITH_MBIM
        if (!port && ptype == MM_PORT_TYPE_MBIM)
            port = MM_PORT (mm_port_mbim_new (name));
#endif

        /* Non-serial AT port */
        if (!port && ptype == MM_PORT_TYPE_AT) {
            port = MM_PORT (mm_port_serial_at_new (name, MM_PORT_SUBSYS_USB));

            /* Set common response parser */
            mm_port_serial_at_set_response_parser (MM_PORT_SERIAL_AT (port),
                                                   mm_serial_parser_v1_parse,
                                                   mm_serial_parser_v1_new (),
                                                   mm_serial_parser_v1_destroy);
            /* Store flags already */
            mm_port_serial_at_set_flags (MM_PORT_SERIAL_AT (port), at_pflags);
        }

        if (!port) {
            g_set_error (error,
                         MM_CORE_ERROR,
                         MM_CORE_ERROR_UNSUPPORTED,
                         "Cannot add port '%s/%s', unsupported",
                         subsys,
                         name);
            g_free (key);
            return FALSE;
        }
    }
    /* Virtual ports... */
    else if (g_str_equal (subsys, "virtual")) {
        port = MM_PORT (mm_port_serial_at_new (name, MM_PORT_SUBSYS_UNIX));

        /* Set common response parser */
        mm_port_serial_at_set_response_parser (MM_PORT_SERIAL_AT (port),
                                               mm_serial_parser_v1_parse,
                                               mm_serial_parser_v1_new (),
                                               mm_serial_parser_v1_destroy);
        /* Store flags already */
        mm_port_serial_at_set_flags (MM_PORT_SERIAL_AT (port), at_pflags);
    }
    else
        /* We already filter out before all non-tty, non-net, non-cdc-wdm ports */
        g_assert_not_reached ();

    mm_dbg ("(%s) type '%s' claimed by %s",
            name,
            mm_port_type_get_string (ptype),
            mm_base_modem_get_device (self));

    /* Add it to the tracking HT.
     * Note: 'key' and 'port' now owned by the HT. */
    g_hash_table_insert (self->priv->ports, key, port);

    /* Store kernel device */
    g_object_set (port,
                  MM_PORT_KERNEL_DEVICE, kernel_device,
                  NULL);

    return TRUE;
}

gboolean
mm_base_modem_disable_finish (MMBaseModem *self,
                              GAsyncResult *res,
                              GError **error)
{
    return MM_BASE_MODEM_GET_CLASS (self)->disable_finish (self, res, error);
}

void
mm_base_modem_disable (MMBaseModem *self,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->disable != NULL);
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->disable_finish != NULL);

    MM_BASE_MODEM_GET_CLASS (self)->disable (
        self,
        self->priv->cancellable,
        callback,
        user_data);
}

gboolean
mm_base_modem_enable_finish (MMBaseModem *self,
                             GAsyncResult *res,
                             GError **error)
{
    return MM_BASE_MODEM_GET_CLASS (self)->enable_finish (self, res, error);
}

void
mm_base_modem_enable (MMBaseModem *self,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->enable != NULL);
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->enable_finish != NULL);

    MM_BASE_MODEM_GET_CLASS (self)->enable (
        self,
        self->priv->cancellable,
        callback,
        user_data);
}

gboolean
mm_base_modem_initialize_finish (MMBaseModem *self,
                                 GAsyncResult *res,
                                 GError **error)
{
    return MM_BASE_MODEM_GET_CLASS (self)->initialize_finish (self, res, error);
}

void
mm_base_modem_initialize (MMBaseModem *self,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->initialize != NULL);
    g_assert (MM_BASE_MODEM_GET_CLASS (self)->initialize_finish != NULL);

    MM_BASE_MODEM_GET_CLASS (self)->initialize (
        self,
        self->priv->cancellable,
        callback,
        user_data);
}

void
mm_base_modem_set_hotplugged (MMBaseModem *self,
                              gboolean hotplugged)
{
    g_return_if_fail (MM_IS_BASE_MODEM (self));

    self->priv->hotplugged = hotplugged;
}

gboolean
mm_base_modem_get_hotplugged (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), FALSE);

    return self->priv->hotplugged;
}

void
mm_base_modem_set_valid (MMBaseModem *self,
                         gboolean new_valid)
{
    g_return_if_fail (MM_IS_BASE_MODEM (self));

    /* If validity changed OR if both old and new were invalid, notify. This
     * last case is to cover failures during initialization. */
    if (self->priv->valid != new_valid ||
        !new_valid) {
        self->priv->valid = new_valid;
        g_object_notify_by_pspec (G_OBJECT (self), properties[PROP_VALID]);
    }
}

void
mm_base_modem_set_reprobe (MMBaseModem *self,
                           gboolean reprobe)
{
    g_return_if_fail (MM_IS_BASE_MODEM (self));

    self->priv->reprobe = reprobe;
}

gboolean
mm_base_modem_get_reprobe (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), FALSE);

    return self->priv->reprobe;
}

gboolean
mm_base_modem_get_valid (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), FALSE);

    return self->priv->valid;
}

GCancellable *
mm_base_modem_peek_cancellable (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->cancellable;
}

GCancellable *
mm_base_modem_get_cancellable  (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return g_object_ref (self->priv->cancellable);
}

MMPortSerialAt *
mm_base_modem_get_port_primary (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (self->priv->primary ? g_object_ref (self->priv->primary) : NULL);
}

MMPortSerialAt *
mm_base_modem_peek_port_primary (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->primary;
}

MMPortSerialAt *
mm_base_modem_get_port_secondary (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (self->priv->secondary ? g_object_ref (self->priv->secondary) : NULL);
}

MMPortSerialAt *
mm_base_modem_peek_port_secondary (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->secondary;
}

MMPortSerialQcdm *
mm_base_modem_get_port_qcdm (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (self->priv->qcdm ? g_object_ref (self->priv->qcdm) : NULL);
}

MMPortSerialQcdm *
mm_base_modem_peek_port_qcdm (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->qcdm;
}

MMPortSerialAt *
mm_base_modem_get_port_gps_control (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (self->priv->gps_control ? g_object_ref (self->priv->gps_control) : NULL);
}

MMPortSerialAt *
mm_base_modem_peek_port_gps_control (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->gps_control;
}

MMPortSerialGps *
mm_base_modem_get_port_gps (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (self->priv->gps ? g_object_ref (self->priv->gps) : NULL);
}

MMPortSerialGps *
mm_base_modem_peek_port_gps (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->gps;
}

#if defined WITH_QMI

MMPortQmi *
mm_base_modem_get_port_qmi (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    /* First QMI port in the list is the primary one always */
    return (self->priv->qmi ? ((MMPortQmi *)g_object_ref (self->priv->qmi->data)) : NULL);
}

MMPortQmi *
mm_base_modem_peek_port_qmi (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    /* First QMI port in the list is the primary one always */
    return (self->priv->qmi ? (MMPortQmi *)self->priv->qmi->data : NULL);
}

MMPortQmi *
mm_base_modem_get_port_qmi_for_data (MMBaseModem *self,
                                     MMPort *data,
                                     GError **error)
{
    MMPortQmi *qmi;

    qmi = mm_base_modem_peek_port_qmi_for_data (self, data, error);
    return (qmi ? (MMPortQmi *)g_object_ref (qmi) : NULL);
}

MMPortQmi *
mm_base_modem_peek_port_qmi_for_data (MMBaseModem *self,
                                      MMPort *data,
                                      GError **error)
{
    GList *cdc_wdm_qmi_ports, *l;
    const gchar *net_port_parent_path;
    MMPortQmi *found = NULL;

    g_warn_if_fail (mm_port_get_subsys (data) == MM_PORT_SUBSYS_NET);
    net_port_parent_path = mm_kernel_device_get_interface_sysfs_path (mm_port_peek_kernel_device (data));
    if (!net_port_parent_path) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "No parent path for 'net/%s'",
                     mm_port_get_device (data));
        return NULL;
    }

    /* Find the CDC-WDM port on the same USB interface as the given net port */
    cdc_wdm_qmi_ports = mm_base_modem_find_ports (MM_BASE_MODEM (self),
                                                  MM_PORT_SUBSYS_USB,
                                                  MM_PORT_TYPE_QMI,
                                                  NULL);
    for (l = cdc_wdm_qmi_ports; l && !found; l = g_list_next (l)) {
        const gchar *wdm_port_parent_path;

        g_assert (MM_IS_PORT_QMI (l->data));
        wdm_port_parent_path = mm_kernel_device_get_interface_sysfs_path (mm_port_peek_kernel_device (MM_PORT (l->data)));
        if (wdm_port_parent_path && g_str_equal (wdm_port_parent_path, net_port_parent_path))
            found = MM_PORT_QMI (l->data);
    }

    g_list_free_full (cdc_wdm_qmi_ports, g_object_unref);

    if (!found)
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_NOT_FOUND,
                     "Couldn't find associated QMI port for 'net/%s'",
                     mm_port_get_device (data));

    return found;
}

#endif /* WITH_QMI */

#if defined WITH_MBIM

MMPortMbim *
mm_base_modem_get_port_mbim (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    /* First MBIM port in the list is the primary one always */
    return (self->priv->mbim ? ((MMPortMbim *)g_object_ref (self->priv->mbim->data)) : NULL);
}

MMPortMbim *
mm_base_modem_peek_port_mbim (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    /* First MBIM port in the list is the primary one always */
    return (self->priv->mbim ? (MMPortMbim *)self->priv->mbim->data : NULL);
}

MMPortMbim *
mm_base_modem_get_port_mbim_for_data (MMBaseModem *self,
                                      MMPort *data,
                                      GError **error)
{
    MMPortMbim *mbim;

    mbim = mm_base_modem_peek_port_mbim_for_data (self, data, error);
    return (mbim ? (MMPortMbim *)g_object_ref (mbim) : NULL);
}

MMPortMbim *
mm_base_modem_peek_port_mbim_for_data (MMBaseModem *self,
                                       MMPort *data,
                                       GError **error)
{
    GList *cdc_wdm_mbim_ports, *l;
    const gchar *net_port_parent_path;
    MMPortMbim *found = NULL;

    g_warn_if_fail (mm_port_get_subsys (data) == MM_PORT_SUBSYS_NET);
    net_port_parent_path = mm_kernel_device_get_interface_sysfs_path (mm_port_peek_kernel_device (data));
    if (!net_port_parent_path) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_FAILED,
                     "No parent path for 'net/%s'",
                     mm_port_get_device (data));
        return NULL;
    }

    /* Find the CDC-WDM port on the same USB interface as the given net port */
    cdc_wdm_mbim_ports = mm_base_modem_find_ports (MM_BASE_MODEM (self),
                                                  MM_PORT_SUBSYS_USB,
                                                  MM_PORT_TYPE_MBIM,
                                                  NULL);

    for (l = cdc_wdm_mbim_ports; l && !found; l = g_list_next (l)) {
        const gchar *wdm_port_parent_path;

        g_assert (MM_IS_PORT_MBIM (l->data));
        wdm_port_parent_path = mm_kernel_device_get_interface_sysfs_path (mm_port_peek_kernel_device (MM_PORT (l->data)));
        if (wdm_port_parent_path && g_str_equal (wdm_port_parent_path, net_port_parent_path))
            found = MM_PORT_MBIM (l->data);
    }

    g_list_free_full (cdc_wdm_mbim_ports, g_object_unref);

    if (!found)
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_NOT_FOUND,
                     "Couldn't find associated MBIM port for 'net/%s'",
                     mm_port_get_device (data));

    return found;
}

#endif /* WITH_MBIM */

MMPort *
mm_base_modem_get_best_data_port (MMBaseModem *self,
                                  MMPortType type)
{
    MMPort *port;

    port = mm_base_modem_peek_best_data_port (self, type);
    return (port ? g_object_ref (port) : NULL);
}

MMPort *
mm_base_modem_peek_best_data_port (MMBaseModem *self,
                                   MMPortType type)
{
    GList *l;

    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    /* Return first not-connected data port */
    for (l = self->priv->data; l; l = g_list_next (l)) {
        if (!mm_port_get_connected ((MMPort *)l->data) &&
            (mm_port_get_port_type ((MMPort *)l->data) == type ||
             type == MM_PORT_TYPE_UNKNOWN)) {
            return (MMPort *)l->data;
        }
    }

    return NULL;
}

GList *
mm_base_modem_get_data_ports (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return g_list_copy_deep (self->priv->data, (GCopyFunc)g_object_ref, NULL);
}

GList *
mm_base_modem_peek_data_ports (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->data;
}

MMPortSerialAt *
mm_base_modem_get_best_at_port (MMBaseModem *self,
                                GError **error)
{
    MMPortSerialAt *best;

    best = mm_base_modem_peek_best_at_port (self, error);
    return (best ? g_object_ref (best) : NULL);
}

MMPortSerialAt *
mm_base_modem_peek_best_at_port (MMBaseModem *self,
                                 GError **error)
{
    /* Decide which port to use */
    if (self->priv->primary &&
        !mm_port_get_connected (MM_PORT (self->priv->primary)))
        return self->priv->primary;

    /* If primary port is connected, check if we can get the secondary
     * port */
    if (self->priv->secondary &&
        !mm_port_get_connected (MM_PORT (self->priv->secondary)))
        return self->priv->secondary;

    /* Otherwise, we cannot get any port */
    g_set_error (error,
                 MM_CORE_ERROR,
                 MM_CORE_ERROR_CONNECTED,
                 "No AT port available to run command");
    return NULL;
}

gboolean
mm_base_modem_has_at_port (MMBaseModem *self)
{
    GHashTableIter iter;
    gpointer value;
    gpointer key;

    /* We'll iterate the ht of ports, looking for any port which is AT */
    g_hash_table_iter_init (&iter, self->priv->ports);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (MM_IS_PORT_SERIAL_AT (value))
            return TRUE;
    }

    return FALSE;
}

MMModemPortInfo *
mm_base_modem_get_port_infos (MMBaseModem *self,
                              guint *n_port_infos)
{
    GHashTableIter iter;
    MMModemPortInfo *port_infos;
    MMPort *port;
    guint i;

    *n_port_infos = g_hash_table_size (self->priv->ports);
    port_infos = g_new (MMModemPortInfo, *n_port_infos);
    g_hash_table_iter_init (&iter, self->priv->ports);
    i = 0;
    while (g_hash_table_iter_next (&iter, NULL, (gpointer)&port)) {
        port_infos[i].name = g_strdup (mm_port_get_device (port));
        switch (mm_port_get_port_type (port)) {
        case MM_PORT_TYPE_NET:
            port_infos[i].type = MM_MODEM_PORT_TYPE_NET;
            break;
        case MM_PORT_TYPE_AT:
            port_infos[i].type = MM_MODEM_PORT_TYPE_AT;
            break;
        case MM_PORT_TYPE_QCDM:
            port_infos[i].type = MM_MODEM_PORT_TYPE_QCDM;
            break;
        case MM_PORT_TYPE_GPS:
            port_infos[i].type = MM_MODEM_PORT_TYPE_GPS;
            break;
        case MM_PORT_TYPE_QMI:
            port_infos[i].type = MM_MODEM_PORT_TYPE_QMI;
            break;
        case MM_PORT_TYPE_MBIM:
            port_infos[i].type = MM_MODEM_PORT_TYPE_MBIM;
            break;
        case MM_PORT_TYPE_UNKNOWN:
        case MM_PORT_TYPE_IGNORED:
        default:
            port_infos[i].type = MM_MODEM_PORT_TYPE_UNKNOWN;
            break;
        }

        i++;
    }

    return port_infos;
}

GList *
mm_base_modem_find_ports (MMBaseModem *self,
                          MMPortSubsys subsys,
                          MMPortType type,
                          const gchar *name)
{
    GList *out = NULL;
    GHashTableIter iter;
    gpointer value;
    gpointer key;

    /* We'll iterate the ht of ports, looking for any port which is matches
     * the compare function */
    g_hash_table_iter_init (&iter, self->priv->ports);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        MMPort *port = MM_PORT (value);

        if (subsys != MM_PORT_SUBSYS_UNKNOWN && mm_port_get_subsys (port) != subsys)
            continue;

        if (type != MM_PORT_TYPE_UNKNOWN && mm_port_get_port_type (port) != type)
            continue;

        if (name != NULL && !g_str_equal (mm_port_get_device (port), name))
            continue;

        out = g_list_append (out, g_object_ref (port));
    }

    return out;
}

static void
initialize_ready (MMBaseModem *self,
                  GAsyncResult *res)
{
    GError *error = NULL;

    if (mm_base_modem_initialize_finish (self, res, &error)) {
        mm_dbg ("modem properly initialized");
        mm_base_modem_set_valid (self, TRUE);
        return;
    }

    /* Wrong state is returned when modem is found locked */
    if (g_error_matches (error, MM_CORE_ERROR, MM_CORE_ERROR_WRONG_STATE)) {
        /* Even with initialization errors, we do set the state to valid, so
         * that the modem gets exported and the failure notified to the user.
         */
        mm_dbg ("Couldn't finish initialization in the current state: '%s'",
                error->message);
        g_error_free (error);
        mm_base_modem_set_valid (self, TRUE);
        return;
    }

    /* Really fatal, we cannot even export the failed modem (e.g. error before
     * even trying to enable the Modem interface */
    mm_warn ("couldn't initialize the modem: '%s'", error->message);
    g_error_free (error);
}

static inline void
log_port (MMBaseModem *self, MMPort *port, const char *desc)
{
    if (port) {
        mm_dbg ("(%s) %s/%s %s",
                self->priv->device,
                mm_port_subsys_get_string (mm_port_get_subsys (port)),
                mm_port_get_device (port),
                desc);
    }
}

gboolean
mm_base_modem_organize_ports (MMBaseModem *self,
                              GError **error)
{
    GHashTableIter iter;
    MMPort *candidate;
    MMPortSerialAtFlag flags;
    MMPortSerialAt *backup_primary = NULL;
    MMPortSerialAt *primary = NULL;
    MMPortSerialAt *secondary = NULL;
    MMPortSerialAt *backup_secondary = NULL;
    MMPortSerialQcdm *qcdm = NULL;
    MMPortSerialAt *gps_control = NULL;
    MMPortSerialGps *gps = NULL;
    MMPort *data_primary = NULL;
    GList *data = NULL;
#if defined WITH_QMI
    MMPort *qmi_primary = NULL;
    GList *qmi = NULL;
#endif
#if defined WITH_MBIM
    MMPort *mbim_primary = NULL;
    GList *mbim = NULL;
#endif
    GList *l;

    g_return_val_if_fail (MM_IS_BASE_MODEM (self), FALSE);

    /* If ports have already been organized, just return success */
    if (self->priv->primary)
        return TRUE;

    g_hash_table_iter_init (&iter, self->priv->ports);
    while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &candidate)) {
        switch (mm_port_get_port_type (candidate)) {

        case MM_PORT_TYPE_AT:
            g_assert (MM_IS_PORT_SERIAL_AT (candidate));
            flags = mm_port_serial_at_get_flags (MM_PORT_SERIAL_AT (candidate));

            if (flags & MM_PORT_SERIAL_AT_FLAG_PRIMARY) {
                if (!primary)
                    primary = MM_PORT_SERIAL_AT (candidate);
                else if (!backup_primary) {
                    /* Just in case the plugin gave us more than one primary
                     * and no secondaries, treat additional primary ports as
                     * secondary.
                     */
                    backup_primary = MM_PORT_SERIAL_AT (candidate);
                }
            }

            if (flags & MM_PORT_SERIAL_AT_FLAG_PPP) {
                if (!data_primary)
                    data_primary = candidate;
                else
                    data = g_list_append (data, candidate);
            }

            /* Explicitly flagged secondary ports trump NONE ports for secondary */
            if (flags & MM_PORT_SERIAL_AT_FLAG_SECONDARY) {
                if (!secondary || !(mm_port_serial_at_get_flags (secondary) & MM_PORT_SERIAL_AT_FLAG_SECONDARY))
                    secondary = MM_PORT_SERIAL_AT (candidate);
            }

            if (flags & MM_PORT_SERIAL_AT_FLAG_GPS_CONTROL) {
                if (!gps_control)
                    gps_control = MM_PORT_SERIAL_AT (candidate);
            }

            /* Fallback secondary */
            if (flags == MM_PORT_SERIAL_AT_FLAG_NONE) {
                if (!secondary)
                    secondary = MM_PORT_SERIAL_AT (candidate);
                else if (!backup_secondary)
                    backup_secondary = MM_PORT_SERIAL_AT (candidate);
            }
            break;

        case MM_PORT_TYPE_QCDM:
            g_assert (MM_IS_PORT_SERIAL_QCDM (candidate));
            if (!qcdm)
                qcdm = MM_PORT_SERIAL_QCDM (candidate);
            break;

        case MM_PORT_TYPE_NET:
            if (!data_primary)
                data_primary = candidate;
            else if (MM_IS_PORT_SERIAL_AT (data_primary)) {
                /* Net device (if any) is the preferred data port */
                data = g_list_append (data, data_primary);
                data_primary = candidate;
            }
            else
                /* All non-primary net ports get added to the list of data ports */
                data = g_list_append (data, candidate);
            break;

        case MM_PORT_TYPE_GPS:
            g_assert (MM_IS_PORT_SERIAL_GPS (candidate));
            if (!gps)
                gps = MM_PORT_SERIAL_GPS (candidate);
            break;

#if defined WITH_QMI
        case MM_PORT_TYPE_QMI:
            if (!qmi_primary)
                qmi_primary = candidate;
            else
                /* All non-primary QMI ports get added to the list of QMI ports */
                qmi = g_list_append (qmi, candidate);
            break;
#endif

#if defined WITH_MBIM
        case MM_PORT_TYPE_MBIM:
            if (!mbim_primary)
                mbim_primary = candidate;
            else
                /* All non-primary MBIM ports get added to the list of MBIM ports */
                mbim = g_list_append (mbim, candidate);
            break;
#endif

        default:
            /* Ignore port */
            break;
        }
    }

    if (!primary) {
        /* Fall back to a secondary port if we didn't find a primary port */
        if (secondary) {
            primary = secondary;
            secondary = NULL;
        }
        /* Fallback to a data port if no primary or secondary */
        else if (data_primary && MM_IS_PORT_SERIAL_AT (data_primary)) {
            primary = MM_PORT_SERIAL_AT (data_primary);
            data_primary = NULL;
        }
        else {
            gboolean allow_modem_without_at_port = FALSE;

#if defined WITH_QMI
            if (qmi_primary)
                allow_modem_without_at_port = TRUE;
#endif

#if defined WITH_MBIM
            if (mbim_primary)
                allow_modem_without_at_port = TRUE;
#endif

            if (!allow_modem_without_at_port) {
                g_set_error_literal (error,
                                     MM_CORE_ERROR,
                                     MM_CORE_ERROR_FAILED,
                                     "Failed to find primary AT port");
                return FALSE;
            }
        }
    }

    /* If the plugin didn't give us any secondary ports, use any additional
     * primary ports or backup secondary ports as secondary.
     */
    if (!secondary)
        secondary = backup_primary ? backup_primary : backup_secondary;

#if defined WITH_QMI
    /* On QMI-based modems, we need to have at least a net port */
    if (qmi_primary && !data_primary) {
        g_set_error_literal (error,
                             MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Failed to find a net port in the QMI modem");
        return FALSE;
    }
#endif

#if defined WITH_MBIM
    /* On MBIM-based modems, we need to have at least a net port */
    if (mbim_primary && !data_primary) {
        g_set_error_literal (error,
                             MM_CORE_ERROR,
                             MM_CORE_ERROR_FAILED,
                             "Failed to find a net port in the MBIM modem");
        return FALSE;
    }
#endif

    /* Data port defaults to primary AT port */
    if (!data_primary)
        data_primary = MM_PORT (primary);
    g_assert (data_primary);

    /* Reset flags on all ports; clear data port first since it might also
     * be the primary or secondary port.
     */
    if (MM_IS_PORT_SERIAL_AT (data_primary))
        mm_port_serial_at_set_flags (MM_PORT_SERIAL_AT (data_primary), MM_PORT_SERIAL_AT_FLAG_NONE);

    if (primary)
        mm_port_serial_at_set_flags (primary, MM_PORT_SERIAL_AT_FLAG_PRIMARY);
    if (secondary)
        mm_port_serial_at_set_flags (secondary, MM_PORT_SERIAL_AT_FLAG_SECONDARY);

    if (MM_IS_PORT_SERIAL_AT (data_primary)) {
        flags = mm_port_serial_at_get_flags (MM_PORT_SERIAL_AT (data_primary));
        mm_port_serial_at_set_flags (MM_PORT_SERIAL_AT (data_primary), flags | MM_PORT_SERIAL_AT_FLAG_PPP);
    }

    log_port (self, MM_PORT (primary),      "at (primary)");
    log_port (self, MM_PORT (secondary),    "at (secondary)");
    log_port (self, MM_PORT (data_primary), "data (primary)");
    for (l = data; l; l = g_list_next (l))
        log_port (self, MM_PORT (l->data),  "data (secondary)");
    log_port (self, MM_PORT (qcdm),         "qcdm");
    log_port (self, MM_PORT (gps_control),  "gps (control)");
    log_port (self, MM_PORT (gps),          "gps (nmea)");
#if defined WITH_QMI
    log_port (self, MM_PORT (qmi_primary),  "qmi (primary)");
    for (l = qmi; l; l = g_list_next (l))
        log_port (self, MM_PORT (l->data),  "qmi (secondary)");
#endif
#if defined WITH_MBIM
    log_port (self, MM_PORT (mbim_primary),  "mbim (primary)");
    for (l = mbim; l; l = g_list_next (l))
        log_port (self, MM_PORT (l->data),   "mbim (secondary)");
#endif

    /* We keep new refs to the objects here */
    self->priv->primary = (primary ? g_object_ref (primary) : NULL);
    self->priv->secondary = (secondary ? g_object_ref (secondary) : NULL);
    self->priv->qcdm = (qcdm ? g_object_ref (qcdm) : NULL);
    self->priv->gps_control = (gps_control ? g_object_ref (gps_control) : NULL);
    self->priv->gps = (gps ? g_object_ref (gps) : NULL);

    /* Build the final list of data ports, primary port first */
    self->priv->data = g_list_append (self->priv->data, g_object_ref (data_primary));
    g_list_foreach (data, (GFunc)g_object_ref, NULL);
    self->priv->data = g_list_concat (self->priv->data, data);

#if defined WITH_QMI
    /* Build the final list of QMI ports, primary port first */
    if (qmi_primary) {
        self->priv->qmi = g_list_append (self->priv->qmi, g_object_ref (qmi_primary));
        g_list_foreach (qmi, (GFunc)g_object_ref, NULL);
        self->priv->qmi = g_list_concat (self->priv->qmi, qmi);
    }
#endif

#if defined WITH_MBIM
    /* Build the final list of MBIM ports, primary port first */
    if (mbim_primary) {
        self->priv->mbim = g_list_append (self->priv->mbim, g_object_ref (mbim_primary));
        g_list_foreach (mbim, (GFunc)g_object_ref, NULL);
        self->priv->mbim = g_list_concat (self->priv->mbim, mbim);
    }
#endif

    /* As soon as we get the ports organized, we initialize the modem */
    mm_base_modem_initialize (self,
                              (GAsyncReadyCallback)initialize_ready,
                              NULL);

    return TRUE;
}

/*****************************************************************************/
/* Authorization */

gboolean
mm_base_modem_authorize_finish (MMBaseModem *self,
                                GAsyncResult *res,
                                GError **error)
{
    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
authorize_ready (MMAuthProvider *authp,
                 GAsyncResult *res,
                 GTask *task)
{
    GError *error = NULL;

    if (!mm_auth_provider_authorize_finish (authp, res, &error))
        g_task_return_error (task, error);
    else
        g_task_return_boolean (task, TRUE);

    g_object_unref (task);
}

void
mm_base_modem_authorize (MMBaseModem *self,
                         GDBusMethodInvocation *invocation,
                         const gchar *authorization,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
    GTask *task;

    task = g_task_new (self, self->priv->authp_cancellable, callback, user_data);

    /* When running in the session bus for tests, default to always allow */
    if (mm_context_get_test_session ()) {
        g_task_return_boolean (task, TRUE);
        g_object_unref (task);
        return;
    }

    mm_auth_provider_authorize (self->priv->authp,
                                invocation,
                                authorization,
                                self->priv->authp_cancellable,
                                (GAsyncReadyCallback)authorize_ready,
                                task);
}

/*****************************************************************************/

const gchar *
mm_base_modem_get_device (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->device;
}

const gchar **
mm_base_modem_get_drivers (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return (const gchar **)self->priv->drivers;
}

const gchar *
mm_base_modem_get_plugin (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), NULL);

    return self->priv->plugin;
}

guint
mm_base_modem_get_vendor_id  (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), 0);

    return self->priv->vendor_id;
}

guint
mm_base_modem_get_product_id (MMBaseModem *self)
{
    g_return_val_if_fail (MM_IS_BASE_MODEM (self), 0);

    return self->priv->product_id;
}

/*****************************************************************************/

static gboolean
base_modem_invalid_idle (MMBaseModem *self)
{
    /* Ensure the modem is set invalid if we get the modem-wide cancellable
     * cancelled */
    mm_base_modem_set_valid (self, FALSE);
    g_object_unref (self);
    return G_SOURCE_REMOVE;
}

static void
base_modem_cancelled (GCancellable *cancellable,
                      MMBaseModem *self)
{
    /* NOTE: Don't call set_valid() directly here, do it in an idle, and ensure
     * that we pass a valid reference of the modem object as context. */
    g_idle_add ((GSourceFunc)base_modem_invalid_idle, g_object_ref (self));
}

/*****************************************************************************/

static void
mm_base_modem_init (MMBaseModem *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_BASE_MODEM,
                                              MMBaseModemPrivate);

    /* Setup authorization provider */
    self->priv->authp = mm_auth_get_provider ();
    self->priv->authp_cancellable = g_cancellable_new ();

    /* Setup modem-wide cancellable */
    self->priv->cancellable = g_cancellable_new ();
    self->priv->invalid_if_cancelled =
        g_cancellable_connect (self->priv->cancellable,
                               G_CALLBACK (base_modem_cancelled),
                               self,
                               NULL);

    self->priv->ports = g_hash_table_new_full (g_str_hash,
                                               g_str_equal,
                                               g_free,
                                               g_object_unref);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
    MMBaseModem *self = MM_BASE_MODEM (object);

    switch (prop_id) {
    case PROP_VALID:
        mm_base_modem_set_valid (self, g_value_get_boolean (value));
        break;
    case PROP_REPROBE:
        mm_base_modem_set_reprobe (self, g_value_get_boolean (value));
        break;
    case PROP_MAX_TIMEOUTS:
        self->priv->max_timeouts = g_value_get_uint (value);
        break;
    case PROP_DEVICE:
        g_free (self->priv->device);
        self->priv->device = g_value_dup_string (value);
        break;
    case PROP_DRIVERS:
        g_strfreev (self->priv->drivers);
        self->priv->drivers = g_value_dup_boxed (value);
        break;
    case PROP_PLUGIN:
        g_free (self->priv->plugin);
        self->priv->plugin = g_value_dup_string (value);
        break;
    case PROP_VENDOR_ID:
        self->priv->vendor_id = g_value_get_uint (value);
        break;
    case PROP_PRODUCT_ID:
        self->priv->product_id = g_value_get_uint (value);
        break;
    case PROP_CONNECTION:
        g_clear_object (&self->priv->connection);
        self->priv->connection = g_value_dup_object (value);
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
    MMBaseModem *self = MM_BASE_MODEM (object);

    switch (prop_id) {
    case PROP_VALID:
        g_value_set_boolean (value, self->priv->valid);
        break;
    case PROP_REPROBE:
        g_value_set_boolean (value, self->priv->reprobe);
        break;
    case PROP_MAX_TIMEOUTS:
        g_value_set_uint (value, self->priv->max_timeouts);
        break;
    case PROP_DEVICE:
        g_value_set_string (value, self->priv->device);
        break;
    case PROP_DRIVERS:
        g_value_set_boxed (value, self->priv->drivers);
        break;
    case PROP_PLUGIN:
        g_value_set_string (value, self->priv->plugin);
        break;
    case PROP_VENDOR_ID:
        g_value_set_uint (value, self->priv->vendor_id);
        break;
    case PROP_PRODUCT_ID:
        g_value_set_uint (value, self->priv->product_id);
        break;
    case PROP_CONNECTION:
        g_value_set_object (value, self->priv->connection);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
finalize (GObject *object)
{
    MMBaseModem *self = MM_BASE_MODEM (object);

    /* TODO
     * mm_auth_provider_cancel_for_owner (self->priv->authp, object);
    */

    mm_dbg ("Modem (%s) '%s' completely disposed",
            self->priv->plugin,
            self->priv->device);

    g_free (self->priv->device);
    g_strfreev (self->priv->drivers);
    g_free (self->priv->plugin);

    G_OBJECT_CLASS (mm_base_modem_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
    MMBaseModem *self = MM_BASE_MODEM (object);

    /* Cancel all ongoing auth requests */
    g_cancellable_cancel (self->priv->authp_cancellable);
    g_clear_object (&self->priv->authp_cancellable);
    g_clear_object (&self->priv->authp);

    /* Ensure we cancel any ongoing operation, but before
     * disconnect our own signal handler, or we'll end up with
     * another reference of the modem object around. */
    g_cancellable_disconnect (self->priv->cancellable,
                              self->priv->invalid_if_cancelled);
    g_cancellable_cancel (self->priv->cancellable);
    g_clear_object (&self->priv->cancellable);

    g_clear_object (&self->priv->primary);
    g_clear_object (&self->priv->secondary);
    g_list_free_full (self->priv->data, g_object_unref);
    self->priv->data = NULL;
    g_clear_object (&self->priv->qcdm);
    g_clear_object (&self->priv->gps_control);
    g_clear_object (&self->priv->gps);
#if defined WITH_QMI
    /* We need to close the QMI port cleanly when disposing the modem object,
     * otherwise the allocated CIDs will be kept allocated, and if we end up
     * allocating too many newer allocations will fail with client-ids-exhausted
     * errors. */
    g_list_foreach (self->priv->qmi, (GFunc)mm_port_qmi_close, NULL);
    g_list_free_full (self->priv->qmi, g_object_unref);
    self->priv->qmi = NULL;
#endif
#if defined WITH_MBIM
    /* We need to close the MBIM port cleanly when disposing the modem object */
    g_list_foreach (self->priv->mbim, (GFunc)mm_port_mbim_close, NULL);
    g_list_free_full (self->priv->mbim, g_object_unref);
    self->priv->mbim = NULL;
#endif

    if (self->priv->ports) {
        g_hash_table_destroy (self->priv->ports);
        self->priv->ports = NULL;
    }

    g_clear_object (&self->priv->connection);

    G_OBJECT_CLASS (mm_base_modem_parent_class)->dispose (object);
}

static void
mm_base_modem_class_init (MMBaseModemClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMBaseModemPrivate));

    /* Virtual methods */
    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize = finalize;
    object_class->dispose = dispose;

    properties[PROP_MAX_TIMEOUTS] =
        g_param_spec_uint (MM_BASE_MODEM_MAX_TIMEOUTS,
                           "Max timeouts",
                           "Maximum number of consecutive timed out commands sent to "
                           "the modem before disabling it. If 0, this feature is disabled.",
                           0, G_MAXUINT, 0,
                           G_PARAM_READWRITE);
    g_object_class_install_property (object_class, PROP_MAX_TIMEOUTS, properties[PROP_MAX_TIMEOUTS]);

    properties[PROP_VALID] =
        g_param_spec_boolean (MM_BASE_MODEM_VALID,
                              "Valid",
                              "Whether the modem is to be considered valid or not.",
                              FALSE,
                              G_PARAM_READWRITE);
    g_object_class_install_property (object_class, PROP_VALID, properties[PROP_VALID]);

    properties[PROP_DEVICE] =
        g_param_spec_string (MM_BASE_MODEM_DEVICE,
                             "Device",
                             "Master modem parent device of all the modem's ports",
                             NULL,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_DEVICE, properties[PROP_DEVICE]);

    properties[PROP_DRIVERS] =
        g_param_spec_boxed (MM_BASE_MODEM_DRIVERS,
                            "Drivers",
                            "Kernel drivers",
                            G_TYPE_STRV,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_DRIVERS, properties[PROP_DRIVERS]);

    properties[PROP_PLUGIN] =
        g_param_spec_string (MM_BASE_MODEM_PLUGIN,
                             "Plugin",
                             "Name of the plugin managing this modem",
                             NULL,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_PLUGIN, properties[PROP_PLUGIN]);

    properties[PROP_VENDOR_ID] =
        g_param_spec_uint (MM_BASE_MODEM_VENDOR_ID,
                           "Hardware vendor ID",
                           "Hardware vendor ID. May be unknown for serial devices.",
                           0, G_MAXUINT, 0,
                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_VENDOR_ID, properties[PROP_VENDOR_ID]);

    properties[PROP_PRODUCT_ID] =
        g_param_spec_uint (MM_BASE_MODEM_PRODUCT_ID,
                           "Hardware product ID",
                           "Hardware product ID. May be unknown for serial devices.",
                           0, G_MAXUINT, 0,
                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_PRODUCT_ID, properties[PROP_PRODUCT_ID]);

    properties[PROP_CONNECTION] =
        g_param_spec_object (MM_BASE_MODEM_CONNECTION,
                             "Connection",
                             "GDBus connection to the system bus.",
                             G_TYPE_DBUS_CONNECTION,
                             G_PARAM_READWRITE);
    g_object_class_install_property (object_class, PROP_CONNECTION, properties[PROP_CONNECTION]);

    properties[PROP_REPROBE] =
        g_param_spec_boolean (MM_BASE_MODEM_REPROBE,
                              "Reprobe",
                              "Whether the modem needs to be reprobed or not.",
                              FALSE,
                              G_PARAM_READWRITE);
    g_object_class_install_property (object_class, PROP_REPROBE, properties[PROP_REPROBE]);
}
