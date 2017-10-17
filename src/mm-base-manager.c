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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 * Copyright (C) 2011 - 2012 Google, Inc
 * Copyright (C) 2016 Velocloud, Inc.
 * Copyright (C) 2011 - 2016 Aleksander Morgado <aleksander@aleksander.es>
 */

#include <config.h>

#include <string.h>
#include <ctype.h>

#include <gmodule.h>

#if defined WITH_UDEV
# include "mm-kernel-device-udev.h"
#endif
#include "mm-kernel-device-generic.h"

#include <ModemManager.h>
#include <mm-errors-types.h>
#include <mm-gdbus-manager.h>
#include <mm-gdbus-test.h>

#include "mm-base-manager.h"
#include "mm-daemon-enums-types.h"
#include "mm-device.h"
#include "mm-plugin-manager.h"
#include "mm-auth.h"
#include "mm-plugin.h"
#include "mm-filter.h"
#include "mm-log.h"

static void initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_EXTENDED (MMBaseManager, mm_base_manager, MM_GDBUS_TYPE_ORG_FREEDESKTOP_MODEM_MANAGER1_SKELETON, 0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                               initable_iface_init));

enum {
    PROP_0,
    PROP_CONNECTION,
    PROP_AUTO_SCAN,
    PROP_FILTER_POLICY,
    PROP_ENABLE_TEST,
    PROP_PLUGIN_DIR,
    PROP_INITIAL_KERNEL_EVENTS,
    LAST_PROP
};

struct _MMBaseManagerPrivate {
    /* The connection to the system bus */
    GDBusConnection *connection;
    /* Whether auto-scanning is enabled */
    gboolean auto_scan;
    /* Filter policy (mask of enabled rules) */
    MMFilterRule filter_policy;
    /* Whether the test interface is enabled */
    gboolean enable_test;
    /* Path to look for plugins */
    gchar *plugin_dir;
    /* Path to the list of initial kernel events */
    gchar *initial_kernel_events;
    /* The authorization provider */
    MMAuthProvider *authp;
    GCancellable *authp_cancellable;
    /* The Plugin Manager object */
    MMPluginManager *plugin_manager;
    /* The port/device filter */
    MMFilter *filter;
    /* The container of devices being prepared */
    GHashTable *devices;
    /* The Object Manager server */
    GDBusObjectManagerServer *object_manager;

    /* The Test interface support */
    MmGdbusTest *test_skeleton;

#if defined WITH_UDEV
    /* The UDev client */
    GUdevClient *udev;
#endif
};

/*****************************************************************************/

static MMDevice *
find_device_by_modem (MMBaseManager *manager,
                      MMBaseModem *modem)
{
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, manager->priv->devices);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        MMDevice *candidate = MM_DEVICE (value);

        if (modem == mm_device_peek_modem (candidate))
            return candidate;
    }
    return NULL;
}

static MMDevice *
find_device_by_port (MMBaseManager  *manager,
                     MMKernelDevice *port)
{
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, manager->priv->devices);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        MMDevice *candidate = MM_DEVICE (value);

        if (mm_device_owns_port (candidate, port))
            return candidate;
    }
    return NULL;
}

static MMDevice *
find_device_by_physdev_uid (MMBaseManager *self,
                            const gchar   *physdev_uid)
{
    return g_hash_table_lookup (self->priv->devices, physdev_uid);
}

static MMDevice *
find_device_by_kernel_device (MMBaseManager  *manager,
                              MMKernelDevice *kernel_device)
{
    return find_device_by_physdev_uid (manager, mm_kernel_device_get_physdev_uid (kernel_device));
}

/*****************************************************************************/

typedef struct {
    MMBaseManager *self;
    MMDevice *device;
} FindDeviceSupportContext;

static void
find_device_support_context_free (FindDeviceSupportContext *ctx)
{
    g_object_unref (ctx->self);
    g_object_unref (ctx->device);
    g_slice_free (FindDeviceSupportContext, ctx);
}

static void
device_support_check_ready (MMPluginManager          *plugin_manager,
                            GAsyncResult             *res,
                            FindDeviceSupportContext *ctx)
{
    GError   *error = NULL;
    MMPlugin *plugin;

    /* If the device support check fails, either with an error, or afterwards
     * when trying to create a modem object, we must remove the MMDevice from
     * the tracking table of devices, so that a manual scan request afterwards
     * re-scans all ports. */

    /* Receive plugin result from the plugin manager */
    plugin = mm_plugin_manager_device_support_check_finish (plugin_manager, res, &error);
    if (!plugin) {
        mm_info ("Couldn't check support for device '%s': %s",
                 mm_device_get_uid (ctx->device), error->message);
        g_error_free (error);
        g_hash_table_remove (ctx->self->priv->devices, mm_device_get_uid (ctx->device));
        find_device_support_context_free (ctx);
        return;
    }

    /* Set the plugin as the one expected in the device */
    mm_device_set_plugin (ctx->device, G_OBJECT (plugin));
    g_object_unref (plugin);

    if (!mm_device_create_modem (ctx->device, ctx->self->priv->object_manager, &error)) {
        mm_warn ("Couldn't create modem for device '%s': %s",
                 mm_device_get_uid (ctx->device), error->message);
        g_error_free (error);
        g_hash_table_remove (ctx->self->priv->devices, mm_device_get_uid (ctx->device));
        find_device_support_context_free (ctx);
        return;
    }

    /* Modem now created */
    mm_info ("Modem for device '%s' successfully created",
             mm_device_get_uid (ctx->device));
    find_device_support_context_free (ctx);
}

static void
device_removed (MMBaseManager  *self,
                MMKernelDevice *kernel_device)
{
    MMDevice *device;
    const gchar *subsys;
    const gchar *name;

    g_return_if_fail (kernel_device != NULL);

    subsys = mm_kernel_device_get_subsystem (kernel_device);
    name = mm_kernel_device_get_name (kernel_device);

    if (!g_str_has_prefix (subsys, "usb") ||
        (name && g_str_has_prefix (name, "cdc-wdm"))) {
        /* Handle tty/net/wdm port removal */
        device = find_device_by_port (self, kernel_device);
        if (device) {
            mm_info ("(%s/%s): released by device '%s'", subsys, name, mm_device_get_uid (device));
            mm_device_release_port (device, kernel_device);

            /* If port probe list gets empty, remove the device object iself */
            if (!mm_device_peek_port_probe_list (device)) {
                /* The callback triggered when the device support is cancelled may end up
                 * removing the device from the HT, and that was the last full reference
                 * we kept. So, in order to make sure the reference is still valid after
                 * support_check_cancel(), we hold a full reference ourselves. */
                mm_dbg ("Removing empty device '%s'", mm_device_get_uid (device));
                g_object_ref (device);
                {
                    if (mm_plugin_manager_device_support_check_cancel (self->priv->plugin_manager, device))
                        mm_dbg ("Device support check has been cancelled");

                    /* The device may have already been removed from the tracking HT, we
                     * just try to remove it and if it fails, we ignore it */
                    mm_device_remove_modem (device);
                    g_hash_table_remove (self->priv->devices, mm_device_get_uid (device));
                }
                g_object_unref (device);
            }
        }

        return;
    }

#if defined WITH_UDEV
    /* When a USB modem is switching its USB configuration, udev may deliver
     * the remove events of USB interfaces associated with the old USB
     * configuration and the add events of USB interfaces associated with the
     * new USB configuration in an interleaved fashion. As we don't want a
     * remove event of an USB interface trigger the removal of a MMDevice for
     * the special case being handled here, we ignore any remove event with
     * DEVTYPE != usb_device.
     */
    if (g_strcmp0 (mm_kernel_device_get_property (kernel_device, "DEVTYPE"), "usb_device") != 0)
        return;
#endif

    /* This case is designed to handle the case where, at least with kernel 2.6.31, unplugging
     * an in-use ttyACMx device results in udev generating remove events for the usb, but the
     * ttyACMx device (subsystem tty) is not removed, since it was in-use.  So if we have not
     * found a modem for the port (above), we're going to look here to see if we have a modem
     * associated with the newly removed device.  If so, we'll remove the modem, since the
     * device has been removed.  That way, if the device is reinserted later, we'll go through
     * the process of exporting it.
     */
    device = find_device_by_kernel_device (self, kernel_device);
    if (device) {
        mm_dbg ("Removing device '%s'", mm_device_get_uid (device));
        mm_device_remove_modem (device);
        g_hash_table_remove (self->priv->devices, mm_device_get_uid (device));
        return;
    }
}

static void
device_added (MMBaseManager  *manager,
              MMKernelDevice *port,
              gboolean        hotplugged,
              gboolean        manual_scan)
{
    MMDevice    *device;
    const gchar *physdev_uid;

    g_return_if_fail (port != NULL);

    mm_dbg ("(%s/%s): adding device at sysfs path: %s",
            mm_kernel_device_get_subsystem (port),
            mm_kernel_device_get_name (port),
            mm_kernel_device_get_sysfs_path (port));

    /* Ignore devices that aren't completely configured by udev yet.  If
     * ModemManager is started in parallel with udev, explicitly requesting
     * devices may return devices for which not all udev rules have yet been
     * applied (a bug in udev/gudev).  Since we often need those rules to match
     * the device to a specific ModemManager driver, we need to ensure that all
     * rules have been processed before handling a device.
     *
     * This udev tag applies to each port in a device. In other words, the flag
     * may be set in some ports, but not in others */
    if (!mm_kernel_device_get_property_as_boolean (port, "ID_MM_CANDIDATE")) {
        /* This could mean that device changed, losing its ID_MM_CANDIDATE
         * flags (such as Bluetooth RFCOMM devices upon disconnect.
         * Try to forget it. */
        device_removed (manager, port);
        mm_dbg ("(%s/%s): port not candidate",
                mm_kernel_device_get_subsystem (port),
                mm_kernel_device_get_name (port));
        return;
    }

    /* Run port filter */
    if (!mm_filter_port (manager->priv->filter, port, manual_scan))
        return;

    /* If already added, ignore new event */
    if (find_device_by_port (manager, port)) {
        mm_dbg ("(%s/%s): port already added",
                mm_kernel_device_get_subsystem (port),
                mm_kernel_device_get_name (port));
        return;
    }

    /* Get the port's physical device's uid. All ports of the same physical
     * device will share the same uid. */
    physdev_uid = mm_kernel_device_get_physdev_uid (port);
    g_assert (physdev_uid);

    /* See if we already created an object to handle ports in this device */
    device = find_device_by_physdev_uid (manager, physdev_uid);
    if (!device) {
        FindDeviceSupportContext *ctx;

        mm_dbg ("(%s/%s): first port in device %s",
                mm_kernel_device_get_subsystem (port),
                mm_kernel_device_get_name (port),
                physdev_uid);

        /* Keep the device listed in the Manager */
        device = mm_device_new (physdev_uid, hotplugged, FALSE);
        g_hash_table_insert (manager->priv->devices,
                             g_strdup (physdev_uid),
                             device);

        /* Launch device support check */
        ctx = g_slice_new (FindDeviceSupportContext);
        ctx->self = g_object_ref (manager);
        ctx->device = g_object_ref (device);
        mm_plugin_manager_device_support_check (
            manager->priv->plugin_manager,
            device,
            (GAsyncReadyCallback) device_support_check_ready,
            ctx);
    } else
        mm_dbg ("(%s/%s): additional port in device %s",
                mm_kernel_device_get_subsystem (port),
                mm_kernel_device_get_name (port),
                physdev_uid);

    /* Grab the port in the existing device. */
    mm_device_grab_port (device, port);
}

static gboolean
handle_kernel_event (MMBaseManager            *self,
                     MMKernelEventProperties  *properties,
                     GError                  **error)
{
    MMKernelDevice *kernel_device;
    const gchar    *action;
    const gchar    *subsystem;
    const gchar    *name;
    const gchar    *uid;

    action = mm_kernel_event_properties_get_action (properties);
    if (!action) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS, "Missing mandatory parameter 'action'");
        return FALSE;
    }
    if (g_strcmp0 (action, "add") != 0 && g_strcmp0 (action, "remove") != 0) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS, "Invalid 'action' parameter given: '%s' (expected 'add' or 'remove')", action);
        return FALSE;
    }

    subsystem = mm_kernel_event_properties_get_subsystem (properties);
    if (!subsystem) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS, "Missing mandatory parameter 'subsystem'");
        return FALSE;
    }

    name = mm_kernel_event_properties_get_name (properties);
    if (!name) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS, "Missing mandatory parameter 'name'");
        return FALSE;
    }

    uid = mm_kernel_event_properties_get_uid (properties);

    mm_dbg ("Kernel event reported:");
    mm_dbg ("  action:    %s", action);
    mm_dbg ("  subsystem: %s", subsystem);
    mm_dbg ("  name:      %s", name);
    mm_dbg ("  uid:       %s", uid ? uid : "n/a");

#if defined WITH_UDEV
    kernel_device = mm_kernel_device_udev_new_from_properties (properties, error);
#else
    kernel_device = mm_kernel_device_generic_new (properties, error);
#endif

    if (!kernel_device)
        return FALSE;

    if (g_strcmp0 (action, "add") == 0)
        device_added (self, kernel_device, TRUE, TRUE);
    else if (g_strcmp0 (action, "remove") == 0)
        device_removed (self, kernel_device);
    else
        g_assert_not_reached ();
    g_object_unref (kernel_device);

    return TRUE;
}

#if defined WITH_UDEV

static void
handle_uevent (GUdevClient *client,
               const char *action,
               GUdevDevice *device,
               gpointer user_data)
{
    MMBaseManager *self = MM_BASE_MANAGER (user_data);
    const gchar *subsys;
    const gchar *name;
    MMKernelDevice *kernel_device;

    g_return_if_fail (action != NULL);

    /* A bit paranoid */
    subsys = g_udev_device_get_subsystem (device);
    g_return_if_fail (subsys != NULL);
    g_return_if_fail (g_str_equal (subsys, "tty") || g_str_equal (subsys, "net") || g_str_has_prefix (subsys, "usb"));

    kernel_device = mm_kernel_device_udev_new (device);

    /* We only care about tty/net and usb/cdc-wdm devices when adding modem ports,
     * but for remove, also handle usb parent device remove events
     */
    name = mm_kernel_device_get_name (kernel_device);
    if (   (g_str_equal (action, "add") || g_str_equal (action, "move") || g_str_equal (action, "change"))
        && (!g_str_has_prefix (subsys, "usb") || (name && g_str_has_prefix (name, "cdc-wdm"))))
        device_added (self, kernel_device, TRUE, FALSE);
    else if (g_str_equal (action, "remove"))
        device_removed (self, kernel_device);

    g_object_unref (kernel_device);
}

typedef struct {
    MMBaseManager *self;
    GUdevDevice *device;
    gboolean manual_scan;
} StartDeviceAdded;

static gboolean
start_device_added_idle (StartDeviceAdded *ctx)
{
    MMKernelDevice *kernel_device;

    kernel_device = mm_kernel_device_udev_new (ctx->device);
    device_added (ctx->self, kernel_device, FALSE, ctx->manual_scan);
    g_object_unref (kernel_device);

    g_object_unref (ctx->self);
    g_object_unref (ctx->device);
    g_slice_free (StartDeviceAdded, ctx);
    return G_SOURCE_REMOVE;
}

static void
start_device_added (MMBaseManager *self,
                    GUdevDevice *device,
                    gboolean manual_scan)
{
    StartDeviceAdded *ctx;

    ctx = g_slice_new (StartDeviceAdded);
    ctx->self = g_object_ref (self);
    ctx->device = g_object_ref (device);
    ctx->manual_scan = manual_scan;
    g_idle_add ((GSourceFunc)start_device_added_idle, ctx);
}

static void
process_scan (MMBaseManager *self,
              gboolean       manual_scan)
{
    GList *devices, *iter;

    devices = g_udev_client_query_by_subsystem (self->priv->udev, "tty");
    for (iter = devices; iter; iter = g_list_next (iter)) {
        start_device_added (self, G_UDEV_DEVICE (iter->data), manual_scan);
        g_object_unref (G_OBJECT (iter->data));
    }
    g_list_free (devices);

    devices = g_udev_client_query_by_subsystem (self->priv->udev, "net");
    for (iter = devices; iter; iter = g_list_next (iter)) {
        start_device_added (self, G_UDEV_DEVICE (iter->data), manual_scan);
        g_object_unref (G_OBJECT (iter->data));
    }
    g_list_free (devices);

    devices = g_udev_client_query_by_subsystem (self->priv->udev, "usb");
    for (iter = devices; iter; iter = g_list_next (iter)) {
        const gchar *name;

        name = g_udev_device_get_name (G_UDEV_DEVICE (iter->data));
        if (name && g_str_has_prefix (name, "cdc-wdm"))
            start_device_added (self, G_UDEV_DEVICE (iter->data), manual_scan);
        g_object_unref (G_OBJECT (iter->data));
    }
    g_list_free (devices);

    /* Newer kernels report 'usbmisc' subsystem */
    devices = g_udev_client_query_by_subsystem (self->priv->udev, "usbmisc");
    for (iter = devices; iter; iter = g_list_next (iter)) {
        const gchar *name;

        name = g_udev_device_get_name (G_UDEV_DEVICE (iter->data));
        if (name && g_str_has_prefix (name, "cdc-wdm"))
            start_device_added (self, G_UDEV_DEVICE (iter->data), manual_scan);
        g_object_unref (G_OBJECT (iter->data));
    }
    g_list_free (devices);
}

#endif

static void
process_initial_kernel_events (MMBaseManager *self)
{
    gchar *contents = NULL;
    gchar *line;
    GError *error = NULL;

    if (!self->priv->initial_kernel_events)
        return;

    if (!g_file_get_contents (self->priv->initial_kernel_events, &contents, NULL, &error)) {
        g_warning ("Couldn't load initial kernel events: %s", error->message);
        g_error_free (error);
        return;
    }

    line = contents;
    while (line) {
        gchar *next;

        next = strchr (line, '\n');
        if (next) {
            *next = '\0';
            next++;
        }

        /* ignore empty lines */
        if (line[0] != '\0') {
            MMKernelEventProperties *properties;

            properties = mm_kernel_event_properties_new_from_string (line, &error);
            if (!properties) {
                g_warning ("Couldn't parse line '%s' as initial kernel event %s", line, error->message);
                g_clear_error (&error);
            } else if (!handle_kernel_event (self, properties, &error)) {
                g_warning ("Couldn't process line '%s' as initial kernel event %s", line, error->message);
                g_clear_error (&error);
            } else
                g_debug ("Processed initial kernel event:' %s'", line);
            g_clear_object (&properties);
        }

        line = next;
    }

    g_free (contents);
}

void
mm_base_manager_start (MMBaseManager *self,
                       gboolean       manual_scan)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (MM_IS_BASE_MANAGER (self));

    if (!self->priv->auto_scan && !manual_scan) {
        /* If we have a list of initial kernel events, process it now */
        process_initial_kernel_events (self);
        return;
    }

#if defined WITH_UDEV
    mm_dbg ("Starting %s device scan...", manual_scan ? "manual" : "automatic");
    process_scan (self, manual_scan);
    mm_dbg ("Finished device scan...");
#else
    mm_dbg ("Unsupported %s device scan...", manual_scan ? "manual" : "automatic");
#endif
}

/*****************************************************************************/

static void
remove_disable_ready (MMBaseModem *modem,
                      GAsyncResult *res,
                      MMBaseManager *self)
{
    MMDevice *device;

    /* We don't care about errors disabling at this point */
    mm_base_modem_disable_finish (modem, res, NULL);

    device = find_device_by_modem (self, modem);
    if (device) {
        g_cancellable_cancel (mm_base_modem_peek_cancellable (modem));
        mm_device_remove_modem (device);
        g_hash_table_remove (self->priv->devices, device);
    }
}

static void
foreach_disable (gpointer key,
                 MMDevice *device,
                 MMBaseManager *self)
{
    MMBaseModem *modem;

    modem = mm_device_peek_modem (device);
    if (modem)
        mm_base_modem_disable (modem, (GAsyncReadyCallback)remove_disable_ready, self);
}

static gboolean
foreach_remove (gpointer key,
                MMDevice *device,
                MMBaseManager *self)
{
    MMBaseModem *modem;

    modem = mm_device_peek_modem (device);
    if (modem)
        g_cancellable_cancel (mm_base_modem_peek_cancellable (modem));
    mm_device_remove_modem (device);
    return TRUE;
}

void
mm_base_manager_shutdown (MMBaseManager *self,
                          gboolean disable)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (MM_IS_BASE_MANAGER (self));

    /* Cancel all ongoing auth requests */
    g_cancellable_cancel (self->priv->authp_cancellable);

    if (disable) {
        g_hash_table_foreach (self->priv->devices, (GHFunc)foreach_disable, self);

        /* Disabling may take a few iterations of the mainloop, so the caller
         * has to iterate the mainloop until all devices have been disabled and
         * removed.
         */
        return;
    }

    /* Otherwise, just remove directly */
    g_hash_table_foreach_remove (self->priv->devices, (GHRFunc)foreach_remove, self);
}

guint32
mm_base_manager_num_modems (MMBaseManager *self)
{
    GHashTableIter iter;
    gpointer key, value;
    guint32 n;

    g_return_val_if_fail (self != NULL, 0);
    g_return_val_if_fail (MM_IS_BASE_MANAGER (self), 0);

    n = 0;
    g_hash_table_iter_init (&iter, self->priv->devices);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        n += !!mm_device_peek_modem (MM_DEVICE (value));
    }

    return n;
}

/*****************************************************************************/
/* Set logging */

typedef struct {
    MMBaseManager *self;
    GDBusMethodInvocation *invocation;
    gchar *level;
} SetLoggingContext;

static void
set_logging_context_free (SetLoggingContext *ctx)
{
    g_object_unref (ctx->invocation);
    g_object_unref (ctx->self);
    g_free (ctx->level);
    g_free (ctx);
}

static void
set_logging_auth_ready (MMAuthProvider *authp,
                        GAsyncResult *res,
                        SetLoggingContext *ctx)
{
    GError *error = NULL;

    if (!mm_auth_provider_authorize_finish (authp, res, &error))
        g_dbus_method_invocation_take_error (ctx->invocation, error);
    else if (!mm_log_set_level (ctx->level, &error))
        g_dbus_method_invocation_take_error (ctx->invocation, error);
    else {
        mm_info ("logging: level '%s'", ctx->level);
        mm_gdbus_org_freedesktop_modem_manager1_complete_set_logging (
            MM_GDBUS_ORG_FREEDESKTOP_MODEM_MANAGER1 (ctx->self),
            ctx->invocation);
    }

    set_logging_context_free (ctx);
}

static gboolean
handle_set_logging (MmGdbusOrgFreedesktopModemManager1 *manager,
                    GDBusMethodInvocation *invocation,
                    const gchar *level)
{
    SetLoggingContext *ctx;

    ctx = g_new0 (SetLoggingContext, 1);
    ctx->self = g_object_ref (manager);
    ctx->invocation = g_object_ref (invocation);
    ctx->level = g_strdup (level);

    mm_auth_provider_authorize (ctx->self->priv->authp,
                                invocation,
                                MM_AUTHORIZATION_MANAGER_CONTROL,
                                ctx->self->priv->authp_cancellable,
                                (GAsyncReadyCallback)set_logging_auth_ready,
                                ctx);
    return TRUE;
}

/*****************************************************************************/
/* Manual scan */

typedef struct {
    MMBaseManager *self;
    GDBusMethodInvocation *invocation;
} ScanDevicesContext;

static void
scan_devices_context_free (ScanDevicesContext *ctx)
{
    g_object_unref (ctx->invocation);
    g_object_unref (ctx->self);
    g_free (ctx);
}

static void
scan_devices_auth_ready (MMAuthProvider *authp,
                         GAsyncResult *res,
                         ScanDevicesContext *ctx)
{
    GError *error = NULL;

    if (!mm_auth_provider_authorize_finish (authp, res, &error))
        g_dbus_method_invocation_take_error (ctx->invocation, error);
    else {
#if defined WITH_UDEV
        /* Otherwise relaunch device scan */
        mm_base_manager_start (MM_BASE_MANAGER (ctx->self), TRUE);
        mm_gdbus_org_freedesktop_modem_manager1_complete_scan_devices (
            MM_GDBUS_ORG_FREEDESKTOP_MODEM_MANAGER1 (ctx->self),
            ctx->invocation);
#else
        g_dbus_method_invocation_return_error_literal (
            ctx->invocation, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
            "Cannot request manual scan of devices: unsupported");
#endif
    }

    scan_devices_context_free (ctx);
}

static gboolean
handle_scan_devices (MmGdbusOrgFreedesktopModemManager1 *manager,
                     GDBusMethodInvocation *invocation)
{
    ScanDevicesContext *ctx;

    ctx = g_new (ScanDevicesContext, 1);
    ctx->self = g_object_ref (manager);
    ctx->invocation = g_object_ref (invocation);

    mm_auth_provider_authorize (ctx->self->priv->authp,
                                invocation,
                                MM_AUTHORIZATION_MANAGER_CONTROL,
                                ctx->self->priv->authp_cancellable,
                                (GAsyncReadyCallback)scan_devices_auth_ready,
                                ctx);
    return TRUE;
}

/*****************************************************************************/

typedef struct {
    MMBaseManager *self;
    GDBusMethodInvocation *invocation;
    GVariant *dictionary;
} ReportKernelEventContext;

static void
report_kernel_event_context_free (ReportKernelEventContext *ctx)
{
    g_object_unref (ctx->invocation);
    g_object_unref (ctx->self);
    g_variant_unref (ctx->dictionary);
    g_slice_free (ReportKernelEventContext, ctx);
}

static void
report_kernel_event_auth_ready (MMAuthProvider           *authp,
                                GAsyncResult             *res,
                                ReportKernelEventContext *ctx)
{
    GError                  *error = NULL;
    MMKernelEventProperties *properties = NULL;

    if (!mm_auth_provider_authorize_finish (authp, res, &error))
        goto out;

#if defined WITH_UDEV
    if (ctx->self->priv->auto_scan) {
        error = g_error_new_literal (MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
                                     "Cannot report kernel event: "
                                     "udev monitoring already in place");
        goto out;
    }
#endif

    properties = mm_kernel_event_properties_new_from_dictionary (ctx->dictionary, &error);
    if (!properties)
        goto out;

    handle_kernel_event (ctx->self, properties, &error);

out:
    if (error)
        g_dbus_method_invocation_take_error (ctx->invocation, error);
    else
        mm_gdbus_org_freedesktop_modem_manager1_complete_report_kernel_event (
            MM_GDBUS_ORG_FREEDESKTOP_MODEM_MANAGER1 (ctx->self),
            ctx->invocation);

    if (properties)
        g_object_unref (properties);
    report_kernel_event_context_free (ctx);
}

static gboolean
handle_report_kernel_event (MmGdbusOrgFreedesktopModemManager1 *manager,
                            GDBusMethodInvocation *invocation,
                            GVariant *dictionary)
{
    ReportKernelEventContext *ctx;

    ctx = g_slice_new0 (ReportKernelEventContext);
    ctx->self = g_object_ref (manager);
    ctx->invocation = g_object_ref (invocation);
    ctx->dictionary = g_variant_ref (dictionary);

    mm_auth_provider_authorize (ctx->self->priv->authp,
                                invocation,
                                MM_AUTHORIZATION_MANAGER_CONTROL,
                                ctx->self->priv->authp_cancellable,
                                (GAsyncReadyCallback)report_kernel_event_auth_ready,
                                ctx);
    return TRUE;
}

/*****************************************************************************/
/* Test profile setup */

static gboolean
handle_set_profile (MmGdbusTest *skeleton,
                    GDBusMethodInvocation *invocation,
                    const gchar *id,
                    const gchar *plugin_name,
                    const gchar *const *ports,
                    MMBaseManager *self)
{
    MMPlugin *plugin;
    MMDevice *device;
    gchar *physdev_uid;
    GError *error = NULL;

    mm_info ("Test profile set to: '%s'", id);

    /* Create device and keep it listed in the Manager */
    physdev_uid = g_strdup_printf ("/virtual/%s", id);
    device = mm_device_new (physdev_uid, TRUE, TRUE);
    g_hash_table_insert (self->priv->devices, physdev_uid, device);

    /* Grab virtual ports */
    mm_device_virtual_grab_ports (device, (const gchar **)ports);

    /* Set plugin to use */
    plugin = mm_plugin_manager_peek_plugin (self->priv->plugin_manager, plugin_name);
    if (!plugin) {
        error = g_error_new (MM_CORE_ERROR,
                             MM_CORE_ERROR_NOT_FOUND,
                             "Requested plugin '%s' not found",
                             plugin_name);
        mm_warn ("Couldn't set plugin for virtual device '%s': %s",
                 mm_device_get_uid (device),
                 error->message);
        goto out;
    }
    mm_device_set_plugin (device, G_OBJECT (plugin));

    /* Create modem */
    if (!mm_device_create_modem (device, self->priv->object_manager, &error)) {
        mm_warn ("Couldn't create modem for virtual device '%s': %s",
                 mm_device_get_uid (device),
                 error->message);
        goto out;
    }

    mm_info ("Modem for virtual device '%s' successfully created",
             mm_device_get_uid (device));

out:

    if (error) {
        mm_device_remove_modem (device);
        g_hash_table_remove (self->priv->devices, mm_device_get_uid (device));
        g_dbus_method_invocation_return_gerror (invocation, error);
        g_error_free (error);
    } else
        mm_gdbus_test_complete_set_profile (skeleton, invocation);

    return TRUE;
}

/*****************************************************************************/

MMBaseManager *
mm_base_manager_new (GDBusConnection  *connection,
                     const gchar      *plugin_dir,
                     gboolean          auto_scan,
                     MMFilterRule      filter_policy,
                     const gchar      *initial_kernel_events,
                     gboolean          enable_test,
                     GError          **error)
{
    g_return_val_if_fail (G_IS_DBUS_CONNECTION (connection), NULL);

    return g_initable_new (MM_TYPE_BASE_MANAGER,
                           NULL, /* cancellable */
                           error,
                           MM_BASE_MANAGER_CONNECTION,            connection,
                           MM_BASE_MANAGER_PLUGIN_DIR,            plugin_dir,
                           MM_BASE_MANAGER_AUTO_SCAN,             auto_scan,
                           MM_BASE_MANAGER_FILTER_POLICY,         filter_policy,
                           MM_BASE_MANAGER_INITIAL_KERNEL_EVENTS, initial_kernel_events,
                           MM_BASE_MANAGER_ENABLE_TEST,           enable_test,
                           NULL);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
    MMBaseManagerPrivate *priv = MM_BASE_MANAGER (object)->priv;

    switch (prop_id) {
    case PROP_CONNECTION: {
        gboolean had_connection = FALSE;

        if (priv->connection) {
            had_connection = TRUE;
            g_object_unref (priv->connection);
        }
        priv->connection = g_value_dup_object (value);
        /* Propagate connection loss to subobjects */
        if (had_connection && !priv->connection) {
            if (priv->object_manager) {
                mm_dbg ("Stopping connection in object manager server");
                g_dbus_object_manager_server_set_connection (priv->object_manager, NULL);
            }
            if (priv->test_skeleton &&
                g_dbus_interface_skeleton_get_connection (G_DBUS_INTERFACE_SKELETON (priv->test_skeleton))) {
                mm_dbg ("Stopping connection in test skeleton");
                g_dbus_interface_skeleton_unexport (G_DBUS_INTERFACE_SKELETON (priv->test_skeleton));
            }
        }
        break;
    }
    case PROP_AUTO_SCAN:
        priv->auto_scan = g_value_get_boolean (value);
        break;
    case PROP_FILTER_POLICY:
        priv->filter_policy = g_value_get_flags (value);
        break;
    case PROP_ENABLE_TEST:
        priv->enable_test = g_value_get_boolean (value);
        break;
    case PROP_PLUGIN_DIR:
        g_free (priv->plugin_dir);
        priv->plugin_dir = g_value_dup_string (value);
        break;
    case PROP_INITIAL_KERNEL_EVENTS:
        g_free (priv->initial_kernel_events);
        priv->initial_kernel_events = g_value_dup_string (value);
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
    MMBaseManagerPrivate *priv = MM_BASE_MANAGER (object)->priv;

    switch (prop_id) {
    case PROP_CONNECTION:
        g_value_set_object (value, priv->connection);
        break;
    case PROP_AUTO_SCAN:
        g_value_set_boolean (value, priv->auto_scan);
        break;
    case PROP_FILTER_POLICY:
        g_value_set_flags (value, priv->filter_policy);
        break;
    case PROP_ENABLE_TEST:
        g_value_set_boolean (value, priv->enable_test);
        break;
    case PROP_PLUGIN_DIR:
        g_value_set_string (value, priv->plugin_dir);
        break;
    case PROP_INITIAL_KERNEL_EVENTS:
        g_value_set_string (value, priv->initial_kernel_events);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
mm_base_manager_init (MMBaseManager *manager)
{
    MMBaseManagerPrivate *priv;

    /* Setup private data */
    manager->priv = priv = G_TYPE_INSTANCE_GET_PRIVATE (manager,
                                                        MM_TYPE_BASE_MANAGER,
                                                        MMBaseManagerPrivate);

    /* Setup authorization provider */
    priv->authp = mm_auth_get_provider ();
    priv->authp_cancellable = g_cancellable_new ();

    /* Setup internal lists of device objects */
    priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

#if defined WITH_UDEV
    {
        const gchar *subsys[5] = { "tty", "net", "usb", "usbmisc", NULL };

        /* Setup UDev client */
        priv->udev = g_udev_client_new (subsys);
    }
#endif

    /* By default, enable autoscan */
    priv->auto_scan = TRUE;

    /* By default, no test interface */
    priv->enable_test = FALSE;

    /* Setup Object Manager Server */
    priv->object_manager = g_dbus_object_manager_server_new (MM_DBUS_PATH);

    /* Enable processing of input DBus messages */
    g_signal_connect (manager,
                      "handle-set-logging",
                      G_CALLBACK (handle_set_logging),
                      NULL);
    g_signal_connect (manager,
                      "handle-scan-devices",
                      G_CALLBACK (handle_scan_devices),
                      NULL);
    g_signal_connect (manager,
                      "handle-report-kernel-event",
                      G_CALLBACK (handle_report_kernel_event),
                      NULL);
}

static gboolean
initable_init (GInitable *initable,
               GCancellable *cancellable,
               GError **error)
{
    MMBaseManagerPrivate *priv = MM_BASE_MANAGER (initable)->priv;

#if defined WITH_UDEV
    /* If autoscan enabled, list for udev events */
    if (priv->auto_scan)
        g_signal_connect (priv->udev, "uevent", G_CALLBACK (handle_uevent), initable);
#endif

    /* Create filter */
    priv->filter = mm_filter_new (priv->filter_policy, error);
    if (!priv->filter)
        return FALSE;

    /* Create plugin manager */
    priv->plugin_manager = mm_plugin_manager_new (priv->plugin_dir, priv->filter, error);
    if (!priv->plugin_manager)
        return FALSE;

    /* Export the manager interface */
    if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (initable),
                                           priv->connection,
                                           MM_DBUS_PATH,
                                           error))
        return FALSE;

    /* Export the Object Manager interface */
    g_dbus_object_manager_server_set_connection (priv->object_manager,
                                                 priv->connection);

    /* Setup the Test skeleton and export the interface */
    if (priv->enable_test) {
        priv->test_skeleton = mm_gdbus_test_skeleton_new ();
        g_signal_connect (priv->test_skeleton,
                          "handle-set-profile",
                          G_CALLBACK (handle_set_profile),
                          initable);
        if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->test_skeleton),
                                               priv->connection,
                                               MM_DBUS_PATH,
                                               error))
            return FALSE;
    }

    /* All good */
    return TRUE;
}

static void
finalize (GObject *object)
{
    MMBaseManagerPrivate *priv = MM_BASE_MANAGER (object)->priv;

    g_free (priv->initial_kernel_events);
    g_free (priv->plugin_dir);

    g_hash_table_destroy (priv->devices);

#if defined WITH_UDEV
    if (priv->udev)
        g_object_unref (priv->udev);
#endif

    if (priv->filter)
        g_object_unref (priv->filter);

    if (priv->plugin_manager)
        g_object_unref (priv->plugin_manager);

    if (priv->object_manager)
        g_object_unref (priv->object_manager);

    if (priv->test_skeleton)
        g_object_unref (priv->test_skeleton);

    if (priv->connection)
        g_object_unref (priv->connection);

    if (priv->authp)
        g_object_unref (priv->authp);

    if (priv->authp_cancellable)
        g_object_unref (priv->authp_cancellable);

    G_OBJECT_CLASS (mm_base_manager_parent_class)->finalize (object);
}

static void
initable_iface_init (GInitableIface *iface)
{
    iface->init = initable_init;
}

static void
mm_base_manager_class_init (MMBaseManagerClass *manager_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

    g_type_class_add_private (object_class, sizeof (MMBaseManagerPrivate));

    /* Virtual methods */
    object_class->set_property = set_property;
    object_class->get_property = get_property;
    object_class->finalize = finalize;

    /* Properties */

    g_object_class_install_property
        (object_class, PROP_CONNECTION,
         g_param_spec_object (MM_BASE_MANAGER_CONNECTION,
                              "Connection",
                              "GDBus connection to the system bus.",
                              G_TYPE_DBUS_CONNECTION,
                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

    g_object_class_install_property
        (object_class, PROP_AUTO_SCAN,
         g_param_spec_boolean (MM_BASE_MANAGER_AUTO_SCAN,
                               "Auto scan",
                               "Automatically look for new devices",
                               TRUE,
                               G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property (
        object_class, PROP_FILTER_POLICY,
        g_param_spec_flags (MM_BASE_MANAGER_FILTER_POLICY,
                            "Filter policy",
                            "Mask of rules enabled in the filter",
                            MM_TYPE_FILTER_RULE,
                            MM_FILTER_RULE_NONE,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property
        (object_class, PROP_ENABLE_TEST,
         g_param_spec_boolean (MM_BASE_MANAGER_ENABLE_TEST,
                               "Enable tests",
                               "Enable the Test interface",
                               FALSE,
                               G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property
        (object_class, PROP_PLUGIN_DIR,
         g_param_spec_string (MM_BASE_MANAGER_PLUGIN_DIR,
                              "Plugin directory",
                              "Where to look for plugins",
                              NULL,
                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

    g_object_class_install_property
        (object_class, PROP_INITIAL_KERNEL_EVENTS,
         g_param_spec_string (MM_BASE_MANAGER_INITIAL_KERNEL_EVENTS,
                              "Initial kernel events",
                              "Path to a file with the list of initial kernel events",
                              NULL,
                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
