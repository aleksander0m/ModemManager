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
 * Copyright (C) 2016 Velocloud, Inc.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-kernel-device-generic.h"
#include "mm-kernel-device-generic-rules.h"
#include "mm-log.h"

#if !defined UDEVRULESDIR
# error UDEVRULESDIR is not defined
#endif

static void initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_EXTENDED (MMKernelDeviceGeneric, mm_kernel_device_generic,  MM_TYPE_KERNEL_DEVICE, 0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init))

enum {
    PROP_0,
    PROP_PROPERTIES,
    PROP_RULES,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

struct _MMKernelDeviceGenericPrivate {
    /* Input properties */
    MMKernelEventProperties *properties;
    /* Rules to apply */
    GArray *rules;

    /* Contents from sysfs */
    gchar   *driver;
    gchar   *sysfs_path;
    gchar   *interface_sysfs_path;
    guint8   interface_class;
    guint8   interface_subclass;
    guint8   interface_protocol;
    guint8   interface_number;
    gchar   *physdev_sysfs_path;
    guint16  physdev_vid;
    guint16  physdev_pid;
    gchar   *physdev_subsystem;
    gchar   *physdev_manufacturer;
    gchar   *physdev_product;
};

static guint
read_sysfs_property_as_hex (const gchar *path,
                            const gchar *property)
{
    gchar *aux;
    gchar *contents = NULL;
    guint val = 0;

    aux = g_strdup_printf ("%s/%s", path, property);
    if (g_file_get_contents (aux, &contents, NULL, NULL)) {
        g_strdelimit (contents, "\r\n", ' ');
        g_strstrip (contents);
        mm_get_uint_from_hex_str (contents, &val);
    }
    g_free (contents);
    g_free (aux);
    return val;
}

static gchar *
read_sysfs_property_as_string (const gchar *path,
                               const gchar *property)
{
    gchar *aux;
    gchar *contents = NULL;

    aux = g_strdup_printf ("%s/%s", path, property);
    if (g_file_get_contents (aux, &contents, NULL, NULL)) {
        g_strdelimit (contents, "\r\n", ' ');
        g_strstrip (contents);
    }
    g_free (aux);
    return contents;
}

/*****************************************************************************/
/* Load contents */

static void
preload_sysfs_path (MMKernelDeviceGeneric *self)
{
    gchar *tmp;

    if (self->priv->sysfs_path)
        return;

    /* sysfs can be built directly using subsystem and name; e.g. for subsystem
     * usbmisc and name cdc-wdm0:
     *    $ realpath /sys/class/usbmisc/cdc-wdm0
     *    /sys/devices/pci0000:00/0000:00:1d.0/usb4/4-1/4-1.3/4-1.3:1.8/usbmisc/cdc-wdm0
     */
    tmp = g_strdup_printf ("/sys/class/%s/%s",
                           mm_kernel_event_properties_get_subsystem (self->priv->properties),
                           mm_kernel_event_properties_get_name      (self->priv->properties));

    self->priv->sysfs_path = canonicalize_file_name (tmp);
    if (!self->priv->sysfs_path || !g_file_test (self->priv->sysfs_path, G_FILE_TEST_EXISTS)) {
        mm_warn ("Invalid sysfs path read for %s/%s",
                 mm_kernel_event_properties_get_subsystem (self->priv->properties),
                 mm_kernel_event_properties_get_name      (self->priv->properties));
        g_clear_pointer (&self->priv->sysfs_path, g_free);
    }

    if (self->priv->sysfs_path) {
        const gchar *devpath;

        mm_dbg ("(%s/%s) sysfs path: %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->sysfs_path);
        devpath = (g_str_has_prefix (self->priv->sysfs_path, "/sys") ?
                   &self->priv->sysfs_path[4] :
                   self->priv->sysfs_path);
        g_object_set_data_full (G_OBJECT (self), "DEVPATH", g_strdup (devpath), g_free);
    }
    g_free (tmp);
}

static void
preload_interface_sysfs_path (MMKernelDeviceGeneric *self)
{
    gchar *dirpath;
    gchar *aux;

    if (self->priv->interface_sysfs_path || !self->priv->sysfs_path)
        return;

    /* parent sysfs can be built directly using subsystem and name; e.g. for
     * subsystem usbmisc and name cdc-wdm0:
     *    $ realpath /sys/class/usbmisc/cdc-wdm0/device
     *    /sys/devices/pci0000:00/0000:00:1d.0/usb4/4-1/4-1.3/4-1.3:1.8
     *
     * This sysfs path will be equal for all devices exported from within the
     * same interface (e.g. a pair of cdc-wdm/wwan devices).
     *
     * The correct parent dir we want to have is the first one with "usb" subsystem.
     */
    aux = g_strdup_printf ("%s/device", self->priv->sysfs_path);
    dirpath = canonicalize_file_name (aux);
    g_free (aux);

    while (dirpath) {
        gchar *subsystem_filepath;

        /* Directory must exist */
        if (!g_file_test (dirpath, G_FILE_TEST_EXISTS))
            break;

        /* If subsystem file not found, keep looping */
        subsystem_filepath = g_strdup_printf ("%s/subsystem", dirpath);
        if (g_file_test (subsystem_filepath, G_FILE_TEST_EXISTS)) {
            gchar *canonicalized_subsystem;
            gchar *subsystem_name;

            canonicalized_subsystem = canonicalize_file_name (subsystem_filepath);
            g_free (subsystem_filepath);

            subsystem_name = g_path_get_basename (canonicalized_subsystem);
            g_free (canonicalized_subsystem);

            if (subsystem_name && g_str_equal (subsystem_name, "usb")) {
                self->priv->interface_sysfs_path = dirpath;
                g_free (subsystem_name);
                break;
            }
            g_free (subsystem_name);
        } else
            g_free (subsystem_filepath);

        /* Just in case */
        if (g_str_equal (dirpath, "/")) {
            g_free (dirpath);
            break;
        }

        aux = g_path_get_dirname (dirpath);
        g_free (dirpath);
        dirpath = aux;
    }

    if (self->priv->interface_sysfs_path)
        mm_dbg ("(%s/%s) interface sysfs path: %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->interface_sysfs_path);
}

static void
preload_physdev_sysfs_path (MMKernelDeviceGeneric *self)
{
    /* physdev sysfs is the dirname of the parent sysfs path, e.g.:
     *    /sys/devices/pci0000:00/0000:00:1d.0/usb4/4-1/4-1.3
     *
     * This sysfs path will be equal for all devices exported from the same
     * physical device.
     */
    if (!self->priv->physdev_sysfs_path && self->priv->interface_sysfs_path)
        self->priv->physdev_sysfs_path = g_path_get_dirname (self->priv->interface_sysfs_path);

    if (self->priv->physdev_sysfs_path)
        mm_dbg ("(%s/%s) physdev sysfs path: %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->physdev_sysfs_path);
}

static void
preload_driver (MMKernelDeviceGeneric *self)
{
    if (!self->priv->driver && self->priv->interface_sysfs_path) {
        gchar *tmp;
        gchar *tmp2;

        tmp = g_strdup_printf ("%s/driver", self->priv->interface_sysfs_path);
        tmp2 = canonicalize_file_name (tmp);
        if (tmp2 && g_file_test (tmp2, G_FILE_TEST_EXISTS))
            self->priv->driver = g_path_get_basename (tmp2);
        g_free (tmp2);
        g_free (tmp);
    }

    if (self->priv->driver)
        mm_dbg ("(%s/%s) driver: %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->driver);
}

static void
preload_physdev_vid (MMKernelDeviceGeneric *self)
{
    if (!self->priv->physdev_vid && self->priv->physdev_sysfs_path) {
        guint val;

        val = read_sysfs_property_as_hex (self->priv->physdev_sysfs_path, "idVendor");
        if (val && val <= G_MAXUINT16)
            self->priv->physdev_vid = val;
    }

    if (self->priv->physdev_vid) {
        mm_dbg ("(%s/%s) vid (ID_VENDOR_ID): 0x%04x",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->physdev_vid);
        g_object_set_data_full (G_OBJECT (self), "ID_VENDOR_ID", g_strdup_printf ("%04x", self->priv->physdev_vid), g_free);
    } else
        mm_dbg ("(%s/%s) vid: unknown",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties));

}

static void
preload_physdev_pid (MMKernelDeviceGeneric *self)
{
    if (!self->priv->physdev_pid && self->priv->physdev_sysfs_path) {
        guint val;

        val = read_sysfs_property_as_hex (self->priv->physdev_sysfs_path, "idProduct");
        if (val && val <= G_MAXUINT16)
            self->priv->physdev_pid = val;
    }

    if (self->priv->physdev_pid) {
        mm_dbg ("(%s/%s) pid (ID_MODEL_ID): 0x%04x",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->physdev_pid);
        g_object_set_data_full (G_OBJECT (self), "ID_MODEL_ID", g_strdup_printf ("%04x", self->priv->physdev_pid), g_free);
    } else
        mm_dbg ("(%s/%s) pid: unknown",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties));
}

static void
preload_physdev_subsystem (MMKernelDeviceGeneric *self)
{
    if (!self->priv->physdev_subsystem && self->priv->physdev_sysfs_path) {
        gchar *aux;
        gchar *subsyspath;

        aux = g_strdup_printf ("%s/subsystem", self->priv->physdev_sysfs_path);
        subsyspath = canonicalize_file_name (aux);
        self->priv->physdev_subsystem = g_path_get_dirname (subsyspath);
        g_free (subsyspath);
        g_free (aux);
    }

    mm_dbg ("(%s/%s) subsystem: %s",
            mm_kernel_event_properties_get_subsystem (self->priv->properties),
            mm_kernel_event_properties_get_name      (self->priv->properties),
            self->priv->physdev_subsystem ? self->priv->physdev_subsystem : "unknown");
}

static void
preload_manufacturer (MMKernelDeviceGeneric *self)
{
    if (!self->priv->physdev_manufacturer)
        self->priv->physdev_manufacturer = (self->priv->physdev_sysfs_path ? read_sysfs_property_as_string (self->priv->physdev_sysfs_path, "manufacturer") : NULL);

    if (self->priv->physdev_manufacturer) {
        mm_dbg ("(%s/%s) manufacturer (ID_VENDOR): %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->physdev_manufacturer);
        g_object_set_data_full (G_OBJECT (self), "ID_VENDOR", g_strdup (self->priv->physdev_manufacturer), g_free);
    } else
        mm_dbg ("(%s/%s) manufacturer: unknown",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties));
}

static void
preload_product (MMKernelDeviceGeneric *self)
{
    if (!self->priv->physdev_product)
        self->priv->physdev_product = (self->priv->physdev_sysfs_path ? read_sysfs_property_as_string (self->priv->physdev_sysfs_path, "product") : NULL);

    if (self->priv->physdev_product) {
        mm_dbg ("(%s/%s) product (ID_MODEL): %s",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->physdev_product);
        g_object_set_data_full (G_OBJECT (self), "ID_MODEL", g_strdup (self->priv->physdev_product), g_free);
    } else
        mm_dbg ("(%s/%s) product: unknown",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties));

}

static void
preload_interface_class (MMKernelDeviceGeneric *self)
{
    self->priv->interface_class = (self->priv->interface_sysfs_path ? read_sysfs_property_as_hex (self->priv->interface_sysfs_path, "bInterfaceClass") : 0x00);
    mm_dbg ("(%s/%s) interface class: 0x%02x",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->interface_class);
}

static void
preload_interface_subclass (MMKernelDeviceGeneric *self)
{
    self->priv->interface_subclass = (self->priv->interface_sysfs_path ? read_sysfs_property_as_hex (self->priv->interface_sysfs_path, "bInterfaceSubClass") : 0x00);
    mm_dbg ("(%s/%s) interface subclass: 0x%02x",
                mm_kernel_event_properties_get_subsystem (self->priv->properties),
                mm_kernel_event_properties_get_name      (self->priv->properties),
                self->priv->interface_subclass);
}

static void
preload_interface_protocol (MMKernelDeviceGeneric *self)
{
    self->priv->interface_protocol = (self->priv->interface_sysfs_path ? read_sysfs_property_as_hex (self->priv->interface_sysfs_path, "bInterfaceProtocol") : 0x00);
    mm_dbg ("(%s/%s) interface protocol: 0x%02x",
            mm_kernel_event_properties_get_subsystem (self->priv->properties),
            mm_kernel_event_properties_get_name      (self->priv->properties),
            self->priv->interface_protocol);
}

static void
preload_interface_number (MMKernelDeviceGeneric *self)
{
    self->priv->interface_number = (self->priv->interface_sysfs_path ? read_sysfs_property_as_hex (self->priv->interface_sysfs_path, "bInterfaceNumber") : 0x00);
    mm_dbg ("(%s/%s) interface number (ID_USB_INTERFACE_NUM): 0x%02x",
            mm_kernel_event_properties_get_subsystem (self->priv->properties),
            mm_kernel_event_properties_get_name      (self->priv->properties),
            self->priv->interface_number);
    g_object_set_data_full (G_OBJECT (self), "ID_USB_INTERFACE_NUM", g_strdup_printf ("%02x", self->priv->interface_number), g_free);
}

static void
preload_contents (MMKernelDeviceGeneric *self)
{
    preload_sysfs_path           (self);
    preload_interface_sysfs_path (self);
    preload_interface_class      (self);
    preload_interface_subclass   (self);
    preload_interface_protocol   (self);
    preload_interface_number     (self);
    preload_physdev_sysfs_path   (self);
    preload_manufacturer         (self);
    preload_product              (self);
    preload_driver               (self);
    preload_physdev_vid          (self);
    preload_physdev_pid          (self);
    preload_physdev_subsystem    (self);
}

/*****************************************************************************/

static const gchar *
kernel_device_get_subsystem (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return mm_kernel_event_properties_get_subsystem (MM_KERNEL_DEVICE_GENERIC (self)->priv->properties);
}

static const gchar *
kernel_device_get_name (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return mm_kernel_event_properties_get_name (MM_KERNEL_DEVICE_GENERIC (self)->priv->properties);
}

static const gchar *
kernel_device_get_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->sysfs_path;
}

static gint
kernel_device_get_interface_class (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), -1);

    return (gint) MM_KERNEL_DEVICE_GENERIC (self)->priv->interface_class;
}

static gint
kernel_device_get_interface_subclass (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), -1);

    return (gint) MM_KERNEL_DEVICE_GENERIC (self)->priv->interface_subclass;
}

static gint
kernel_device_get_interface_protocol (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), -1);

    return (gint) MM_KERNEL_DEVICE_GENERIC (self)->priv->interface_protocol;
}

static const gchar *
kernel_device_get_interface_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->interface_sysfs_path;
}

static const gchar *
kernel_device_get_physdev_uid (MMKernelDevice *self)
{
    const gchar *uid;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    /* Prefer the one coming in the properties, if any */
    if ((uid = mm_kernel_event_properties_get_uid (MM_KERNEL_DEVICE_GENERIC (self)->priv->properties)) != NULL)
        return uid;

    /* Try to load from properties set */
    if ((uid = mm_kernel_device_get_property (self, "ID_MM_PHYSDEV_UID")) != NULL)
        return uid;

    /* Use physical device path, if any */
    if (MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_sysfs_path)
        return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_sysfs_path;

    /* If there is no physdev sysfs path, e.g. for platform ports, use the device sysfs itself */
    return MM_KERNEL_DEVICE_GENERIC (self)->priv->sysfs_path;
}

static const gchar *
kernel_device_get_driver (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->driver;
}

static guint16
kernel_device_get_physdev_vid (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), 0);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_vid;
}

static guint16
kernel_device_get_physdev_pid (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), 0);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_pid;
}

static const gchar *
kernel_device_get_physdev_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), 0);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_sysfs_path;
}

static const gchar *
kernel_device_get_physdev_subsystem (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_subsystem;
}

static const gchar *
kernel_device_get_physdev_manufacturer (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), 0);

    return MM_KERNEL_DEVICE_GENERIC (self)->priv->physdev_manufacturer;
}

static gboolean
kernel_device_cmp (MMKernelDevice *a,
                   MMKernelDevice *b)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (a), FALSE);
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (b), FALSE);

    return (!g_strcmp0 (mm_kernel_device_get_subsystem (a), mm_kernel_device_get_subsystem (b)) &&
            !g_strcmp0 (mm_kernel_device_get_name      (a), mm_kernel_device_get_name      (b)));
}

/*****************************************************************************/

static gboolean
string_match (const gchar *str,
              const gchar *original_pattern)
{
    gchar    *pattern;
    gchar    *start;
    gboolean  open_prefix = FALSE;
    gboolean  open_suffix = FALSE;
    gboolean  match;

    pattern = g_strdup (original_pattern);
    start = pattern;

    if (start[0] == '*') {
        open_prefix = TRUE;
        start++;
    }

    if (start[strlen (start) - 1] == '*') {
        open_suffix = TRUE;
        start[strlen (start) - 1] = '\0';
    }

    if (open_suffix && !open_prefix)
        match = g_str_has_prefix (str, start);
    else if (!open_suffix && open_prefix)
        match = g_str_has_suffix (str, start);
    else if (open_suffix && open_prefix)
        match = !!strstr (str, start);
    else
        match = g_str_equal (str, start);

    g_free (pattern);
    return match;
}

static gboolean
check_condition (MMKernelDeviceGeneric *self,
                 MMUdevRuleMatch       *match)
{
    gboolean condition_equal;

    condition_equal = (match->type == MM_UDEV_RULE_MATCH_TYPE_EQUAL);

    /* We only apply 'add' rules */
    if (g_str_equal (match->parameter, "ACTION"))
        return ((!!strstr (match->value, "add")) == condition_equal);

    /* We look for the subsystem string in the whole sysfs path.
     *
     * Note that we're not really making a difference between "SUBSYSTEMS"
     * (where the whole device tree is checked) and "SUBSYSTEM" (where just one
     * single device is checked), because a lot of the MM udev rules are meant
     * to just tag the physical device (e.g. with ID_MM_DEVICE_IGNORE) instead
     * of the single ports. In our case with the custom parsing, we do tag all
     * independent ports.
     */
    if (g_str_equal (match->parameter, "SUBSYSTEMS") || g_str_equal (match->parameter, "SUBSYSTEM"))
        return ((self->priv->sysfs_path && !!strstr (self->priv->sysfs_path, match->value)) == condition_equal);

    /* Exact DRIVER match? We also include the check for DRIVERS, even if we
     * only apply it to this port driver. */
    if (g_str_equal (match->parameter, "DRIVER") || g_str_equal (match->parameter, "DRIVERS"))
        return ((!g_strcmp0 (match->value, mm_kernel_device_get_driver (MM_KERNEL_DEVICE (self)))) == condition_equal);

    /* Device name checks */
    if (g_str_equal (match->parameter, "KERNEL"))
        return (string_match (mm_kernel_device_get_name (MM_KERNEL_DEVICE (self)), match->value) == condition_equal);

    /* Device sysfs path checks; we allow both a direct match and a prefix patch */
    if (g_str_equal (match->parameter, "DEVPATH")) {
        gchar    *prefix_match = NULL;
        gboolean  result = FALSE;

        /* If sysfs path invalid (e.g. path doesn't exist), no match */
        if (!self->priv->sysfs_path)
            return FALSE;

        /* If not already doing a prefix match, do an implicit one. This is so that
         * we can add properties to the usb_device owning all ports, and then apply
         * the property to all ports individually processed here. */
        if (match->value[0] && match->value[strlen (match->value) - 1] != '*')
            prefix_match = g_strdup_printf ("%s/*", match->value);

        if (string_match (self->priv->sysfs_path, match->value) == condition_equal) {
            result = TRUE;
            goto out;
        }

        if (prefix_match && string_match (self->priv->sysfs_path, prefix_match) == condition_equal) {
            result = TRUE;
            goto out;
        }

        if (g_str_has_prefix (self->priv->sysfs_path, "/sys")) {
            if (string_match (&self->priv->sysfs_path[4], match->value) == condition_equal) {
                result = TRUE;
                goto out;
            }
            if (prefix_match && string_match (&self->priv->sysfs_path[4], prefix_match) == condition_equal) {
                result = TRUE;
                goto out;
            }
        }
    out:
        g_free (prefix_match);
        return result;
    }

    /* Attributes checks */
    if (g_str_has_prefix (match->parameter, "ATTRS")) {
        gchar    *attribute;
        gchar    *contents = NULL;
        gboolean  result = FALSE;
        guint     val;

        attribute = g_strdup (&match->parameter[5]);
        g_strdelimit (attribute, "{}", ' ');
        g_strstrip (attribute);

        /* VID/PID directly from our API */
        if (g_str_equal (attribute, "idVendor"))
            result = ((mm_get_uint_from_hex_str (match->value, &val)) &&
                      ((mm_kernel_device_get_physdev_vid (MM_KERNEL_DEVICE (self)) == val) == condition_equal));
        else if (g_str_equal (attribute, "idProduct"))
            result = ((mm_get_uint_from_hex_str (match->value, &val)) &&
                      ((mm_kernel_device_get_physdev_pid (MM_KERNEL_DEVICE (self)) == val) == condition_equal));
        /* manufacturer in the physdev */
        else if (g_str_equal (attribute, "manufacturer"))
            result = ((self->priv->physdev_manufacturer && g_str_equal (self->priv->physdev_manufacturer, match->value)) == condition_equal);
        /* product in the physdev */
        else if (g_str_equal (attribute, "product"))
            result = ((self->priv->physdev_product && g_str_equal (self->priv->physdev_product, match->value)) == condition_equal);
        /* interface class/subclass/protocol/number in the interface */
        else if (g_str_equal (attribute, "bInterfaceClass"))
            result = (g_str_equal (match->value, "?*") || ((mm_get_uint_from_hex_str (match->value, &val)) &&
                                                           ((self->priv->interface_class == val) == condition_equal)));
        else if (g_str_equal (attribute, "bInterfaceSubClass"))
            result = (g_str_equal (match->value, "?*") || ((mm_get_uint_from_hex_str (match->value, &val)) &&
                                                           ((self->priv->interface_subclass == val) == condition_equal)));
        else if (g_str_equal (attribute, "bInterfaceProtocol"))
            result = (g_str_equal (match->value, "?*") || ((mm_get_uint_from_hex_str (match->value, &val)) &&
                                                           ((self->priv->interface_protocol == val) == condition_equal)));
        else if (g_str_equal (attribute, "bInterfaceNumber"))
            result = (g_str_equal (match->value, "?*") || ((mm_get_uint_from_hex_str (match->value, &val)) &&
                                                           ((self->priv->interface_number == val) == condition_equal)));
        else
            mm_warn ("Unknown attribute: %s", attribute);

        g_free (contents);
        g_free (attribute);
        return result;
    }

    /* Previously set property checks */
    if (g_str_has_prefix (match->parameter, "ENV")) {
        gchar    *property;
        gboolean  result = FALSE;

        property = g_strdup (&match->parameter[3]);
        g_strdelimit (property, "{}", ' ');
        g_strstrip (property);

        result = ((!g_strcmp0 ((const gchar *) g_object_get_data (G_OBJECT (self), property), match->value)) == condition_equal);

        g_free (property);
        return result;
    }

    mm_warn ("Unknown match condition parameter: %s", match->parameter);
    return FALSE;
}

static guint
check_rule (MMKernelDeviceGeneric *self,
            guint                  rule_i)
{
    MMUdevRule *rule;
    gboolean    apply = TRUE;

    g_assert (rule_i < self->priv->rules->len);

    rule = &g_array_index (self->priv->rules, MMUdevRule, rule_i);
    if (rule->conditions) {
        guint condition_i;

        for (condition_i = 0; condition_i < rule->conditions->len; condition_i++) {
            MMUdevRuleMatch *match;

            match = &g_array_index (rule->conditions, MMUdevRuleMatch, condition_i);
            if (!check_condition (self, match)) {
                apply = FALSE;
                break;
            }
        }
    }

    if (apply) {
        switch (rule->result.type) {
        case MM_UDEV_RULE_RESULT_TYPE_PROPERTY: {
            gchar *property_value_read = NULL;

            if (g_str_equal (rule->result.content.property.value, "$attr{bInterfaceClass}"))
                property_value_read = g_strdup_printf ("%02x", self->priv->interface_class);
            else if (g_str_equal (rule->result.content.property.value, "$attr{bInterfaceSubClass}"))
                property_value_read = g_strdup_printf ("%02x", self->priv->interface_subclass);
            else if (g_str_equal (rule->result.content.property.value, "$attr{bInterfaceProtocol}"))
                property_value_read = g_strdup_printf ("%02x", self->priv->interface_protocol);
            else if (g_str_equal (rule->result.content.property.value, "$attr{bInterfaceNumber}"))
                property_value_read = g_strdup_printf ("%02x", self->priv->interface_number);

            /* add new property */
            mm_dbg ("(%s/%s) property added: %s=%s",
                    mm_kernel_event_properties_get_subsystem (self->priv->properties),
                    mm_kernel_event_properties_get_name      (self->priv->properties),
                    rule->result.content.property.name,
                    property_value_read ? property_value_read : rule->result.content.property.value);

            if (!property_value_read)
                /* NOTE: we keep a reference to the list of rules ourselves, so it isn't
                 * an issue if we re-use the same string (i.e. without g_strdup-ing it)
                 * as a property value. */
                g_object_set_data (G_OBJECT (self),
                                   rule->result.content.property.name,
                                   rule->result.content.property.value);
            else
                g_object_set_data_full (G_OBJECT (self),
                                        rule->result.content.property.name,
                                        property_value_read,
                                        g_free);
            break;
        }

        case MM_UDEV_RULE_RESULT_TYPE_LABEL:
            /* noop */
            break;

        case MM_UDEV_RULE_RESULT_TYPE_GOTO_INDEX:
            /* Jump to a new index */
            return rule->result.content.index;

        case MM_UDEV_RULE_RESULT_TYPE_GOTO_TAG:
        case MM_UDEV_RULE_RESULT_TYPE_UNKNOWN:
            g_assert_not_reached ();
        }
    }

    /* Go to the next rule */
    return rule_i + 1;
}

static void
preload_properties (MMKernelDeviceGeneric *self)
{
    guint i;

    g_assert (self->priv->rules);
    g_assert (self->priv->rules->len > 0);

    /* Start to process rules */
    i = 0;
    while (i < self->priv->rules->len) {
        guint next_rule;

        next_rule = check_rule (self, i);
        i = next_rule;
    }
}

static void
check_preload (MMKernelDeviceGeneric *self)
{
    /* Only preload when properties and rules are set */
    if (!self->priv->properties || !self->priv->rules)
        return;

    /* Don't preload on "remove" actions, where we don't have the device any more */
    if (g_strcmp0 (mm_kernel_event_properties_get_action (self->priv->properties), "remove") == 0)
        return;

    /* Don't preload for devices in the 'virtual' subsystem */
    if (g_strcmp0 (mm_kernel_event_properties_get_subsystem (self->priv->properties), "virtual") == 0)
        return;

    mm_dbg ("(%s/%s) preloading contents and properties...",
            mm_kernel_event_properties_get_subsystem (self->priv->properties),
            mm_kernel_event_properties_get_name      (self->priv->properties));
    preload_contents (self);
    preload_properties (self);
}

static gboolean
kernel_device_has_property (MMKernelDevice *self,
                            const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), FALSE);

    return !!g_object_get_data (G_OBJECT (self), property);
}

static const gchar *
kernel_device_get_property (MMKernelDevice *self,
                            const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), NULL);

    return g_object_get_data (G_OBJECT (self), property);
}

static gboolean
kernel_device_get_property_as_boolean (MMKernelDevice *self,
                                       const gchar    *property)
{
    const gchar *value;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), FALSE);

    value = g_object_get_data (G_OBJECT (self), property);
    return (value && mm_common_get_boolean_from_string (value, NULL));
}

static gint
kernel_device_get_property_as_int (MMKernelDevice *self,
                                   const gchar    *property)
{
    const gchar *value;
    gint aux = 0;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), -1);

    value = g_object_get_data (G_OBJECT (self), property);
    return ((value && mm_get_int_from_str (value, &aux)) ? aux : 0);
}

static guint
kernel_device_get_property_as_int_hex (MMKernelDevice *self,
                                       const gchar    *property)
{
    const gchar *value;
    guint aux = 0;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_GENERIC (self), G_MAXUINT);

    value = g_object_get_data (G_OBJECT (self), property);
    return ((value && mm_get_uint_from_hex_str (value, &aux)) ? aux : 0);
}

/*****************************************************************************/

MMKernelDevice *
mm_kernel_device_generic_new_with_rules (MMKernelEventProperties  *properties,
                                         GArray                   *rules,
                                         GError                  **error)
{
    g_return_val_if_fail (MM_IS_KERNEL_EVENT_PROPERTIES (properties), NULL);

    /* Note: we allow NULL rules, e.g. for virtual devices */

    return MM_KERNEL_DEVICE (g_initable_new (MM_TYPE_KERNEL_DEVICE_GENERIC,
                                             NULL,
                                             error,
                                             "properties", properties,
                                             "rules",      rules,
                                             NULL));
}

MMKernelDevice *
mm_kernel_device_generic_new (MMKernelEventProperties  *properties,
                              GError                  **error)
{
    static GArray *rules = NULL;

    g_return_val_if_fail (MM_IS_KERNEL_EVENT_PROPERTIES (properties), NULL);

    /* We only try to load the default list of rules once */
    if (G_UNLIKELY (!rules)) {
        rules = mm_kernel_device_generic_rules_load (UDEVRULESDIR, error);
        if (!rules)
            return NULL;
    }

    return mm_kernel_device_generic_new_with_rules (properties, rules, error);
}

/*****************************************************************************/

static void
mm_kernel_device_generic_init (MMKernelDeviceGeneric *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, MM_TYPE_KERNEL_DEVICE_GENERIC, MMKernelDeviceGenericPrivate);
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
    MMKernelDeviceGeneric *self = MM_KERNEL_DEVICE_GENERIC (object);

    switch (prop_id) {
    case PROP_PROPERTIES:
        g_assert (!self->priv->properties);
        self->priv->properties = g_value_dup_object (value);
        check_preload (self);
        break;
    case PROP_RULES:
        g_assert (!self->priv->rules);
        self->priv->rules = g_value_dup_boxed (value);
        check_preload (self);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
get_property (GObject    *object,
              guint       prop_id,
              GValue     *value,
              GParamSpec *pspec)
{
    MMKernelDeviceGeneric *self = MM_KERNEL_DEVICE_GENERIC (object);

    switch (prop_id) {
    case PROP_PROPERTIES:
        g_value_set_object (value, self->priv->properties);
        break;
    case PROP_RULES:
        g_value_set_boxed (value, self->priv->rules);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static gboolean
initable_init (GInitable     *initable,
               GCancellable  *cancellable,
               GError       **error)
{
    MMKernelDeviceGeneric *self = MM_KERNEL_DEVICE_GENERIC (initable);
    const gchar *subsystem;

    subsystem = mm_kernel_device_get_subsystem (MM_KERNEL_DEVICE (self));
    if (!subsystem) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "subsystem is mandatory in kernel device");
        return FALSE;
    }

    if (!mm_kernel_device_get_name (MM_KERNEL_DEVICE (self))) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "name is mandatory in kernel device");
        return FALSE;
    }

    /* sysfs path is mandatory as output, and will only be given if the
     * specified device exists; but only if this wasn't a 'remove' event
     * and not a virtual device.
     */
    if (self->priv->properties &&
        g_strcmp0 (mm_kernel_event_properties_get_action (self->priv->properties), "remove") &&
        g_strcmp0 (mm_kernel_event_properties_get_subsystem (self->priv->properties), "virtual") &&
        !self->priv->sysfs_path) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "device %s/%s not found",
                     mm_kernel_event_properties_get_subsystem (self->priv->properties),
                     mm_kernel_event_properties_get_name      (self->priv->properties));
        return FALSE;
    }

    return TRUE;
}

static void
dispose (GObject *object)
{
    MMKernelDeviceGeneric *self = MM_KERNEL_DEVICE_GENERIC (object);

    g_clear_pointer (&self->priv->physdev_product,      g_free);
    g_clear_pointer (&self->priv->physdev_manufacturer, g_free);
    g_clear_pointer (&self->priv->physdev_sysfs_path,   g_free);
    g_clear_pointer (&self->priv->interface_sysfs_path, g_free);
    g_clear_pointer (&self->priv->sysfs_path,           g_free);
    g_clear_pointer (&self->priv->driver,               g_free);
    g_clear_pointer (&self->priv->rules,                g_array_unref);
    g_clear_object  (&self->priv->properties);

    G_OBJECT_CLASS (mm_kernel_device_generic_parent_class)->dispose (object);
}

static void
initable_iface_init (GInitableIface *iface)
{
    iface->init = initable_init;
}

static void
mm_kernel_device_generic_class_init (MMKernelDeviceGenericClass *klass)
{
    GObjectClass        *object_class        = G_OBJECT_CLASS (klass);
    MMKernelDeviceClass *kernel_device_class = MM_KERNEL_DEVICE_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMKernelDeviceGenericPrivate));

    object_class->dispose      = dispose;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    kernel_device_class->get_subsystem            = kernel_device_get_subsystem;
    kernel_device_class->get_name                 = kernel_device_get_name;
    kernel_device_class->get_driver               = kernel_device_get_driver;
    kernel_device_class->get_sysfs_path           = kernel_device_get_sysfs_path;
    kernel_device_class->get_physdev_uid          = kernel_device_get_physdev_uid;
    kernel_device_class->get_physdev_vid          = kernel_device_get_physdev_vid;
    kernel_device_class->get_physdev_pid          = kernel_device_get_physdev_pid;
    kernel_device_class->get_physdev_sysfs_path   = kernel_device_get_physdev_sysfs_path;
    kernel_device_class->get_physdev_subsystem    = kernel_device_get_physdev_subsystem;
    kernel_device_class->get_physdev_manufacturer = kernel_device_get_physdev_manufacturer;
    kernel_device_class->get_interface_class      = kernel_device_get_interface_class;
    kernel_device_class->get_interface_subclass   = kernel_device_get_interface_subclass;
    kernel_device_class->get_interface_protocol   = kernel_device_get_interface_protocol;
    kernel_device_class->get_interface_sysfs_path = kernel_device_get_interface_sysfs_path;
    kernel_device_class->cmp                      = kernel_device_cmp;
    kernel_device_class->has_property             = kernel_device_has_property;
    kernel_device_class->get_property             = kernel_device_get_property;
    kernel_device_class->get_property_as_boolean  = kernel_device_get_property_as_boolean;
    kernel_device_class->get_property_as_int      = kernel_device_get_property_as_int;
    kernel_device_class->get_property_as_int_hex  = kernel_device_get_property_as_int_hex;

    /* Device-wide properties are stored per-port in the generic backend */
    kernel_device_class->has_global_property            = kernel_device_has_property;
    kernel_device_class->get_global_property            = kernel_device_get_property;
    kernel_device_class->get_global_property_as_boolean = kernel_device_get_property_as_boolean;
    kernel_device_class->get_global_property_as_int     = kernel_device_get_property_as_int;
    kernel_device_class->get_global_property_as_int_hex = kernel_device_get_property_as_int_hex;

    properties[PROP_PROPERTIES] =
        g_param_spec_object ("properties",
                             "Properties",
                             "Generic kernel event properties",
                             MM_TYPE_KERNEL_EVENT_PROPERTIES,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_PROPERTIES, properties[PROP_PROPERTIES]);

    properties[PROP_RULES] =
        g_param_spec_boxed ("rules",
                            "Rules",
                            "List of rules to apply",
                            G_TYPE_ARRAY,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_RULES, properties[PROP_RULES]);
}
