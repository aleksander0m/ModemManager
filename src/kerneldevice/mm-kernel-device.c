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

#include <config.h>
#include <string.h>

#include "mm-log.h"
#include "mm-kernel-device.h"

G_DEFINE_ABSTRACT_TYPE (MMKernelDevice, mm_kernel_device, G_TYPE_OBJECT)

/*****************************************************************************/

const gchar *
mm_kernel_device_get_subsystem (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_subsystem ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_subsystem (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_name (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_name ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_name (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_driver (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_driver ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_driver (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_sysfs_path ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_sysfs_path (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_physdev_uid (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_uid ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_uid (self) :
            NULL);
}

guint16
mm_kernel_device_get_physdev_vid (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), 0);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_vid ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_vid (self) :
            0);
}

guint16
mm_kernel_device_get_physdev_pid (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), 0);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_pid ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_pid (self) :
            0);
}

const gchar *
mm_kernel_device_get_physdev_subsystem (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_subsystem ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_subsystem (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_physdev_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_sysfs_path ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_sysfs_path (self) :
            NULL);
}

const gchar *
mm_kernel_device_get_physdev_manufacturer (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_manufacturer ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_physdev_manufacturer (self) :
            NULL);
}

gboolean
mm_kernel_device_is_candidate (MMKernelDevice *self,
                               gboolean        manual_scan)
{
    const gchar *physdev_subsys;
    const gchar *name;
    const gchar *subsys;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), FALSE);

    name   = mm_kernel_device_get_name      (self);
    subsys = mm_kernel_device_get_subsystem (self);

    /* ignore VTs */
    if (strncmp (name, "tty", 3) == 0 && g_ascii_isdigit (name[3]))
        return FALSE;

    /* Ignore devices that aren't completely configured by udev yet.  If
     * ModemManager is started in parallel with udev, explicitly requesting
     * devices may return devices for which not all udev rules have yet been
     * applied (a bug in udev/gudev).  Since we often need those rules to match
     * the device to a specific ModemManager driver, we need to ensure that all
     * rules have been processed before handling a device.
     *
     * This udev tag applies to each port in a device. In other words, the flag
     * may be set in some ports, but not in others */
    if (!mm_kernel_device_get_property_as_boolean (self, "ID_MM_CANDIDATE"))
        return FALSE;

    /* Don't process device if no sysfs path */
    if (!mm_kernel_device_get_physdev_sysfs_path (self)) {
        /* Log about it, but filter out some common ports that we know don't have
         * anything to do with mobile broadband.
         */
        if (   strcmp (name, "console")
            && strcmp (name, "ptmx")
            && strcmp (name, "lo")
            && strcmp (name, "tty")
            && !strstr (name, "virbr"))
            mm_dbg ("(%s/%s): could not get port's parent device", subsys, name);
        return FALSE;
    }

    /* Ignore blacklisted devices. */
    if (mm_kernel_device_get_global_property_as_boolean (MM_KERNEL_DEVICE (self), "ID_MM_DEVICE_IGNORE")) {
        mm_dbg ("(%s/%s): device is blacklisted", subsys, name);
        return FALSE;
    }

    /* Is the device in the manual-only greylist? If so, return if this is an
     * automatic scan. */
    if (!manual_scan && mm_kernel_device_get_global_property_as_boolean (MM_KERNEL_DEVICE (self), "ID_MM_DEVICE_MANUAL_SCAN_ONLY")) {
        mm_dbg ("(%s/%s): device probed only in manual scan", subsys, name);
        return FALSE;
    }

    /* If the physdev is a 'platform' or 'pnp' device that's not whitelisted, ignore it */
    physdev_subsys = mm_kernel_device_get_physdev_subsystem (MM_KERNEL_DEVICE (self));
    if ((!g_strcmp0 (physdev_subsys, "platform") || !g_strcmp0 (physdev_subsys, "pnp")) &&
        (!mm_kernel_device_get_global_property_as_boolean (MM_KERNEL_DEVICE (self), "ID_MM_PLATFORM_DRIVER_PROBE"))) {
        mm_dbg ("(%s/%s): port's parent platform driver is not whitelisted", subsys, name);
        return FALSE;
    }

    return TRUE;
}

const gchar *
mm_kernel_device_get_parent_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_parent_sysfs_path ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_parent_sysfs_path (self) :
            NULL);
}

gboolean
mm_kernel_device_cmp (MMKernelDevice *a,
                      MMKernelDevice *b)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (a), FALSE);
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (b), FALSE);

    return (MM_KERNEL_DEVICE_GET_CLASS (a)->cmp ?
            MM_KERNEL_DEVICE_GET_CLASS (a)->cmp (a, b) :
            FALSE);
}

gboolean
mm_kernel_device_has_property (MMKernelDevice *self,
                               const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), FALSE);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->has_property ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->has_property (self, property) :
            FALSE);
}

const gchar *
mm_kernel_device_get_property (MMKernelDevice *self,
                               const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_property ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_property (self, property) :
            NULL);
}

gboolean
mm_kernel_device_get_property_as_boolean (MMKernelDevice *self,
                                          const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), FALSE);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_boolean ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_boolean (self, property) :
            FALSE);
}

gint
mm_kernel_device_get_property_as_int (MMKernelDevice *self,
                                      const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), -1);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_int ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_int (self, property) :
            -1);
}

guint
mm_kernel_device_get_property_as_int_hex (MMKernelDevice *self,
                                          const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), 0);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_int_hex ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_property_as_int_hex (self, property) :
            0);
}

gboolean
mm_kernel_device_has_global_property (MMKernelDevice *self,
                                      const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), FALSE);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->has_global_property ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->has_global_property (self, property) :
            FALSE);
}

const gchar *
mm_kernel_device_get_global_property (MMKernelDevice *self,
                                      const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property (self, property) :
            NULL);
}

gboolean
mm_kernel_device_get_global_property_as_boolean (MMKernelDevice *self,
                                                 const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), FALSE);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_boolean ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_boolean (self, property) :
            FALSE);
}

gint
mm_kernel_device_get_global_property_as_int (MMKernelDevice *self,
                                             const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), -1);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_int ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_int (self, property) :
            -1);
}

guint
mm_kernel_device_get_global_property_as_int_hex (MMKernelDevice *self,
                                                 const gchar    *property)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), 0);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_int_hex ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_global_property_as_int_hex (self, property) :
            0);
}

/*****************************************************************************/

static void
mm_kernel_device_init (MMKernelDevice *self)
{
}

static void
mm_kernel_device_class_init (MMKernelDeviceClass *klass)
{
}
