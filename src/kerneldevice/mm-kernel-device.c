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

gint
mm_kernel_device_get_interface_class (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), -1);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_class ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_class (self) :
            -1);
}

gint
mm_kernel_device_get_interface_subclass (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), -1);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_subclass ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_subclass (self) :
            -1);
}

gint
mm_kernel_device_get_interface_protocol (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), -1);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_protocol ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_protocol (self) :
            -1);
}

const gchar *
mm_kernel_device_get_interface_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    return (MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_sysfs_path ?
            MM_KERNEL_DEVICE_GET_CLASS (self)->get_interface_sysfs_path (self) :
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
