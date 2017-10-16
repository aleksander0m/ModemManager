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

#include <string.h>

#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-kernel-device-udev.h"
#include "mm-log.h"

static void initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_EXTENDED (MMKernelDeviceUdev, mm_kernel_device_udev,  MM_TYPE_KERNEL_DEVICE, 0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, initable_iface_init))

enum {
    PROP_0,
    PROP_UDEV_DEVICE,
    PROP_PROPERTIES,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

struct _MMKernelDeviceUdevPrivate {
    GUdevDevice *device;
    GUdevDevice *parent;
    GUdevDevice *physdev;
    guint16      vendor;
    guint16      product;

    MMKernelEventProperties *properties;
};

/*****************************************************************************/

static gboolean
get_device_ids (GUdevDevice *device,
                guint16     *vendor,
                guint16     *product)
{
    GUdevDevice *parent = NULL;
    const gchar *vid = NULL, *pid = NULL, *parent_subsys;
    gboolean success = FALSE;
    char *pci_vid = NULL, *pci_pid = NULL;

    g_assert (vendor != NULL && product != NULL);

    parent = g_udev_device_get_parent (device);
    if (parent) {
        parent_subsys = g_udev_device_get_subsystem (parent);
        if (parent_subsys) {
            if (g_str_equal (parent_subsys, "bluetooth")) {
                /* Bluetooth devices report the VID/PID of the BT adapter here,
                 * which isn't really what we want.  Just return null IDs instead.
                 */
                success = TRUE;
                goto out;
            } else if (g_str_equal (parent_subsys, "pcmcia")) {
                /* For PCMCIA devices we need to grab the PCMCIA subsystem's
                 * manfid and cardid, since any IDs on the tty device itself
                 * may be from PCMCIA controller or something else.
                 */
                vid = g_udev_device_get_sysfs_attr (parent, "manf_id");
                pid = g_udev_device_get_sysfs_attr (parent, "card_id");
                if (!vid || !pid)
                    goto out;
            } else if (g_str_equal (parent_subsys, "platform")) {
                /* Platform devices don't usually have a VID/PID */
                success = TRUE;
                goto out;
            } else if (g_str_has_prefix (parent_subsys, "usb") &&
                       (!g_strcmp0 (g_udev_device_get_driver (parent), "qmi_wwan") ||
                        !g_strcmp0 (g_udev_device_get_driver (parent), "cdc_mbim"))) {
                /* Need to look for vendor/product in the parent of the QMI/MBIM device */
                GUdevDevice *qmi_parent;

                qmi_parent = g_udev_device_get_parent (parent);
                if (qmi_parent) {
                    vid = g_udev_device_get_property (qmi_parent, "ID_VENDOR_ID");
                    pid = g_udev_device_get_property (qmi_parent, "ID_MODEL_ID");
                    g_object_unref (qmi_parent);
                }
            } else if (g_str_equal (parent_subsys, "pci")) {
                const char *pci_id;

                /* We can't always rely on the model + vendor showing up on
                 * the PCI device's child, so look at the PCI parent.  PCI_ID
                 * has the format "1931:000C".
                 */
                pci_id = g_udev_device_get_property (parent, "PCI_ID");
                if (pci_id && strlen (pci_id) == 9 && pci_id[4] == ':') {
                    vid = pci_vid = g_strdup (pci_id);
                    pci_vid[4] = '\0';
                    pid = pci_pid = g_strdup (pci_id + 5);
                }
            }
        }
    }

    if (!vid)
        vid = g_udev_device_get_property (device, "ID_VENDOR_ID");
    if (!vid)
        goto out;

    if (strncmp (vid, "0x", 2) == 0)
        vid += 2;
    if (strlen (vid) != 4)
        goto out;

    if (!pid)
        pid = g_udev_device_get_property (device, "ID_MODEL_ID");
    if (!pid)
        goto out;

    if (strncmp (pid, "0x", 2) == 0)
        pid += 2;
    if (strlen (pid) != 4)
        goto out;

    *vendor = (guint16) (mm_utils_hex2byte (vid + 2) & 0xFF);
    *vendor |= (guint16) ((mm_utils_hex2byte (vid) & 0xFF) << 8);

    *product = (guint16) (mm_utils_hex2byte (pid + 2) & 0xFF);
    *product |= (guint16) ((mm_utils_hex2byte (pid) & 0xFF) << 8);

    success = TRUE;

out:
    if (parent)
        g_object_unref (parent);
    g_free (pci_vid);
    g_free (pci_pid);
    return success;
}

static void
ensure_device_ids (MMKernelDeviceUdev *self)
{
    if (self->priv->vendor || self->priv->product)
        return;

    if (!self->priv->device)
        return;

    if (!get_device_ids (self->priv->device, &self->priv->vendor, &self->priv->product))
        mm_dbg ("(%s/%s) could not get vendor/product id",
                g_udev_device_get_subsystem (self->priv->device),
                g_udev_device_get_name      (self->priv->device));
}

/*****************************************************************************/

static GUdevDevice *
find_physical_gudevdevice (GUdevDevice *child)
{
    GUdevDevice *iter, *old = NULL;
    GUdevDevice *physdev = NULL;
    const char *subsys, *type, *name;
    guint32 i = 0;
    gboolean is_usb = FALSE, is_pcmcia = FALSE;

    g_return_val_if_fail (child != NULL, NULL);

    /* Bluetooth rfcomm devices are "virtual" and don't necessarily have
     * parents at all.
     */
    name = g_udev_device_get_name (child);
    if (name && strncmp (name, "rfcomm", 6) == 0)
        return g_object_ref (child);

    iter = g_object_ref (child);
    while (iter && i++ < 8) {
        subsys = g_udev_device_get_subsystem (iter);
        if (subsys) {
            if (is_usb || g_str_has_prefix (subsys, "usb")) {
                is_usb = TRUE;
                type = g_udev_device_get_devtype (iter);
                if (type && !strcmp (type, "usb_device")) {
                    physdev = iter;
                    break;
                }
            } else if (is_pcmcia || !strcmp (subsys, "pcmcia")) {
                GUdevDevice *pcmcia_parent;
                const char *tmp_subsys;

                is_pcmcia = TRUE;

                /* If the parent of this PCMCIA device is no longer part of
                 * the PCMCIA subsystem, we want to stop since we're looking
                 * for the base PCMCIA device, not the PCMCIA controller which
                 * is usually PCI or some other bus type.
                 */
                pcmcia_parent = g_udev_device_get_parent (iter);
                if (pcmcia_parent) {
                    tmp_subsys = g_udev_device_get_subsystem (pcmcia_parent);
                    if (tmp_subsys && strcmp (tmp_subsys, "pcmcia"))
                        physdev = iter;
                    g_object_unref (pcmcia_parent);
                    if (physdev)
                        break;
                }
            } else if (!strcmp (subsys, "platform") ||
                       !strcmp (subsys, "pci") ||
                       !strcmp (subsys, "pnp") ||
                       !strcmp (subsys, "sdio")) {
                /* Take the first parent as the physical device */
                physdev = iter;
                break;
            }
        }

        old = iter;
        iter = g_udev_device_get_parent (old);
        g_object_unref (old);
    }

    return physdev;
}

static void
ensure_physdev (MMKernelDeviceUdev *self)
{
    if (self->priv->physdev)
        return;
    if (self->priv->device)
        self->priv->physdev = find_physical_gudevdevice (self->priv->device);
}

/*****************************************************************************/

static void
ensure_parent (MMKernelDeviceUdev *self)
{
    if (self->priv->parent)
        return;
    if (self->priv->device)
        self->priv->parent = g_udev_device_get_parent (self->priv->device);
}

/*****************************************************************************/

static const gchar *
kernel_device_get_subsystem (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (self->priv->device)
        return g_udev_device_get_subsystem (self->priv->device);

    g_assert (self->priv->properties);
    return mm_kernel_event_properties_get_subsystem (self->priv->properties);
}

static const gchar *
kernel_device_get_name (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (self->priv->device)
        return g_udev_device_get_name (self->priv->device);

    g_assert (self->priv->properties);
    return mm_kernel_event_properties_get_name (self->priv->properties);
}

static const gchar *
kernel_device_get_driver (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;
    const gchar *driver, *subsys, *name;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return NULL;

    driver = g_udev_device_get_driver (self->priv->device);
    if (!driver) {
        GUdevDevice *parent;

        parent = g_udev_device_get_parent (self->priv->device);
        if (parent)
            driver = g_udev_device_get_driver (parent);

        /* Check for bluetooth; it's driver is a bunch of levels up so we
         * just check for the subsystem of the parent being bluetooth.
         */
        if (!driver && parent) {
            subsys = g_udev_device_get_subsystem (parent);
            if (subsys && !strcmp (subsys, "bluetooth"))
                driver = "bluetooth";
        }

        if (parent)
            g_object_unref (parent);
    }

    /* Newer kernels don't set up the rfcomm port parent in sysfs,
     * so we must infer it from the device name.
     */
    name = g_udev_device_get_name (self->priv->device);
    if (!driver && strncmp (name, "rfcomm", 6) == 0)
        driver = "bluetooth";

    /* Note: may return NULL! */
    return driver;
}

static const gchar *
kernel_device_get_sysfs_path (MMKernelDevice *self)
{
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE (self), NULL);

    if (!MM_KERNEL_DEVICE_UDEV (self)->priv->device)
        return NULL;

    return g_udev_device_get_sysfs_path (MM_KERNEL_DEVICE_UDEV (self)->priv->device);
}

static const gchar *
kernel_device_get_physdev_uid (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;
    const gchar *uid = NULL;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    /* Prefer the one coming in the properties, if any */
    if (self->priv->properties) {
        if ((uid = mm_kernel_event_properties_get_uid (self->priv->properties)) != NULL)
            return uid;
    }

    /* Try to load from properties set on the physical device */
    if ((uid = mm_kernel_device_get_global_property (MM_KERNEL_DEVICE (self), "ID_MM_PHYSDEV_UID")) != NULL)
        return uid;

    /* Use physical device sysfs path, if any */
    if (self->priv->physdev && (uid = g_udev_device_get_sysfs_path (self->priv->physdev)) != NULL)
        return uid;

    /* If there is no physical device sysfs path, use the device sysfs itself */
    g_assert (self->priv->device);
    return g_udev_device_get_sysfs_path (self->priv->device);
}

static guint16
kernel_device_get_physdev_vid (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), 0);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_device_ids (self);
    return self->priv->vendor;
}

static guint16
kernel_device_get_physdev_pid (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), 0);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_device_ids (self);
    return self->priv->product;
}

static const gchar *
kernel_device_get_physdev_sysfs_path (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_physdev (self);
    if (!self->priv->physdev)
        return NULL;

    return g_udev_device_get_sysfs_path (self->priv->physdev);
}

static const gchar *
kernel_device_get_physdev_subsystem (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_physdev (self);
    if (!self->priv->physdev)
        return NULL;

    return g_udev_device_get_subsystem (self->priv->physdev);
}

static const gchar *
kernel_device_get_physdev_manufacturer (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_physdev (self);
    if (!self->priv->physdev)
        return NULL;

    return g_udev_device_get_sysfs_attr (self->priv->physdev, "manufacturer");
}

static gint
kernel_device_get_interface_class (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), -1);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_parent (self);
    return (self->priv->parent ? g_udev_device_get_sysfs_attr_as_int (self->priv->parent, "bInterfaceClass") : -1);
}

static gint
kernel_device_get_interface_subclass (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), -1);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_parent (self);
    return (self->priv->parent ? g_udev_device_get_sysfs_attr_as_int (self->priv->parent, "bInterfaceSubClass") : -1);
}

static gint
kernel_device_get_interface_protocol (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), -1);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_parent (self);
    return (self->priv->parent ? g_udev_device_get_sysfs_attr_as_int (self->priv->parent, "bInterfaceProtocol") : -1);
}

static const gchar *
kernel_device_get_interface_sysfs_path (MMKernelDevice *_self)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);
    ensure_parent (self);
    return (self->priv->parent ? g_udev_device_get_sysfs_path (self->priv->parent) : NULL);
}

static gboolean
kernel_device_cmp (MMKernelDevice *_a,
                   MMKernelDevice *_b)
{
    MMKernelDeviceUdev *a;
    MMKernelDeviceUdev *b;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_a), FALSE);
    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_b), FALSE);

    a = MM_KERNEL_DEVICE_UDEV (_a);
    b = MM_KERNEL_DEVICE_UDEV (_b);

    if (a->priv->device && b->priv->device) {
        if (g_udev_device_has_property (a->priv->device, "DEVPATH_OLD") &&
            g_str_has_suffix (g_udev_device_get_sysfs_path (b->priv->device),
                              g_udev_device_get_property   (a->priv->device, "DEVPATH_OLD")))
            return TRUE;

        if (g_udev_device_has_property (b->priv->device, "DEVPATH_OLD") &&
            g_str_has_suffix (g_udev_device_get_sysfs_path (a->priv->device),
                              g_udev_device_get_property   (b->priv->device, "DEVPATH_OLD")))
            return TRUE;

        return !g_strcmp0 (g_udev_device_get_sysfs_path (a->priv->device), g_udev_device_get_sysfs_path (b->priv->device));
    }

    return (!g_strcmp0 (mm_kernel_device_get_subsystem (_a), mm_kernel_device_get_subsystem (_b)) &&
            !g_strcmp0 (mm_kernel_device_get_name      (_a), mm_kernel_device_get_name      (_b)));
}

static gboolean
kernel_device_has_property (MMKernelDevice *_self,
                            const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), FALSE);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return FALSE;

    return g_udev_device_has_property (self->priv->device, property);
}

static const gchar *
kernel_device_get_property (MMKernelDevice *_self,
                            const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return NULL;

    return g_udev_device_get_property (self->priv->device, property);
}

static gboolean
kernel_device_get_property_as_boolean (MMKernelDevice *_self,
                                       const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), FALSE);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return FALSE;

    return g_udev_device_get_property_as_boolean (self->priv->device, property);
}

static gint
kernel_device_get_property_as_int (MMKernelDevice *_self,
                                   const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), -1);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return -1;

    return g_udev_device_get_property_as_int (self->priv->device, property);
}

static guint
kernel_device_get_property_as_int_hex (MMKernelDevice *_self,
                                       const gchar    *property)
{
    MMKernelDeviceUdev *self;
    const gchar        *s;
    guint               out = 0;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), G_MAXUINT);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    if (!self->priv->device)
        return G_MAXUINT;

    s = g_udev_device_get_property (self->priv->device, property);
    return ((s && mm_get_uint_from_hex_str (s, &out)) ? out : 0);
}

static gboolean
kernel_device_has_global_property (MMKernelDevice *_self,
                                   const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), FALSE);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    ensure_physdev (self);
    if (self->priv->physdev && g_udev_device_has_property (self->priv->physdev, property))
        return TRUE;

    return kernel_device_has_property (_self, property);
}

static const gchar *
kernel_device_get_global_property (MMKernelDevice *_self,
                                   const gchar    *property)
{
    MMKernelDeviceUdev *self;
    const gchar        *str;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), NULL);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    ensure_physdev (self);
    if (self->priv->physdev &&
        g_udev_device_has_property (self->priv->physdev, property) &&
        (str = g_udev_device_get_property (self->priv->physdev, property)) != NULL)
        return str;

    return kernel_device_get_property (_self, property);
}

static gboolean
kernel_device_get_global_property_as_boolean (MMKernelDevice *_self,
                                              const gchar    *property)
{
    MMKernelDeviceUdev *self;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), FALSE);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    ensure_physdev (self);
    if (self->priv->physdev &&
        g_udev_device_has_property (self->priv->physdev, property) &&
        g_udev_device_get_property (self->priv->physdev, property))
        return TRUE;

    return kernel_device_get_property_as_boolean (_self, property);
}

static gint
kernel_device_get_global_property_as_int (MMKernelDevice *_self,
                                          const gchar    *property)
{
    MMKernelDeviceUdev *self;
    gint                value;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), -1);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    ensure_physdev (self);
    if (self->priv->physdev &&
        g_udev_device_has_property (self->priv->physdev, property) &&
        (value = g_udev_device_get_property_as_int (self->priv->physdev, property)) >= 0)
        return value;

    return kernel_device_get_property_as_int (_self, property);
}

static guint
kernel_device_get_global_property_as_int_hex (MMKernelDevice *_self,
                                              const gchar    *property)
{
    MMKernelDeviceUdev *self;
    const gchar        *s;
    guint               out = 0;

    g_return_val_if_fail (MM_IS_KERNEL_DEVICE_UDEV (_self), G_MAXUINT);

    self = MM_KERNEL_DEVICE_UDEV (_self);

    ensure_physdev (self);
    if (self->priv->physdev &&
        g_udev_device_has_property (self->priv->physdev, property) &&
        (s = g_udev_device_get_property (self->priv->physdev, property)) != NULL)
        return ((s && mm_get_uint_from_hex_str (s, &out)) ? out : 0);

    return kernel_device_get_property_as_int_hex (_self, property);
}

/*****************************************************************************/

MMKernelDevice *
mm_kernel_device_udev_new (GUdevDevice *udev_device)
{
    GError *error = NULL;
    MMKernelDevice *self;

    g_return_val_if_fail (G_UDEV_IS_DEVICE (udev_device), NULL);

    self = MM_KERNEL_DEVICE (g_initable_new (MM_TYPE_KERNEL_DEVICE_UDEV,
                                             NULL,
                                             &error,
                                             "udev-device", udev_device,
                                             NULL));
    g_assert_no_error (error);
    return self;
}

/*****************************************************************************/

MMKernelDevice *
mm_kernel_device_udev_new_from_properties (MMKernelEventProperties  *properties,
                                           GError                  **error)
{
    return MM_KERNEL_DEVICE (g_initable_new (MM_TYPE_KERNEL_DEVICE_UDEV,
                                             NULL,
                                             error,
                                             "properties", properties,
                                             NULL));
}

/*****************************************************************************/

static void
mm_kernel_device_udev_init (MMKernelDeviceUdev *self)
{
    /* Initialize private data */
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, MM_TYPE_KERNEL_DEVICE_UDEV, MMKernelDeviceUdevPrivate);
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
    MMKernelDeviceUdev *self = MM_KERNEL_DEVICE_UDEV (object);

    switch (prop_id) {
    case PROP_UDEV_DEVICE:
        g_assert (!self->priv->device);
        self->priv->device = g_value_dup_object (value);
        break;
    case PROP_PROPERTIES:
        g_assert (!self->priv->properties);
        self->priv->properties = g_value_dup_object (value);
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
    MMKernelDeviceUdev *self = MM_KERNEL_DEVICE_UDEV (object);

    switch (prop_id) {
    case PROP_UDEV_DEVICE:
        g_value_set_object (value, self->priv->device);
        break;
    case PROP_PROPERTIES:
        g_value_set_object (value, self->priv->properties);
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
    MMKernelDeviceUdev *self = MM_KERNEL_DEVICE_UDEV (initable);
    const gchar *subsystem;
    const gchar *name;

    /* When created from a GUdevDevice, we're done */
    if (self->priv->device)
        return TRUE;

    /* Otherwise, we do need properties with subsystem and name */
    if (!self->priv->properties) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "missing properties in kernel device");
        return FALSE;
    }

    subsystem = mm_kernel_event_properties_get_subsystem (self->priv->properties);
    if (!subsystem) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "subsystem is mandatory in kernel device");
        return FALSE;
    }

    name = mm_kernel_event_properties_get_name (self->priv->properties);
    if (!mm_kernel_device_get_name (MM_KERNEL_DEVICE (self))) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "name is mandatory in kernel device");
        return FALSE;
    }

    /* On remove events, we don't look for the GUdevDevice */
    if (g_strcmp0 (mm_kernel_event_properties_get_action (self->priv->properties), "remove")) {
        GUdevClient *client;
        GUdevDevice *device;

        client = g_udev_client_new (NULL);
        device = g_udev_client_query_by_subsystem_and_name (client, subsystem, name);
        if (!device) {
            g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                         "device %s/%s not found",
                         subsystem,
                         name);
            g_object_unref (client);
            return FALSE;
        }

        /* Store device */
        self->priv->device = device;
        g_object_unref (client);
    }

    return TRUE;
}

static void
dispose (GObject *object)
{
    MMKernelDeviceUdev *self = MM_KERNEL_DEVICE_UDEV (object);

    g_clear_object (&self->priv->physdev);
    g_clear_object (&self->priv->parent);
    g_clear_object (&self->priv->device);
    g_clear_object (&self->priv->properties);

    G_OBJECT_CLASS (mm_kernel_device_udev_parent_class)->dispose (object);
}

static void
initable_iface_init (GInitableIface *iface)
{
    iface->init = initable_init;
}

static void
mm_kernel_device_udev_class_init (MMKernelDeviceUdevClass *klass)
{
    GObjectClass        *object_class        = G_OBJECT_CLASS (klass);
    MMKernelDeviceClass *kernel_device_class = MM_KERNEL_DEVICE_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMKernelDeviceUdevPrivate));

    object_class->dispose      = dispose;
    object_class->get_property = get_property;
    object_class->set_property = set_property;

    kernel_device_class->get_subsystem                  = kernel_device_get_subsystem;
    kernel_device_class->get_name                       = kernel_device_get_name;
    kernel_device_class->get_driver                     = kernel_device_get_driver;
    kernel_device_class->get_sysfs_path                 = kernel_device_get_sysfs_path;
    kernel_device_class->get_physdev_uid                = kernel_device_get_physdev_uid;
    kernel_device_class->get_physdev_vid                = kernel_device_get_physdev_vid;
    kernel_device_class->get_physdev_pid                = kernel_device_get_physdev_pid;
    kernel_device_class->get_physdev_sysfs_path         = kernel_device_get_physdev_sysfs_path;
    kernel_device_class->get_physdev_subsystem          = kernel_device_get_physdev_subsystem;
    kernel_device_class->get_physdev_manufacturer       = kernel_device_get_physdev_manufacturer;
    kernel_device_class->get_interface_class            = kernel_device_get_interface_class;
    kernel_device_class->get_interface_subclass         = kernel_device_get_interface_subclass;
    kernel_device_class->get_interface_protocol         = kernel_device_get_interface_protocol;
    kernel_device_class->get_interface_sysfs_path       = kernel_device_get_interface_sysfs_path;
    kernel_device_class->cmp                            = kernel_device_cmp;
    kernel_device_class->has_property                   = kernel_device_has_property;
    kernel_device_class->get_property                   = kernel_device_get_property;
    kernel_device_class->get_property_as_boolean        = kernel_device_get_property_as_boolean;
    kernel_device_class->get_property_as_int            = kernel_device_get_property_as_int;
    kernel_device_class->get_property_as_int_hex        = kernel_device_get_property_as_int_hex;
    kernel_device_class->has_global_property            = kernel_device_has_global_property;
    kernel_device_class->get_global_property            = kernel_device_get_global_property;
    kernel_device_class->get_global_property_as_boolean = kernel_device_get_global_property_as_boolean;
    kernel_device_class->get_global_property_as_int     = kernel_device_get_global_property_as_int;
    kernel_device_class->get_global_property_as_int_hex = kernel_device_get_global_property_as_int_hex;

    properties[PROP_UDEV_DEVICE] =
        g_param_spec_object ("udev-device",
                             "udev device",
                             "Device object as reported by GUdev",
                             G_UDEV_TYPE_DEVICE,
                             G_PARAM_READWRITE);
    g_object_class_install_property (object_class, PROP_UDEV_DEVICE, properties[PROP_UDEV_DEVICE]);

    properties[PROP_PROPERTIES] =
        g_param_spec_object ("properties",
                             "Properties",
                             "Generic kernel event properties",
                             MM_TYPE_KERNEL_EVENT_PROPERTIES,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_PROPERTIES, properties[PROP_PROPERTIES]);
}
