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
 * Copyright (C) 2017 Aleksander Morgado <aleksander@aleksander.es>
 */

#include <config.h>
#include <string.h>

#include "mm-daemon-enums-types.h"
#include "mm-filter.h"
#include "mm-log.h"

G_DEFINE_TYPE (MMFilter, mm_filter, G_TYPE_OBJECT)

enum {
    PROP_0,
    PROP_ENABLED_RULES,
    LAST_PROP
};

struct _MMFilterPrivate {
    MMFilterRule enabled_rules;
};

/*****************************************************************************/

gboolean
mm_filter_port (MMFilter        *self,
                MMKernelDevice  *port,
                gboolean         manual_scan)
{
    const gchar *subsystem;
    const gchar *name;

    subsystem = mm_kernel_device_get_subsystem (port);
    name      = mm_kernel_device_get_name      (port);

    /* If this is a virtual device, don't allow it */
    if ((self->priv->enabled_rules & MM_FILTER_RULE_VIRTUAL) &&
        (!mm_kernel_device_get_physdev_sysfs_path (port))) {
        mm_dbg ("[filter] (%s/%s) port filtered: virtual device", subsystem, name);
        return FALSE;
    }

    /* If this is a net device, we always allow it */
    if ((self->priv->enabled_rules & MM_FILTER_RULE_NET) &&
        (g_strcmp0 (subsystem, "net") == 0)) {
        mm_dbg ("[filter] (%s/%s) port allowed: net device", subsystem, name);
        return TRUE;
    }

    /* If this is a cdc-wdm device, we always allow it */
    if ((self->priv->enabled_rules & MM_FILTER_RULE_CDC_WDM) &&
        (g_strcmp0 (subsystem, "usb") == 0 || g_strcmp0 (subsystem, "usbmisc") == 0) &&
        (name && g_str_has_prefix (name, "cdc-wdm"))) {
        mm_dbg ("[filter] (%s/%s) port allowed: cdc-wdm device", subsystem, name);
        return TRUE;
    }

    /* If this is a tty device, we may allow it */
    if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY) &&
        (g_strcmp0 (subsystem, "tty") == 0)) {
        const gchar *physdev_subsystem;

        /* Filter out virtual consoles (e.g. tty0, tty1, tty2...) */
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_VIRTUAL_CONSOLE) &&
            (name && strncmp (name, "tty", 3) == 0) &&
            (g_ascii_isdigit (name[3]))) {
            mm_dbg ("[filter] (%s/%s) port filtered: virtual console", subsystem, name);
            return FALSE;
        }

        /* Ignore blacklisted tty devices. */
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_BLACKLIST) &&
            (mm_kernel_device_get_global_property_as_boolean (port, "ID_MM_DEVICE_IGNORE"))) {
            mm_dbg ("[filter] (%s/%s): port filtered: device is blacklisted", subsystem, name);
            return FALSE;
        }

        /* Is the device in the manual-only greylist? If so, return if this is an
         * automatic scan. */
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_MANUAL_SCAN_ONLY) &&
            (!manual_scan && mm_kernel_device_get_global_property_as_boolean (port, "ID_MM_DEVICE_MANUAL_SCAN_ONLY"))) {
            mm_dbg ("[filter] (%s/%s): port filtered: device probed only in manual scan", subsystem, name);
            return FALSE;
        }

        /* If the physdev is a 'platform' or 'pnp' device that's not whitelisted, ignore it */
        physdev_subsystem = mm_kernel_device_get_physdev_subsystem (port);
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_PLATFORM_DRIVER) &&
            (!g_strcmp0 (physdev_subsystem, "platform") || !g_strcmp0 (physdev_subsystem, "pnp")) &&
            (!mm_kernel_device_get_global_property_as_boolean (port, "ID_MM_PLATFORM_DRIVER_PROBE"))) {
            mm_dbg ("[filter] (%s/%s): port filtered: port's parent platform driver is not whitelisted", subsystem, name);
            return FALSE;
        }

        /* Otherwise, TTY probed */
        return TRUE;
    }

    /* Otherwise forbidden */
    mm_dbg ("[filter] (%s/%s) port filtered: forbidden port type", subsystem, name);
    return FALSE;
}

/*****************************************************************************/

MMFilter *
mm_filter_new (MMFilterRule enabled_rules)
{
    MMFilter *self;

    self = g_object_new (MM_TYPE_FILTER,
                         MM_FILTER_ENABLED_RULES, enabled_rules,
                         NULL);

#define RULE_ENABLED_STR(flag) ((self->priv->enabled_rules & flag) ? "yes" : "no")

    mm_dbg ("[filter] created");
    mm_dbg ("[filter]   virtual devices forbidden:  %s", RULE_ENABLED_STR (MM_FILTER_RULE_VIRTUAL));
    mm_dbg ("[filter]   net devices allowed:        %s", RULE_ENABLED_STR (MM_FILTER_RULE_NET));
    mm_dbg ("[filter]   cdc-wdm devices allowed:    %s", RULE_ENABLED_STR (MM_FILTER_RULE_CDC_WDM));
    mm_dbg ("[filter]   tty devices allowed:        %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY));
    if (self->priv->enabled_rules & MM_FILTER_RULE_TTY) {
        mm_dbg ("[filter]       virtual consoles filtered: %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_VIRTUAL_CONSOLE));
        mm_dbg ("[filter]       blacklist applied:         %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_BLACKLIST));
        mm_dbg ("[filter]       manual scan only applied:  %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_MANUAL_SCAN_ONLY));
        mm_dbg ("[filter]       platform driver check:     %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_PLATFORM_DRIVER));
    }

#undef RULE_ENABLED_STR

    return self;
}

static void
set_property (GObject      *object,
              guint         prop_id,
              const GValue *value,
              GParamSpec   *pspec)
{
    MMFilter *self = MM_FILTER (object);

    switch (prop_id) {
    case PROP_ENABLED_RULES:
        self->priv->enabled_rules = g_value_get_flags (value);
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
    MMFilter *self = MM_FILTER (object);

    switch (prop_id) {
    case PROP_ENABLED_RULES:
        g_value_set_flags (value, self->priv->enabled_rules);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
mm_filter_init (MMFilter *self)
{
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, MM_TYPE_FILTER, MMFilterPrivate);
}

static void
mm_filter_class_init (MMFilterClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMFilterPrivate));

    /* Virtual methods */
    object_class->set_property = set_property;
    object_class->get_property = get_property;

    g_object_class_install_property (
        object_class, PROP_ENABLED_RULES,
        g_param_spec_flags (MM_FILTER_ENABLED_RULES,
                            "Enabled rules",
                            "Mask of rules enabled in the filter",
                            MM_TYPE_FILTER_RULE,
                            MM_FILTER_RULE_NONE,
                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
