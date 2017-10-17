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

#define FILTER_PORT_MAYBE_FORBIDDEN "maybe-forbidden"

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

    /* If the device is explicitly whitelisted, we process every port. Also
     * allow specifying this flag per-port instead of for the full device, e.g.
     * for platform tty ports where there's only one port anyway. */
    if ((self->priv->enabled_rules & MM_FILTER_RULE_EXPLICIT_WHITELIST) &&
        (mm_kernel_device_get_global_property_as_boolean (port, "ID_MM_DEVICE_PROCESS") ||
         mm_kernel_device_get_property_as_boolean (port, "ID_MM_DEVICE_PROCESS"))) {
        mm_dbg ("[filter] (%s/%s) port allowed: device is whitelisted", subsystem, name);
        return TRUE;
    }

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
        const gchar *driver;

        /* Blacklist rules first */

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

        /* Mixed blacklist/whitelist rules */

        /* If the physdev is a 'platform' or 'pnp' device that's not whitelisted, ignore it */
        physdev_subsystem = mm_kernel_device_get_physdev_subsystem (port);
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_PLATFORM_DRIVER) &&
            (!g_strcmp0 (physdev_subsystem, "platform") || !g_strcmp0 (physdev_subsystem, "pnp"))) {
            if (!mm_kernel_device_get_global_property_as_boolean (port, "ID_MM_PLATFORM_DRIVER_PROBE")) {
                mm_dbg ("[filter] (%s/%s): port filtered: port's parent platform driver is not whitelisted", subsystem, name);
                return FALSE;
            }
            mm_dbg ("[filter] (%s/%s): port allowed: port's parent platform driver is whitelisted", subsystem, name);
            return TRUE;
        }

        /* Default allowed? */
        if (self->priv->enabled_rules & MM_FILTER_RULE_TTY_DEFAULT_ALLOWED) {
            mm_dbg ("[filter] (%s/%s) port allowed", subsystem, name);
            return TRUE;
        }

        /* Whitelist rules last */

        /* If the TTY kernel driver is one expected modem kernel driver, allow it */
        driver = mm_kernel_device_get_driver (port);
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_DRIVER) &&
            (!g_strcmp0 (driver, "option") ||
             !g_strcmp0 (driver, "qcserial") ||
             !g_strcmp0 (driver, "sierra"))) {
            mm_dbg ("[filter] (%s/%s): port allowed: modem-specific kernel driver detected", subsystem, name);
            return TRUE;
        }

        /* If the TTY kernel driver is cdc-acm and the interface is class=2/subclass=2/protocol=1, allow it */
        if ((self->priv->enabled_rules & MM_FILTER_RULE_TTY_ACM_INTERFACE) &&
            (!g_strcmp0 (driver, "cdc_acm")) &&
            (mm_kernel_device_get_interface_class (port) == 2) &&
            (mm_kernel_device_get_interface_subclass (port) == 2) &&
            (mm_kernel_device_get_interface_protocol (port) == 1)) {
            mm_dbg ("[filter] (%s/%s): port allowed: cdc-acm interface reported AT-capable", subsystem, name);
            return TRUE;
        }

        /* Default forbidden? flag the port as maybe-forbidden, and go on */
        if (self->priv->enabled_rules & MM_FILTER_RULE_TTY_DEFAULT_FORBIDDEN) {
            g_object_set_data (G_OBJECT (port), FILTER_PORT_MAYBE_FORBIDDEN, GUINT_TO_POINTER (TRUE));
            return TRUE;
        }

        g_assert_not_reached ();
    }

    /* Otherwise forbidden */
    mm_dbg ("[filter] (%s/%s) port filtered: forbidden port type", subsystem, name);
    return FALSE;
}

/*****************************************************************************/

gboolean
mm_filter_device_and_port (MMFilter       *self,
                           MMDevice       *device,
                           MMKernelDevice *port)
{
    const gchar *subsystem;
    const gchar *name;

    /* If it wasn't flagged as maybe forbidden, there's nothing to do */
    if (!GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (port), FILTER_PORT_MAYBE_FORBIDDEN)))
        return TRUE;

    subsystem = mm_kernel_device_get_subsystem (port);
    name      = mm_kernel_device_get_name      (port);

    /* Check whether this device holds a NET port in addition to this TTY */
    if (self->priv->enabled_rules & MM_FILTER_RULE_TTY_WITH_NET) {
        GList *l;

        for (l = mm_device_peek_port_probe_list (device); l; l = g_list_next (l)) {
            if (!g_strcmp0 (mm_port_probe_get_port_subsys (MM_PORT_PROBE (l->data)), "net")) {
                mm_dbg ("[filter] (%s/%s): port allowed: device also exports a net interface (%s)",
                        subsystem, name, mm_port_probe_get_port_name (MM_PORT_PROBE (l->data)));
                return TRUE;
            }
        }
    }

    mm_dbg ("[filter] (%s/%s) port filtered: forbidden", subsystem, name);
    return FALSE;
}

/*****************************************************************************/
/* Use filter rule names as environment variables to control them on startup:
 *  - MM_FILTER_RULE_XXX=1 to explicitly enable the rule.
 *  - MM_FILTER_RULE_XXX=0 to explicitly disable the rule.
 */

static MMFilterRule
filter_rule_env_process (MMFilterRule enabled_rules)
{
    MMFilterRule  updated_rules = enabled_rules;
    GFlagsClass  *flags_class;
    guint         i;

    flags_class = g_type_class_ref (MM_TYPE_FILTER_RULE);

    for (i = 0; (1 << i) & MM_FILTER_RULE_ALL; i++) {
        GFlagsValue *flags_value;
        const gchar *env_value;

        flags_value = g_flags_get_first_value (flags_class, (1 << i));
        g_assert (flags_value);

        env_value = g_getenv (flags_value->value_name);
        if (!env_value)
            continue;

        if (g_str_equal (env_value, "0"))
            updated_rules &= ~(1 << i);
        else if (g_str_equal (env_value, "1"))
            updated_rules |= (1 << i);
    }

    g_type_class_unref (flags_class);

    return updated_rules;
}

/*****************************************************************************/

/* If TTY rule enabled, either DEFAULT_ALLOWED or DEFAULT_FORBIDDEN must be set. */
#define VALIDATE_RULE_TTY(rules) (!(rules & MM_FILTER_RULE_TTY) || \
                                  ((rules & (MM_FILTER_RULE_TTY_DEFAULT_ALLOWED | MM_FILTER_RULE_TTY_DEFAULT_FORBIDDEN)) && \
                                   ((rules & (MM_FILTER_RULE_TTY_DEFAULT_ALLOWED | MM_FILTER_RULE_TTY_DEFAULT_FORBIDDEN)) != \
                                    (MM_FILTER_RULE_TTY_DEFAULT_ALLOWED | MM_FILTER_RULE_TTY_DEFAULT_FORBIDDEN))))

MMFilter *
mm_filter_new (MMFilterRule   enabled_rules,
               GError       **error)
{
    MMFilter     *self;
    MMFilterRule  updated_rules;

    /* The input enabled rules are coming from predefined filter profiles. */
    g_assert (VALIDATE_RULE_TTY (enabled_rules));
    updated_rules = filter_rule_env_process (enabled_rules);
    if (!VALIDATE_RULE_TTY (updated_rules)) {
        g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_INVALID_ARGS,
                     "Invalid rules after processing envvars");
        return NULL;
    }

    self = g_object_new (MM_TYPE_FILTER,
                         MM_FILTER_ENABLED_RULES, updated_rules,
                         NULL);

#define RULE_ENABLED_STR(flag) ((self->priv->enabled_rules & flag) ? "yes" : "no")

    mm_dbg ("[filter] created");
    mm_dbg ("[filter]   explicit whitelist:         %s", RULE_ENABLED_STR (MM_FILTER_RULE_EXPLICIT_WHITELIST));
    mm_dbg ("[filter]   virtual devices forbidden:  %s", RULE_ENABLED_STR (MM_FILTER_RULE_VIRTUAL));
    mm_dbg ("[filter]   net devices allowed:        %s", RULE_ENABLED_STR (MM_FILTER_RULE_NET));
    mm_dbg ("[filter]   cdc-wdm devices allowed:    %s", RULE_ENABLED_STR (MM_FILTER_RULE_CDC_WDM));
    if (self->priv->enabled_rules & MM_FILTER_RULE_TTY) {
        mm_dbg ("[filter]   tty devices:");
        mm_dbg ("[filter]       blacklist applied:        %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_BLACKLIST));
        mm_dbg ("[filter]       manual scan only applied: %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_MANUAL_SCAN_ONLY));
        mm_dbg ("[filter]       platform driver check:    %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_PLATFORM_DRIVER));
        mm_dbg ("[filter]       driver check:             %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_DRIVER));
        mm_dbg ("[filter]       cdc-acm interface check:  %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_ACM_INTERFACE));
        mm_dbg ("[filter]       with net check:           %s", RULE_ENABLED_STR (MM_FILTER_RULE_TTY_WITH_NET));
        if (self->priv->enabled_rules & MM_FILTER_RULE_TTY_DEFAULT_ALLOWED)
            mm_dbg ("[filter]       default:                  allowed");
        else if (self->priv->enabled_rules & MM_FILTER_RULE_TTY_DEFAULT_FORBIDDEN)
            mm_dbg ("[filter]       default:                  forbidden");
        else
            g_assert_not_reached ();
    } else
        mm_dbg ("[filter]   tty devices:                no");

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
