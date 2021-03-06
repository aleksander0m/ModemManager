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
 * Copyright (C) 2016 Aleksander Morgado <aleksander@aleksander.es>
 */

#include <string.h>
#include <gmodule.h>

#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-log.h"
#include "mm-broadband-modem-ublox.h"
#include "mm-plugin-ublox.h"

G_DEFINE_TYPE (MMPluginUblox, mm_plugin_ublox, MM_TYPE_PLUGIN)

MM_PLUGIN_DEFINE_MAJOR_VERSION
MM_PLUGIN_DEFINE_MINOR_VERSION

/*****************************************************************************/
/* Custom commands for AT probing */

/* Increase the response timeout for probe commands since the TOBY-L2 modem
 * takes longer to respond after a reset.
 */
static const MMPortProbeAtCommand custom_at_probe[] = {
    { "AT",  7, mm_port_probe_response_processor_is_at },
    { "AT",  7, mm_port_probe_response_processor_is_at },
    { "AT",  7, mm_port_probe_response_processor_is_at },
    { NULL }
};

/*****************************************************************************/

static MMBaseModem *
create_modem (MMPlugin     *self,
              const gchar  *sysfs_path,
              const gchar **drivers,
              guint16       vendor,
              guint16       product,
              GList        *probes,
              GError      **error)
{
    return MM_BASE_MODEM (mm_broadband_modem_ublox_new (sysfs_path,
                                                        drivers,
                                                        mm_plugin_get_name (self),
                                                        vendor,
                                                        product));
}

static gboolean
grab_port (MMPlugin     *self,
           MMBaseModem  *modem,
           MMPortProbe  *probe,
           GError      **error)
{
    MMPortSerialAtFlag pflags = MM_PORT_SERIAL_AT_FLAG_NONE;
    MMKernelDevice *port;
    MMPortType port_type;

    port_type = mm_port_probe_get_port_type (probe);
    port = mm_port_probe_peek_port (probe);

    if (mm_kernel_device_get_property_as_boolean (port, "ID_MM_UBLOX_PRIMARY_PORT")) {
        mm_dbg ("(%s/%s)' port flagged as primary",
                mm_port_probe_get_port_subsys (probe),
                mm_port_probe_get_port_name (probe));
        pflags = MM_PORT_SERIAL_AT_FLAG_PRIMARY;
    } else if (mm_kernel_device_get_property_as_boolean (port, "ID_MM_UBLOX_SECONDARY_PORT")) {
        mm_dbg ("(%s/%s) port flagged as secondary",
                mm_port_probe_get_port_subsys (probe),
                mm_port_probe_get_port_name (probe));
        pflags = MM_PORT_SERIAL_AT_FLAG_SECONDARY;
    }

    return mm_base_modem_grab_port (modem, port, port_type, pflags, error);
}

/*****************************************************************************/

G_MODULE_EXPORT MMPlugin *
mm_plugin_create (void)
{
    static const gchar *subsystems[] = { "tty", "net", NULL };
    static const guint16 vendor_ids[] = { 0x1546, 0 };
    static const gchar *vendor_strings[] = { "u-blox", NULL };

    return MM_PLUGIN (g_object_new (MM_TYPE_PLUGIN_UBLOX,
                                    MM_PLUGIN_NAME,                   "u-blox",
                                    MM_PLUGIN_ALLOWED_SUBSYSTEMS,     subsystems,
                                    MM_PLUGIN_ALLOWED_VENDOR_IDS,     vendor_ids,
                                    MM_PLUGIN_ALLOWED_VENDOR_STRINGS, vendor_strings,
                                    MM_PLUGIN_ALLOWED_AT,             TRUE,
                                    MM_PLUGIN_CUSTOM_AT_PROBE,        custom_at_probe,
                                    MM_PLUGIN_SEND_DELAY,             (guint64) 0,
                                    NULL));
}

static void
mm_plugin_ublox_init (MMPluginUblox *self)
{
}

static void
mm_plugin_ublox_class_init (MMPluginUbloxClass *klass)
{
    MMPluginClass *plugin_class = MM_PLUGIN_CLASS (klass);

    plugin_class->create_modem = create_modem;
    plugin_class->grab_port    = grab_port;
}
