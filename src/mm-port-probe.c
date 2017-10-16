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
 * Copyright (C) 2011 Aleksander Morgado <aleksander@gnu.org>
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ModemManager.h>
#include <mm-errors-types.h>

#include "mm-port-probe.h"
#include "mm-log.h"
#include "mm-port-serial-at.h"
#include "mm-port-serial.h"
#include "mm-serial-parsers.h"
#include "mm-port-probe-at.h"
#include "libqcdm/src/commands.h"
#include "libqcdm/src/utils.h"
#include "libqcdm/src/errors.h"
#include "mm-port-serial-qcdm.h"
#include "mm-daemon-enums-types.h"

#if defined WITH_QMI
#include "mm-port-qmi.h"
#endif

#if defined WITH_MBIM
#include "mm-port-mbim.h"
#endif

/*
 * Steps and flow of the Probing process:
 * ----> AT Serial Open
 *   |----> Custom Init
 *   |----> AT?
 *      |----> Vendor
 *      |----> Product
 *      |----> Is Icera?
 * ----> QCDM Serial Open
 *   |----> QCDM?
 * ----> QMI Device Open
 *   |----> QMI Version Info check
 * ----> MBIM Device Open
 *   |----> MBIM capabilities check
 */

G_DEFINE_TYPE (MMPortProbe, mm_port_probe, G_TYPE_OBJECT)

enum {
    PROP_0,
    PROP_DEVICE,
    PROP_PORT,
    PROP_LAST
};

static GParamSpec *properties[PROP_LAST];

struct _MMPortProbePrivate {
    /* Properties */
    MMDevice *device;
    MMKernelDevice *port;

    /* Probing results */
    guint32 flags;
    gboolean is_at;
    gboolean is_qcdm;
    gchar *vendor;
    gchar *product;
    gboolean is_icera;
    gboolean is_qmi;
    gboolean is_mbim;

    /* From udev tags */
    gboolean is_ignored;

    /* Current probing task. Only one can be available at a time */
    GTask *task;
};

/*****************************************************************************/
/* Probe task completions.
 * Always make sure that the stored task is NULL when the task is completed.
 */

static gboolean
port_probe_task_return_error_if_cancelled (MMPortProbe *self)
{
    GTask *task;

    task = self->priv->task;
    self->priv->task = NULL;

    if (g_task_return_error_if_cancelled (task)) {
        g_object_unref (task);
        return TRUE;
    }

    self->priv->task = task;
    return FALSE;
}

static void
port_probe_task_return_error (MMPortProbe *self,
                              GError      *error)
{
    GTask *task;

    task = self->priv->task;
    self->priv->task = NULL;
    g_task_return_error (task, error);
    g_object_unref (task);
}

static void
port_probe_task_return_boolean (MMPortProbe *self,
                                gboolean     result)
{
    GTask *task;

    task = self->priv->task;
    self->priv->task = NULL;
    g_task_return_boolean (task, result);
    g_object_unref (task);
}

/*****************************************************************************/

void
mm_port_probe_set_result_at (MMPortProbe *self,
                             gboolean at)
{
    self->priv->is_at = at;
    self->priv->flags |= MM_PORT_PROBE_AT;

    if (self->priv->is_at) {
        mm_dbg ("(%s/%s) port is AT-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));

        /* Also set as not a QCDM/QMI/MBIM port */
        self->priv->is_qcdm = FALSE;
        self->priv->is_qmi = FALSE;
        self->priv->is_mbim = FALSE;
        self->priv->flags |= (MM_PORT_PROBE_QCDM | MM_PORT_PROBE_QMI | MM_PORT_PROBE_MBIM);
    } else {
        mm_dbg ("(%s/%s) port is not AT-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->vendor = NULL;
        self->priv->product = NULL;
        self->priv->is_icera = FALSE;
        self->priv->flags |= (MM_PORT_PROBE_AT_VENDOR |
                              MM_PORT_PROBE_AT_PRODUCT |
                              MM_PORT_PROBE_AT_ICERA);
    }
}

void
mm_port_probe_set_result_at_vendor (MMPortProbe *self,
                                    const gchar *at_vendor)
{
    if (at_vendor) {
        mm_dbg ("(%s/%s) vendor probing finished",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->vendor = g_utf8_casefold (at_vendor, -1);
        self->priv->flags |= MM_PORT_PROBE_AT_VENDOR;
    } else {
        mm_dbg ("(%s/%s) couldn't probe for vendor string",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->vendor = NULL;
        self->priv->product = NULL;
        self->priv->flags |= (MM_PORT_PROBE_AT_VENDOR | MM_PORT_PROBE_AT_PRODUCT);
    }
}

void
mm_port_probe_set_result_at_product (MMPortProbe *self,
                                     const gchar *at_product)
{
    if (at_product) {
        mm_dbg ("(%s/%s) product probing finished",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->product = g_utf8_casefold (at_product, -1);
        self->priv->flags |= MM_PORT_PROBE_AT_PRODUCT;
    } else {
        mm_dbg ("(%s/%s) couldn't probe for product string",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->product = NULL;
        self->priv->flags |= MM_PORT_PROBE_AT_PRODUCT;
    }
}

void
mm_port_probe_set_result_at_icera (MMPortProbe *self,
                                   gboolean is_icera)
{
    if (is_icera) {
        mm_dbg ("(%s/%s) Modem is Icera-based",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->is_icera = TRUE;
        self->priv->flags |= MM_PORT_PROBE_AT_ICERA;
    } else {
        mm_dbg ("(%s/%s) Modem is probably not Icera-based",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        self->priv->is_icera = FALSE;
        self->priv->flags |= MM_PORT_PROBE_AT_ICERA;
    }
}

void
mm_port_probe_set_result_qcdm (MMPortProbe *self,
                               gboolean qcdm)
{
    self->priv->is_qcdm = qcdm;
    self->priv->flags |= MM_PORT_PROBE_QCDM;

    if (self->priv->is_qcdm) {
        mm_dbg ("(%s/%s) port is QCDM-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));

        /* Also set as not an AT/QMI/MBIM port */
        self->priv->is_at = FALSE;
        self->priv->is_qmi = FALSE;
        self->priv->is_mbim = FALSE;
        self->priv->vendor = NULL;
        self->priv->product = NULL;
        self->priv->is_icera = FALSE;
        self->priv->flags |= (MM_PORT_PROBE_AT |
                              MM_PORT_PROBE_AT_VENDOR |
                              MM_PORT_PROBE_AT_PRODUCT |
                              MM_PORT_PROBE_AT_ICERA |
                              MM_PORT_PROBE_QMI |
                              MM_PORT_PROBE_MBIM);
    } else
        mm_dbg ("(%s/%s) port is not QCDM-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
}

void
mm_port_probe_set_result_qmi (MMPortProbe *self,
                              gboolean qmi)
{
    self->priv->is_qmi = qmi;
    self->priv->flags |= MM_PORT_PROBE_QMI;

    if (self->priv->is_qmi) {
        mm_dbg ("(%s/%s) port is QMI-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));

        /* Also set as not an AT/QCDM/MBIM port */
        self->priv->is_at = FALSE;
        self->priv->is_qcdm = FALSE;
        self->priv->is_mbim = FALSE;
        self->priv->vendor = NULL;
        self->priv->product = NULL;
        self->priv->flags |= (MM_PORT_PROBE_AT |
                              MM_PORT_PROBE_AT_VENDOR |
                              MM_PORT_PROBE_AT_PRODUCT |
                              MM_PORT_PROBE_AT_ICERA |
                              MM_PORT_PROBE_QCDM |
                              MM_PORT_PROBE_MBIM);
    } else
        mm_dbg ("(%s/%s) port is not QMI-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
}

void
mm_port_probe_set_result_mbim (MMPortProbe *self,
                               gboolean mbim)
{
    self->priv->is_mbim = mbim;
    self->priv->flags |= MM_PORT_PROBE_MBIM;

    if (self->priv->is_mbim) {
        mm_dbg ("(%s/%s) port is MBIM-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));

        /* Also set as not an AT/QCDM/QMI port */
        self->priv->is_at = FALSE;
        self->priv->is_qcdm = FALSE;
        self->priv->is_qmi = FALSE;
        self->priv->vendor = NULL;
        self->priv->product = NULL;
        self->priv->flags |= (MM_PORT_PROBE_AT |
                              MM_PORT_PROBE_AT_VENDOR |
                              MM_PORT_PROBE_AT_PRODUCT |
                              MM_PORT_PROBE_AT_ICERA |
                              MM_PORT_PROBE_QCDM |
                              MM_PORT_PROBE_QMI);
    } else
        mm_dbg ("(%s/%s) port is not MBIM-capable",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
}

/*****************************************************************************/

typedef struct {
    /* ---- Generic task context ---- */
    guint32 flags;
    guint source_id;
    GCancellable *cancellable;

    /* ---- Serial probing specific context ---- */

    guint buffer_full_id;
    MMPortSerial *serial;

    /* ---- AT probing specific context ---- */

    GCancellable *at_probing_cancellable;
    gulong at_probing_cancellable_linked;
    /* Send delay for AT commands */
    guint64 at_send_delay;
    /* Flag to leave/remove echo in AT responses */
    gboolean at_remove_echo;
    /* Flag to send line-feed at the end of AT commands */
    gboolean at_send_lf;
    /* Number of times we tried to open the AT port */
    guint at_open_tries;
    /* Custom initialization setup */
    gboolean at_custom_init_run;
    MMPortProbeAtCustomInit at_custom_init;
    MMPortProbeAtCustomInitFinish at_custom_init_finish;
    /* Custom commands to look for AT support */
    const MMPortProbeAtCommand *at_custom_probe;
    /* Current group of AT commands to be sent */
    const MMPortProbeAtCommand *at_commands;
    /* Seconds between each AT command sent in the group */
    guint at_commands_wait_secs;
    /* Current AT Result processor */
    void (* at_result_processor) (MMPortProbe *self,
                                  GVariant *result);

#if defined WITH_QMI
    /* ---- QMI probing specific context ---- */
    MMPortQmi *port_qmi;
#endif

#if defined WITH_MBIM
    /* ---- MBIM probing specific context ---- */
    MMPortMbim *mbim_port;
#endif
} PortProbeRunContext;

static gboolean serial_probe_at       (MMPortProbe *self);
static gboolean serial_probe_qcdm     (MMPortProbe *self);
static void     serial_probe_schedule (MMPortProbe *self);

static void
port_probe_run_context_free (PortProbeRunContext *ctx)
{
    if (ctx->cancellable && ctx->at_probing_cancellable_linked) {
        g_cancellable_disconnect (ctx->cancellable, ctx->at_probing_cancellable_linked);
        ctx->at_probing_cancellable_linked = 0;
    }

    if (ctx->source_id) {
        g_source_remove (ctx->source_id);
        ctx->source_id = 0;
    }

    if (ctx->serial && ctx->buffer_full_id) {
        g_signal_handler_disconnect (ctx->serial, ctx->buffer_full_id);
        ctx->buffer_full_id = 0;
    }

    if (ctx->serial) {
        if (mm_port_serial_is_open (ctx->serial))
            mm_port_serial_close (ctx->serial);
        g_object_unref (ctx->serial);
    }

#if defined WITH_QMI
    if (ctx->port_qmi) {
        if (mm_port_qmi_is_open (ctx->port_qmi))
            mm_port_qmi_close (ctx->port_qmi);
        g_object_unref (ctx->port_qmi);
    }
#endif

#if defined WITH_MBIM
    if (ctx->mbim_port) {
        /* We should have closed it cleanly before */
        g_assert (!mm_port_mbim_is_open (ctx->mbim_port));
        g_object_unref (ctx->mbim_port);
    }
#endif

    if (ctx->at_probing_cancellable)
        g_object_unref (ctx->at_probing_cancellable);
    if (ctx->cancellable)
        g_object_unref (ctx->cancellable);

    g_slice_free (PortProbeRunContext, ctx);
}

/***************************************************************/
/* QMI & MBIM */

static gboolean wdm_probe (MMPortProbe *self);

#if defined WITH_QMI

static void
port_qmi_open_ready (MMPortQmi    *port_qmi,
                     GAsyncResult *res,
                     MMPortProbe  *self)
{
    GError              *error = NULL;
    PortProbeRunContext *ctx;
    gboolean             is_qmi;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    is_qmi = mm_port_qmi_open_finish (port_qmi, res, &error);
    if (!is_qmi) {
        mm_dbg ("(%s/%s) error checking QMI support: '%s'",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port),
                error ? error->message : "unknown error");
        g_clear_error (&error);
    }

    /* Set probing result */
    mm_port_probe_set_result_qmi (self, is_qmi);
    mm_port_qmi_close (port_qmi);

    /* Keep on */
    ctx->source_id = g_idle_add ((GSourceFunc) wdm_probe, self);
}

#endif /* WITH_QMI */

static void
wdm_probe_qmi (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

#if defined WITH_QMI
    mm_dbg ("(%s/%s) probing QMI...",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port));

    /* Create a port and try to open it */
    ctx->port_qmi = mm_port_qmi_new (mm_kernel_device_get_name (self->priv->port));
    mm_port_qmi_open (ctx->port_qmi,
                      FALSE,
                      NULL,
                      (GAsyncReadyCallback) port_qmi_open_ready,
                      self);
#else
    /* If not compiled with QMI support, just assume we won't have any QMI port */
    mm_port_probe_set_result_qmi (self, FALSE);
    ctx->source_id = g_idle_add ((GSourceFunc) wdm_probe, self);
#endif /* WITH_QMI */
}

#if defined WITH_MBIM

static void
mbim_port_close_ready (MMPortMbim   *mbim_port,
                       GAsyncResult *res,
                       MMPortProbe  *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    mm_port_mbim_close_finish (mbim_port, res, NULL);

    /* Keep on */
    ctx->source_id = g_idle_add ((GSourceFunc) wdm_probe, self);
}

static void
mbim_port_open_ready (MMPortMbim   *mbim_port,
                      GAsyncResult *res,
                      MMPortProbe  *self)
{
    GError              *error = NULL;
    PortProbeRunContext *ctx;
    gboolean             is_mbim;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    is_mbim = mm_port_mbim_open_finish (mbim_port, res, &error);
    if (!is_mbim) {
        mm_dbg ("(%s/%s) error checking MBIM support: '%s'",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port),
                error ? error->message : "unknown error");
        g_clear_error (&error);
    }

    /* Set probing result */
    mm_port_probe_set_result_mbim (self, is_mbim);

    mm_port_mbim_close (ctx->mbim_port,
                        (GAsyncReadyCallback) mbim_port_close_ready,
                        self);
}

#endif /* WITH_MBIM */

static void
wdm_probe_mbim (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

#if defined WITH_MBIM
    mm_dbg ("(%s/%s) probing MBIM...",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port));

    /* Create a port and try to open it */
    ctx->mbim_port = mm_port_mbim_new (mm_kernel_device_get_name (self->priv->port));
    mm_port_mbim_open (ctx->mbim_port,
                       NULL,
                       (GAsyncReadyCallback) mbim_port_open_ready,
                       self);
#else
    /* If not compiled with MBIM support, just assume we won't have any MBIM port */
    mm_port_probe_set_result_mbim (self, FALSE);
    ctx->source_id = g_idle_add ((GSourceFunc) wdm_probe, self);
#endif /* WITH_MBIM */
}

static gboolean
wdm_probe (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);
    ctx->source_id = 0;

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return G_SOURCE_REMOVE;

    /* QMI probing needed? */
    if ((ctx->flags & MM_PORT_PROBE_QMI) &&
        !(self->priv->flags & MM_PORT_PROBE_QMI)) {
        wdm_probe_qmi (self);
        return G_SOURCE_REMOVE;
    }

    /* MBIM probing needed */
    if ((ctx->flags & MM_PORT_PROBE_MBIM) &&
        !(self->priv->flags & MM_PORT_PROBE_MBIM)) {
        wdm_probe_mbim (self);
        return G_SOURCE_REMOVE;
    }

    /* All done now */
    port_probe_task_return_boolean (self, TRUE);
    return G_SOURCE_REMOVE;
}

/***************************************************************/
/* QCDM */

static void
serial_probe_qcdm_parse_response (MMPortSerialQcdm *port,
                                  GAsyncResult     *res,
                                  MMPortProbe      *self)
{
    QcdmResult          *result;
    gint                 err = QCDM_SUCCESS;
    gboolean             is_qcdm = FALSE;
    gboolean             retry = FALSE;
    GError              *error = NULL;
    GByteArray          *response;
    PortProbeRunContext *ctx;

    ctx = g_task_get_task_data (self->priv->task);

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return;

    response = mm_port_serial_qcdm_command_finish (port, res, &error);
    if (!error) {
        /* Parse the response */
        result = qcdm_cmd_version_info_result ((const gchar *) response->data, response->len, &err);
        if (!result) {
            mm_warn ("(%s/%s) failed to parse QCDM version info command result: %d",
                     mm_kernel_device_get_subsystem (self->priv->port),
                     mm_kernel_device_get_name (self->priv->port),
                     err);
            retry = TRUE;
        } else {
            /* yay, probably a QCDM port */
            is_qcdm = TRUE;
            qcdm_result_unref (result);
        }
        g_byte_array_unref (response);
    } else if (g_error_matches (error, MM_SERIAL_ERROR, MM_SERIAL_ERROR_PARSE_FAILED)) {
        /* Failed to unescape QCDM packet: don't retry */
        mm_dbg ("QCDM parsing error: %s", error->message);
        g_error_free (error);
    } else {
        if (!g_error_matches (error, MM_SERIAL_ERROR, MM_SERIAL_ERROR_RESPONSE_TIMEOUT))
            mm_dbg ("QCDM probe error: (%d) %s", error->code, error->message);
        g_error_free (error);
        retry = TRUE;
    }

    if (retry) {
        GByteArray *cmd2;

        cmd2 = g_object_steal_data (G_OBJECT (self), "cmd2");
        if (cmd2) {
            /* second try */
            mm_port_serial_qcdm_command (MM_PORT_SERIAL_QCDM (ctx->serial),
                                         cmd2,
                                         3,
                                         NULL,
                                         (GAsyncReadyCallback) serial_probe_qcdm_parse_response,
                                         self);
            g_byte_array_unref (cmd2);
            return;
        }
        /* no more retries left */
    }

    /* Set probing result */
    mm_port_probe_set_result_qcdm (self, is_qcdm);
    /* Reschedule probing */
    serial_probe_schedule (self);
}

static gboolean
serial_probe_qcdm (MMPortProbe *self)
{
    GError              *error = NULL;
    GByteArray          *verinfo = NULL;
    GByteArray          *verinfo2;
    gint                 len;
    guint8               marker = 0x7E;
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);
    ctx->source_id = 0;

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return G_SOURCE_REMOVE;

    mm_dbg ("(%s/%s) probing QCDM...",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port));

    /* If open, close the AT port */
    if (ctx->serial) {
        /* Explicitly clear the buffer full signal handler */
        if (ctx->buffer_full_id) {
            g_signal_handler_disconnect (ctx->serial, ctx->buffer_full_id);
            ctx->buffer_full_id = 0;
        }
        mm_port_serial_close (ctx->serial);
        g_object_unref (ctx->serial);
    }

    /* Open the QCDM port */
    ctx->serial = MM_PORT_SERIAL (mm_port_serial_qcdm_new (mm_kernel_device_get_name (self->priv->port)));
    if (!ctx->serial) {
        port_probe_task_return_error (self,
                                      g_error_new (MM_CORE_ERROR,
                                                   MM_CORE_ERROR_FAILED,
                                                   "(%s/%s) Couldn't create QCDM port",
                                                   mm_kernel_device_get_subsystem (self->priv->port),
                                                   mm_kernel_device_get_name (self->priv->port)));
        return G_SOURCE_REMOVE;
    }

    if (mm_kernel_device_has_property (self->priv->port, "ID_MM_TTY_BAUDRATE"))
        g_object_set (ctx->serial,
                      MM_PORT_SERIAL_BAUD, mm_kernel_device_get_property_as_int (self->priv->port, "ID_MM_TTY_BAUDRATE"),
                      NULL);

    /* Try to open the port */
    if (!mm_port_serial_open (ctx->serial, &error)) {
        port_probe_task_return_error (self,
                                      g_error_new (MM_SERIAL_ERROR,
                                                   MM_SERIAL_ERROR_OPEN_FAILED,
                                                   "(%s/%s) Failed to open QCDM port: %s",
                                                   mm_kernel_device_get_subsystem (self->priv->port),
                                                   mm_kernel_device_get_name (self->priv->port),
                                                   (error ? error->message : "unknown error")));
        g_clear_error (&error);
        return G_SOURCE_REMOVE;
    }

    /* Build up the probe command; 0x7E is the frame marker, so put one at the
     * beginning of the buffer to ensure that the device discards any AT
     * commands that probing might have sent earlier.  Should help devices
     * respond more quickly and speed up QCDM probing.
     */
    verinfo = g_byte_array_sized_new (10);
    g_byte_array_append (verinfo, &marker, 1);
    len = qcdm_cmd_version_info_new ((char *) (verinfo->data + 1), 9);
    if (len <= 0) {
        g_byte_array_unref (verinfo);
        port_probe_task_return_error (self,
                                      g_error_new (MM_SERIAL_ERROR,
                                                   MM_SERIAL_ERROR_OPEN_FAILED,
                                                   "(%s/%s) Failed to create QCDM version info command",
                                                   mm_kernel_device_get_subsystem (self->priv->port),
                                                   mm_kernel_device_get_name (self->priv->port)));
        return G_SOURCE_REMOVE;
    }
    verinfo->len = len + 1;

    /* Queuing the command takes ownership over it; save it for the second try */
    verinfo2 = g_byte_array_sized_new (verinfo->len);
    g_byte_array_append (verinfo2, verinfo->data, verinfo->len);
    g_object_set_data_full (G_OBJECT (self), "cmd2", verinfo2, (GDestroyNotify) g_byte_array_unref);

    mm_port_serial_qcdm_command (MM_PORT_SERIAL_QCDM (ctx->serial),
                                 verinfo,
                                 3,
                                 NULL,
                                 (GAsyncReadyCallback) serial_probe_qcdm_parse_response,
                                 self);
    g_byte_array_unref (verinfo);

    return G_SOURCE_REMOVE;
}

/***************************************************************/
/* AT */

static const gchar *non_at_strings[] = {
    /* Option Icera-based devices */
    "option/faema_",
    "os_logids.h",
    /* Sierra CnS port */
    "NETWORK SERVICE CHANGE",
    NULL
};

static const guint8 zerobuf[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static gboolean
is_non_at_response (const guint8 *data, gsize len)
{
    const gchar **iter;
    gsize iter_len;
    gsize i;

    /* Some devices (observed on a ZTE branded "QUALCOMM INCORPORATED" model
     * "154") spew NULLs from some ports.
     */
    for (i = 0; (len >= sizeof (zerobuf)) && (i < len - sizeof (zerobuf)); i++) {
        if (!memcmp (&data[i], zerobuf, sizeof (zerobuf)))
            return TRUE;
    }

    /* Check for a well-known non-AT response.  There are some ports (eg many
     * Icera-based chipsets, Qualcomm Gobi devices before their firmware is
     * loaded, Sierra CnS ports) that just shouldn't be probed for AT capability
     * if we get a certain response since that response means they aren't AT
     * ports.  Also, kernel bugs (at least with 2.6.31 and 2.6.32) trigger port
     * flow control kernel oopses if we read too much data for these ports.
     */
    for (iter = &non_at_strings[0]; iter && *iter; iter++) {
        /* Search in the response for the item; the response could have embedded
         * nulls so we can't use memcmp() or strstr() on the whole response.
         */
        iter_len = strlen (*iter);
        for (i = 0; (len >= iter_len) && (i < len - iter_len); i++) {
            if (!memcmp (&data[i], *iter, iter_len))
                return TRUE;
        }
    }

    return FALSE;
}

static void
serial_probe_at_icera_result_processor (MMPortProbe *self,
                                        GVariant *result)
{
    if (result) {
        /* If any result given, it must be a string */
        g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE_STRING));
        if (strstr (g_variant_get_string (result, NULL), "%IPSYS:")) {
            mm_port_probe_set_result_at_icera (self, TRUE);
            return;
        }
    }

    mm_port_probe_set_result_at_icera (self, FALSE);
}

static void
serial_probe_at_product_result_processor (MMPortProbe *self,
                                          GVariant *result)
{
    if (result) {
        /* If any result given, it must be a string */
        g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE_STRING));
        mm_port_probe_set_result_at_product (self,
                                             g_variant_get_string (result, NULL));
        return;
    }

    mm_port_probe_set_result_at_product (self, NULL);
}

static void
serial_probe_at_vendor_result_processor (MMPortProbe *self,
                                         GVariant *result)
{
    if (result) {
        /* If any result given, it must be a string */
        g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE_STRING));
        mm_port_probe_set_result_at_vendor (self,
                                            g_variant_get_string (result, NULL));
        return;
    }

    mm_port_probe_set_result_at_vendor (self, NULL);
}

static void
serial_probe_at_result_processor (MMPortProbe *self,
                                  GVariant *result)
{
    if (result) {
        /* If any result given, it must be a boolean */
        g_assert (g_variant_is_of_type (result, G_VARIANT_TYPE_BOOLEAN));

        if (g_variant_get_boolean (result)) {
            mm_port_probe_set_result_at (self, TRUE);
            return;
        }
    }

    mm_port_probe_set_result_at (self, FALSE);
}

static void
serial_probe_at_parse_response (MMPortSerialAt *port,
                                GAsyncResult   *res,
                                MMPortProbe    *self)
{
    GVariant            *result = NULL;
    GError              *result_error = NULL;
    const gchar         *response = NULL;
    GError              *error = NULL;
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return;

    /* If AT probing cancelled, end this partial probing */
    if (g_cancellable_is_cancelled (ctx->at_probing_cancellable)) {
        mm_dbg ("(%s/%s) no need to keep on probing the port for AT support",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        ctx->at_result_processor (self, NULL);
        serial_probe_schedule (self);
        return;
    }

    response = mm_port_serial_at_command_finish (port, res, &error);

    if (!ctx->at_commands->response_processor (ctx->at_commands->command,
                                               response,
                                               !!ctx->at_commands[1].command,
                                               error,
                                               &result,
                                               &result_error)) {
        /* Were we told to abort the whole probing? */
        if (result_error) {
            port_probe_task_return_error (self,
                                          g_error_new (MM_CORE_ERROR,
                                                       MM_CORE_ERROR_UNSUPPORTED,
                                                       "(%s/%s) error while probing AT features: %s",
                                                       mm_kernel_device_get_subsystem (self->priv->port),
                                                       mm_kernel_device_get_name (self->priv->port),
                                                       result_error->message));
            goto out;
        }

        /* Go on to next command */
        ctx->at_commands++;
        if (!ctx->at_commands->command) {
            /* Was it the last command in the group? If so,
             * end this partial probing */
            ctx->at_result_processor (self, NULL);
            /* Reschedule */
            serial_probe_schedule (self);
            goto out;
        }

        /* Schedule the next command in the probing group */
        if (ctx->at_commands_wait_secs == 0)
            ctx->source_id = g_idle_add ((GSourceFunc) serial_probe_at, self);
        else {
            mm_dbg ("(%s/%s) re-scheduling next command in probing group in %u seconds...",
                    mm_kernel_device_get_subsystem (self->priv->port),
                    mm_kernel_device_get_name (self->priv->port),
                    ctx->at_commands_wait_secs);
            ctx->source_id = g_timeout_add_seconds (ctx->at_commands_wait_secs, (GSourceFunc) serial_probe_at, self);
        }
        goto out;
    }

    /* Run result processor.
     * Note that custom init commands are allowed to not return anything */
    ctx->at_result_processor (self, result);

    /* Reschedule probing */
    serial_probe_schedule (self);

out:
    g_clear_pointer (&result, g_variant_unref);
    g_clear_error (&error);
    g_clear_error (&result_error);
}

static gboolean
serial_probe_at (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);
    ctx->source_id = 0;

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return G_SOURCE_REMOVE;

    /* If AT probing cancelled, end this partial probing */
    if (g_cancellable_is_cancelled (ctx->at_probing_cancellable)) {
        mm_dbg ("(%s/%s) no need to launch probing for AT support",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        ctx->at_result_processor (self, NULL);
        serial_probe_schedule (self);
        return G_SOURCE_REMOVE;
    }

    mm_port_serial_at_command (
        MM_PORT_SERIAL_AT (ctx->serial),
        ctx->at_commands->command,
        ctx->at_commands->timeout,
        FALSE,
        FALSE,
        ctx->at_probing_cancellable,
        (GAsyncReadyCallback)serial_probe_at_parse_response,
        self);
    return G_SOURCE_REMOVE;
}

static const MMPortProbeAtCommand at_probing[] = {
    { "AT",  3, mm_port_probe_response_processor_is_at },
    { "AT",  3, mm_port_probe_response_processor_is_at },
    { "AT",  3, mm_port_probe_response_processor_is_at },
    { NULL }
};

static const MMPortProbeAtCommand vendor_probing[] = {
    { "+CGMI", 3, mm_port_probe_response_processor_string },
    { "+GMI",  3, mm_port_probe_response_processor_string },
    { "I",     3, mm_port_probe_response_processor_string },
    { NULL }
};

static const MMPortProbeAtCommand product_probing[] = {
    { "+CGMM", 3, mm_port_probe_response_processor_string },
    { "+GMM",  3, mm_port_probe_response_processor_string },
    { "I",     3, mm_port_probe_response_processor_string },
    { NULL }
};

static const MMPortProbeAtCommand icera_probing[] = {
    { "%IPSYS?", 3, mm_port_probe_response_processor_string },
    { "%IPSYS?", 3, mm_port_probe_response_processor_string },
    { "%IPSYS?", 3, mm_port_probe_response_processor_string },
    { NULL }
};

static void
at_custom_init_ready (MMPortProbe *self,
                      GAsyncResult *res)
{
    GError              *error = NULL;
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    if (!ctx->at_custom_init_finish (self, res, &error)) {
        /* All errors propagated up end up forcing an UNSUPPORTED result */
        port_probe_task_return_error (self, error);
        return;
    }

    /* Keep on with remaining probings */
    ctx->at_custom_init_run = TRUE;
    serial_probe_schedule (self);
}

/***************************************************************/

static void
serial_probe_schedule (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return;

    /* If we got some custom initialization setup requested, go on with it
     * first. */
    if (!ctx->at_custom_init_run &&
        ctx->at_custom_init &&
        ctx->at_custom_init_finish) {
        ctx->at_custom_init (self,
                             MM_PORT_SERIAL_AT (ctx->serial),
                             ctx->at_probing_cancellable,
                             (GAsyncReadyCallback) at_custom_init_ready,
                             NULL);
        return;
    }

    /* Cleanup */
    ctx->at_result_processor   = NULL;
    ctx->at_commands           = NULL;
    ctx->at_commands_wait_secs = 0;

    /* AT check requested and not already probed? */
    if ((ctx->flags & MM_PORT_PROBE_AT) &&
        !(self->priv->flags & MM_PORT_PROBE_AT)) {
        /* Prepare AT probing */
        if (ctx->at_custom_probe)
            ctx->at_commands = ctx->at_custom_probe;
        else
            ctx->at_commands = at_probing;
        ctx->at_result_processor = serial_probe_at_result_processor;
    }
    /* Vendor requested and not already probed? */
    else if ((ctx->flags & MM_PORT_PROBE_AT_VENDOR) &&
        !(self->priv->flags & MM_PORT_PROBE_AT_VENDOR)) {
        /* Prepare AT vendor probing */
        ctx->at_result_processor = serial_probe_at_vendor_result_processor;
        ctx->at_commands = vendor_probing;
    }
    /* Product requested and not already probed? */
    else if ((ctx->flags & MM_PORT_PROBE_AT_PRODUCT) &&
             !(self->priv->flags & MM_PORT_PROBE_AT_PRODUCT)) {
        /* Prepare AT product probing */
        ctx->at_result_processor = serial_probe_at_product_result_processor;
        ctx->at_commands = product_probing;
    }
    /* Icera support check requested and not already done? */
    else if ((ctx->flags & MM_PORT_PROBE_AT_ICERA) &&
             !(self->priv->flags & MM_PORT_PROBE_AT_ICERA)) {
        /* Prepare AT product probing */
        ctx->at_result_processor = serial_probe_at_icera_result_processor;
        ctx->at_commands = icera_probing;
        /* By default, wait 2 seconds between ICERA probing retries */
        ctx->at_commands_wait_secs = 2;
    }

    /* If a next AT group detected, go for it */
    if (ctx->at_result_processor &&
        ctx->at_commands) {
        ctx->source_id = g_idle_add ((GSourceFunc) serial_probe_at, self);
        return;
    }

    /* QCDM requested and not already probed? */
    if ((ctx->flags & MM_PORT_PROBE_QCDM) &&
        !(self->priv->flags & MM_PORT_PROBE_QCDM)) {
        ctx->source_id = g_idle_add ((GSourceFunc) serial_probe_qcdm, self);
        return;
    }

    /* All done! */
    port_probe_task_return_boolean (self, TRUE);
}

static void
serial_flash_ready (MMPortSerial *port,
                    GAsyncResult *res,
                    MMPortProbe *self)
{
    mm_port_serial_flash_finish (port, res, NULL);

    /* Schedule probing */
    serial_probe_schedule (self);
}

static void
serial_buffer_full (MMPortSerial *serial,
                    GByteArray   *buffer,
                    MMPortProbe  *self)
{
    PortProbeRunContext *ctx;

    if (!is_non_at_response (buffer->data, buffer->len))
        return;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);

    mm_dbg ("(%s/%s) serial buffer full",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port));
    /* Don't explicitly close the AT port, just end the AT probing
     * (or custom init probing) */
    mm_port_probe_set_result_at (self, FALSE);
    g_cancellable_cancel (ctx->at_probing_cancellable);
}

static gboolean
serial_parser_filter_cb (gpointer   filter,
                         gpointer   user_data,
                         GString   *response,
                         GError   **error)
{
    if (is_non_at_response ((const guint8 *) response->str, response->len)) {
        g_set_error (error,
                     MM_SERIAL_ERROR,
                     MM_SERIAL_ERROR_PARSE_FAILED,
                     "Not an AT response");
        return FALSE;
    }

    return TRUE;
}

static gboolean
serial_open_at (MMPortProbe *self)
{
    GError              *error = NULL;
    PortProbeRunContext *ctx;

    g_assert (self->priv->task);
    ctx = g_task_get_task_data (self->priv->task);
    ctx->source_id = 0;

    /* If already cancelled, do nothing else */
    if (port_probe_task_return_error_if_cancelled (self))
        return G_SOURCE_REMOVE;

    /* Create AT serial port if not done before */
    if (!ctx->serial) {
        gpointer parser;
        MMPortSubsys subsys = MM_PORT_SUBSYS_TTY;

        if (g_str_has_prefix (mm_kernel_device_get_subsystem (self->priv->port), "usb"))
            subsys = MM_PORT_SUBSYS_USB;

        ctx->serial = MM_PORT_SERIAL (mm_port_serial_at_new (mm_kernel_device_get_name (self->priv->port), subsys));
        if (!ctx->serial) {
            port_probe_task_return_error (self,
                                          g_error_new (MM_CORE_ERROR,
                                                       MM_CORE_ERROR_FAILED,
                                                       "(%s/%s) couldn't create AT port",
                                                       mm_kernel_device_get_subsystem (self->priv->port),
                                                       mm_kernel_device_get_name (self->priv->port)));
            return G_SOURCE_REMOVE;
        }

        g_object_set (ctx->serial,
                      MM_PORT_SERIAL_SPEW_CONTROL,   TRUE,
                      MM_PORT_SERIAL_SEND_DELAY,     (guint64)(subsys == MM_PORT_SUBSYS_TTY ? ctx->at_send_delay : 0),
                      MM_PORT_SERIAL_AT_REMOVE_ECHO, ctx->at_remove_echo,
                      MM_PORT_SERIAL_AT_SEND_LF,     ctx->at_send_lf,
                      NULL);

        if (mm_kernel_device_has_property (self->priv->port, "ID_MM_TTY_BAUDRATE"))
            g_object_set (ctx->serial,
                          MM_PORT_SERIAL_BAUD, mm_kernel_device_get_property_as_int (self->priv->port, "ID_MM_TTY_BAUDRATE"),
                          NULL);

        parser = mm_serial_parser_v1_new ();
        mm_serial_parser_v1_add_filter (parser,
                                        serial_parser_filter_cb,
                                        NULL);
        mm_port_serial_at_set_response_parser (MM_PORT_SERIAL_AT (ctx->serial),
                                               mm_serial_parser_v1_parse,
                                               parser,
                                               mm_serial_parser_v1_destroy);
    }

    /* Try to open the port */
    if (!mm_port_serial_open (ctx->serial, &error)) {
        /* Abort if maximum number of open tries reached */
        if (++ctx->at_open_tries > 4) {
            /* took too long to open the port; give up */
            port_probe_task_return_error (self,
                                          g_error_new (MM_CORE_ERROR,
                                                       MM_CORE_ERROR_FAILED,
                                                       "(%s/%s) failed to open port after 4 tries",
                                                       mm_kernel_device_get_subsystem (self->priv->port),
                                                       mm_kernel_device_get_name (self->priv->port)));
            g_clear_error (&error);
            return G_SOURCE_REMOVE;
        }

        if (g_error_matches (error, MM_SERIAL_ERROR, MM_SERIAL_ERROR_OPEN_FAILED_NO_DEVICE)) {
            /* this is nozomi being dumb; try again */
            ctx->source_id = g_timeout_add_seconds (1, (GSourceFunc) serial_open_at, self);
            g_clear_error (&error);
            return G_SOURCE_REMOVE;
        }

        port_probe_task_return_error (self,
                                      g_error_new (MM_SERIAL_ERROR,
                                                   MM_SERIAL_ERROR_OPEN_FAILED,
                                                   "(%s/%s) failed to open port: %s",
                                                   mm_kernel_device_get_subsystem (self->priv->port),
                                                   mm_kernel_device_get_name (self->priv->port),
                                                   (error ? error->message : "unknown error")));
        g_clear_error (&error);
        return G_SOURCE_REMOVE;
    }

    /* success, start probing */
    ctx->buffer_full_id = g_signal_connect (ctx->serial, "buffer-full",
                                            G_CALLBACK (serial_buffer_full), self);
    mm_port_serial_flash (MM_PORT_SERIAL (ctx->serial),
                          100,
                          TRUE,
                          (GAsyncReadyCallback) serial_flash_ready,
                          self);
    return G_SOURCE_REMOVE;
}

static void
at_cancellable_cancel (GCancellable        *cancellable,
                       PortProbeRunContext *ctx)
{
    /* Avoid trying to disconnect cancellable on the handler, or we'll deadlock */
    ctx->at_probing_cancellable_linked = 0;
    g_cancellable_cancel (ctx->at_probing_cancellable);
}

gboolean
mm_port_probe_run_cancel_at_probing (MMPortProbe *self)
{
    PortProbeRunContext *ctx;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    if (!self->priv->task)
        return FALSE;

    ctx = g_task_get_task_data (self->priv->task);
    if (g_cancellable_is_cancelled (ctx->at_probing_cancellable))
        return FALSE;

    mm_dbg ("(%s/%s) requested to cancel all AT probing",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port));
    g_cancellable_cancel (ctx->at_probing_cancellable);
    return TRUE;
}

gboolean
mm_port_probe_run_finish (MMPortProbe   *self,
                          GAsyncResult  *result,
                          GError       **error)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);
    g_return_val_if_fail (G_IS_TASK (result), FALSE);

    return g_task_propagate_boolean (G_TASK (result), error);
}

void
mm_port_probe_run (MMPortProbe                *self,
                   MMPortProbeFlag             flags,
                   guint64                     at_send_delay,
                   gboolean                    at_remove_echo,
                   gboolean                    at_send_lf,
                   const MMPortProbeAtCommand *at_custom_probe,
                   const MMAsyncMethod        *at_custom_init,
                   GCancellable               *cancellable,
                   GAsyncReadyCallback         callback,
                   gpointer                    user_data)
{
    PortProbeRunContext *ctx;
    gchar               *probe_list_str;
    guint32              i;

    g_return_if_fail (MM_IS_PORT_PROBE (self));
    g_return_if_fail (flags != MM_PORT_PROBE_NONE);
    g_return_if_fail (callback != NULL);

    /* Shouldn't schedule more than one probing at a time */
    g_assert (self->priv->task == NULL);
    self->priv->task = g_task_new (self, cancellable, callback, user_data);

    /* Task context */
    ctx = g_slice_new0 (PortProbeRunContext);
    ctx->at_send_delay = at_send_delay;
    ctx->at_remove_echo = at_remove_echo;
    ctx->at_send_lf = at_send_lf;
    ctx->flags = MM_PORT_PROBE_NONE;
    ctx->at_custom_probe = at_custom_probe;
    ctx->at_custom_init = at_custom_init ? (MMPortProbeAtCustomInit)at_custom_init->async : NULL;
    ctx->at_custom_init_finish = at_custom_init ? (MMPortProbeAtCustomInitFinish)at_custom_init->finish : NULL;
    ctx->cancellable = cancellable ? g_object_ref (cancellable) : NULL;

    /* The context will be owned by the task */
    g_task_set_task_data (self->priv->task, ctx, (GDestroyNotify) port_probe_run_context_free);

    /* If we're told to completely ignore the port, don't do any probing */
    if (self->priv->is_ignored) {
        mm_dbg ("(%s/%s) port probing finished: skipping for blacklisted port",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        port_probe_task_return_boolean (self, TRUE);
        return;
    }

    /* Check if we already have the requested probing results.
     * We will fix here the 'ctx->flags' so that we only request probing
     * for the missing things. */
    for (i = MM_PORT_PROBE_AT; i <= MM_PORT_PROBE_MBIM; i = (i << 1)) {
        if ((flags & i) && !(self->priv->flags & i))
            ctx->flags += i;
    }

    /* All requested probings already available? If so, we're done */
    if (!ctx->flags) {
        mm_dbg ("(%s/%s) port probing finished: no more probings needed",
                mm_kernel_device_get_subsystem (self->priv->port),
                mm_kernel_device_get_name (self->priv->port));
        port_probe_task_return_boolean (self, TRUE);
        return;
    }

    /* Log the probes scheduled to be run */
    probe_list_str = mm_port_probe_flag_build_string_from_mask (ctx->flags);
    mm_dbg ("(%s/%s) launching port probing: '%s'",
            mm_kernel_device_get_subsystem (self->priv->port),
            mm_kernel_device_get_name (self->priv->port),
            probe_list_str);
    g_free (probe_list_str);

    /* If any AT probing is needed, start by opening as AT port */
    if (ctx->flags & MM_PORT_PROBE_AT ||
        ctx->flags & MM_PORT_PROBE_AT_VENDOR ||
        ctx->flags & MM_PORT_PROBE_AT_PRODUCT ||
        ctx->flags & MM_PORT_PROBE_AT_ICERA) {
        ctx->at_probing_cancellable = g_cancellable_new ();
        /* If the main cancellable is cancelled, so will be the at-probing one */
        if (cancellable)
            ctx->at_probing_cancellable_linked = g_cancellable_connect (cancellable,
                                                                        (GCallback) at_cancellable_cancel,
                                                                        ctx,
                                                                        NULL);
        ctx->source_id = g_idle_add ((GSourceFunc) serial_open_at, self);
        return;
    }

    /* If QCDM probing needed, start by opening as QCDM port */
    if (ctx->flags & MM_PORT_PROBE_QCDM) {
        ctx->source_id = g_idle_add ((GSourceFunc) serial_probe_qcdm, self);
        return;
    }

    /* If QMI/MBIM probing needed, go on */
    if (ctx->flags & MM_PORT_PROBE_QMI || ctx->flags & MM_PORT_PROBE_MBIM) {
        ctx->source_id = g_idle_add ((GSourceFunc) wdm_probe, self);
        return;
    }

    /* Shouldn't happen */
    g_assert_not_reached ();
}

gboolean
mm_port_probe_is_at (MMPortProbe *self)
{
    const gchar *subsys;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    if (g_str_equal (subsys, "net"))
        return FALSE;

    return (self->priv->flags & MM_PORT_PROBE_AT ?
            self->priv->is_at :
            FALSE);
}

gboolean
mm_port_probe_list_has_at_port (GList *list)
{
    GList *l;

    for (l = list; l; l = g_list_next (l)){
        MMPortProbe *probe = MM_PORT_PROBE (l->data);

        if (!probe->priv->is_ignored &&
            probe->priv->flags & MM_PORT_PROBE_AT &&
            probe->priv->is_at)
            return TRUE;
    }

    return FALSE;
}

gboolean
mm_port_probe_is_qcdm (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);
    if (g_str_equal (subsys, "net") ||
        (g_str_has_prefix (subsys, "usb") &&
         g_str_has_prefix (name, "cdc-wdm")))
        return FALSE;

    return (self->priv->flags & MM_PORT_PROBE_QCDM ?
            self->priv->is_qcdm :
            FALSE);
}

gboolean
mm_port_probe_is_qmi (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);
    if (!g_str_has_prefix (subsys, "usb") ||
        !name ||
        !g_str_has_prefix (name, "cdc-wdm"))
        return FALSE;

    return self->priv->is_qmi;
}

gboolean
mm_port_probe_list_has_qmi_port (GList *list)
{
    GList *l;

    for (l = list; l; l = g_list_next (l)) {
        MMPortProbe *probe = MM_PORT_PROBE (l->data);

        if (!probe->priv->is_ignored &&
            mm_port_probe_is_qmi (probe))
            return TRUE;
    }

    return FALSE;
}

gboolean
mm_port_probe_is_mbim (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);
    if (!g_str_has_prefix (subsys, "usb") ||
        !name ||
        !g_str_has_prefix (name, "cdc-wdm"))
        return FALSE;

    return self->priv->is_mbim;
}

gboolean
mm_port_probe_list_has_mbim_port (GList *list)
{
    GList *l;

    for (l = list; l; l = g_list_next (l)) {
        MMPortProbe *probe = MM_PORT_PROBE (l->data);

        if (!probe->priv->is_ignored &&
            mm_port_probe_is_mbim (probe))
            return TRUE;
    }

    return FALSE;
}

MMPortType
mm_port_probe_get_port_type (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);

    if (g_str_equal (subsys, "net"))
        return MM_PORT_TYPE_NET;

#if defined WITH_QMI
    if (g_str_has_prefix (subsys, "usb") &&
        g_str_has_prefix (name, "cdc-wdm") &&
        self->priv->is_qmi)
        return MM_PORT_TYPE_QMI;
#endif

#if defined WITH_MBIM
    if (g_str_has_prefix (subsys, "usb") &&
        g_str_has_prefix (name, "cdc-wdm") &&
        self->priv->is_mbim)
        return MM_PORT_TYPE_MBIM;
#endif

    if (self->priv->flags & MM_PORT_PROBE_QCDM &&
        self->priv->is_qcdm)
        return MM_PORT_TYPE_QCDM;

    if (self->priv->flags & MM_PORT_PROBE_AT &&
        self->priv->is_at)
        return MM_PORT_TYPE_AT;

    return MM_PORT_TYPE_UNKNOWN;
}

MMDevice *
mm_port_probe_peek_device (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return self->priv->device;
}

MMDevice *
mm_port_probe_get_device (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return MM_DEVICE (g_object_ref (self->priv->device));
}

MMKernelDevice *
mm_port_probe_peek_port (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return self->priv->port;
};

MMKernelDevice *
mm_port_probe_get_port (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return MM_KERNEL_DEVICE (g_object_ref (self->priv->port));
};

const gchar *
mm_port_probe_get_vendor (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);
    if (g_str_equal (subsys, "net") ||
        (g_str_has_prefix (subsys, "usb") &&
         g_str_has_prefix (name, "cdc-wdm")))
        return NULL;

    return (self->priv->flags & MM_PORT_PROBE_AT_VENDOR ?
            self->priv->vendor :
            NULL);
}

const gchar *
mm_port_probe_get_product (MMPortProbe *self)
{
    const gchar *subsys;
    const gchar *name;

    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    subsys = mm_kernel_device_get_subsystem (self->priv->port);
    name = mm_kernel_device_get_name (self->priv->port);
    if (g_str_equal (subsys, "net") ||
        (g_str_has_prefix (subsys, "usb") &&
         g_str_has_prefix (name, "cdc-wdm")))
        return NULL;

    return (self->priv->flags & MM_PORT_PROBE_AT_PRODUCT ?
            self->priv->product :
            NULL);
}

gboolean
mm_port_probe_is_icera (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    if (g_str_equal (mm_kernel_device_get_subsystem (self->priv->port), "net"))
        return FALSE;

    return (self->priv->flags & MM_PORT_PROBE_AT_ICERA ?
            self->priv->is_icera :
            FALSE);
}

gboolean
mm_port_probe_list_is_icera (GList *probes)
{
    GList *l;

    for (l = probes; l; l = g_list_next (l)) {
        if (mm_port_probe_is_icera (MM_PORT_PROBE (l->data)))
            return TRUE;
    }

    return FALSE;
}

gboolean
mm_port_probe_is_ignored (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), FALSE);

    return self->priv->is_ignored;
}

const gchar *
mm_port_probe_get_port_name (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return mm_kernel_device_get_name (self->priv->port);
}

const gchar *
mm_port_probe_get_port_subsys (MMPortProbe *self)
{
    g_return_val_if_fail (MM_IS_PORT_PROBE (self), NULL);

    return mm_kernel_device_get_subsystem (self->priv->port);
}

/*****************************************************************************/

MMPortProbe *
mm_port_probe_new (MMDevice       *device,
                   MMKernelDevice *port)
{
    return MM_PORT_PROBE (g_object_new (MM_TYPE_PORT_PROBE,
                                        MM_PORT_PROBE_DEVICE, device,
                                        MM_PORT_PROBE_PORT,   port,
                                        NULL));
}

static void
mm_port_probe_init (MMPortProbe *self)
{
    self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self,
                                              MM_TYPE_PORT_PROBE,
                                              MMPortProbePrivate);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
    MMPortProbe *self = MM_PORT_PROBE (object);

    switch (prop_id) {
    case PROP_DEVICE:
        /* construct only, no new reference! */
        self->priv->device = g_value_get_object (value);
        break;
    case PROP_PORT:
        /* construct only */
        self->priv->port = g_value_dup_object (value);
        self->priv->is_ignored = mm_kernel_device_get_property_as_boolean (self->priv->port, "ID_MM_PORT_IGNORE");
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
    MMPortProbe *self = MM_PORT_PROBE (object);

    switch (prop_id) {
    case PROP_DEVICE:
        g_value_set_object (value, self->priv->device);
        break;
    case PROP_PORT:
        g_value_set_object (value, self->priv->port);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static void
finalize (GObject *object)
{
    MMPortProbe *self = MM_PORT_PROBE (object);

    /* We should never have a task here */
    g_assert (self->priv->task == NULL);

    g_free (self->priv->vendor);
    g_free (self->priv->product);

    G_OBJECT_CLASS (mm_port_probe_parent_class)->finalize (object);
}

static void
dispose (GObject *object)
{
    MMPortProbe *self = MM_PORT_PROBE (object);

    /* We didn't get a reference to the device */
    self->priv->device = NULL;

    g_clear_object (&self->priv->port);

    G_OBJECT_CLASS (mm_port_probe_parent_class)->dispose (object);
}

static void
mm_port_probe_class_init (MMPortProbeClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MMPortProbePrivate));

    /* Virtual methods */
    object_class->get_property = get_property;
    object_class->set_property = set_property;
    object_class->finalize = finalize;
    object_class->dispose = dispose;

    properties[PROP_DEVICE] =
        g_param_spec_object (MM_PORT_PROBE_DEVICE,
                             "Device",
                             "Device owning this probe",
                             MM_TYPE_DEVICE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_DEVICE, properties[PROP_DEVICE]);

    properties[PROP_PORT] =
        g_param_spec_object (MM_PORT_PROBE_PORT,
                             "Port",
                             "kernel device object of the port",
                             MM_TYPE_KERNEL_DEVICE,
                             G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY);
    g_object_class_install_property (object_class, PROP_PORT, properties[PROP_PORT]);
}
