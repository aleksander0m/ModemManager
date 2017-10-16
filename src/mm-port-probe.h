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
 * Copyright (C) 2011 Aleksander Morgado <aleksander@gnu.org>
 */

#ifndef MM_PORT_PROBE_H
#define MM_PORT_PROBE_H

#include "config.h"

#include <glib.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "mm-private-boxed-types.h"
#include "mm-port-probe-at.h"
#include "mm-port-serial-at.h"
#include "mm-kernel-device.h"
#include "mm-device.h"

#define MM_TYPE_PORT_PROBE            (mm_port_probe_get_type ())
#define MM_PORT_PROBE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_PORT_PROBE, MMPortProbe))
#define MM_PORT_PROBE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MM_TYPE_PORT_PROBE, MMPortProbeClass))
#define MM_IS_PORT_PROBE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_PORT_PROBE))
#define MM_IS_PORT_PROBE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  MM_TYPE_PORT_PROBE))
#define MM_PORT_PROBE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MM_TYPE_PORT_PROBE, MMPortProbeClass))

/* Flags to request port probing */
typedef enum { /*< underscore_name=mm_port_probe_flag >*/
    MM_PORT_PROBE_NONE       = 0,
    MM_PORT_PROBE_AT         = 1 << 0,
    MM_PORT_PROBE_AT_VENDOR  = 1 << 1,
    MM_PORT_PROBE_AT_PRODUCT = 1 << 2,
    MM_PORT_PROBE_AT_ICERA   = 1 << 3,
    MM_PORT_PROBE_QCDM       = 1 << 4,
    MM_PORT_PROBE_QMI        = 1 << 5,
    MM_PORT_PROBE_MBIM       = 1 << 6
} MMPortProbeFlag;

typedef struct _MMPortProbe MMPortProbe;
typedef struct _MMPortProbeClass MMPortProbeClass;
typedef struct _MMPortProbePrivate MMPortProbePrivate;

#define MM_PORT_PROBE_DEVICE "device"
#define MM_PORT_PROBE_PORT   "port"

struct _MMPortProbe {
    GObject parent;
    MMPortProbePrivate *priv;
};

struct _MMPortProbeClass {
    GObjectClass parent;
};

/* Custom AT probing initialization setup.
 * Plugins can use this to configure how AT ports need to get initialized.
 * It also helps to implement plugin-specific checks, as plugins can set
 * their own probing results on the 'probe' object. */
typedef void     (* MMPortProbeAtCustomInit)       (MMPortProbe *probe,
                                                    MMPortSerialAt *port,
                                                    GCancellable *cancellable,
                                                    GAsyncReadyCallback callback,
                                                    gpointer user_data);
typedef gboolean (* MMPortProbeAtCustomInitFinish) (MMPortProbe *probe,
                                                    GAsyncResult *result,
                                                    GError **error);

GType mm_port_probe_get_type (void);

MMPortProbe *mm_port_probe_new (MMDevice       *device,
                                MMKernelDevice *port);

MMDevice       *mm_port_probe_peek_device     (MMPortProbe *self);
MMDevice       *mm_port_probe_get_device      (MMPortProbe *self);
MMKernelDevice *mm_port_probe_peek_port       (MMPortProbe *self);
MMKernelDevice *mm_port_probe_get_port        (MMPortProbe *self);
const gchar    *mm_port_probe_get_port_name   (MMPortProbe *self);
const gchar    *mm_port_probe_get_port_subsys (MMPortProbe *self);

/* Probing result setters */
void mm_port_probe_set_result_at         (MMPortProbe *self,
                                          gboolean at);
void mm_port_probe_set_result_at_vendor  (MMPortProbe *self,
                                          const gchar *at_vendor);
void mm_port_probe_set_result_at_product (MMPortProbe *self,
                                          const gchar *at_product);
void mm_port_probe_set_result_at_icera   (MMPortProbe *self,
                                          gboolean is_icera);
void mm_port_probe_set_result_qcdm       (MMPortProbe *self,
                                          gboolean qcdm);
void mm_port_probe_set_result_qmi        (MMPortProbe *self,
                                          gboolean qmi);
void mm_port_probe_set_result_mbim       (MMPortProbe *self,
                                          gboolean mbim);

/* Run probing */
void     mm_port_probe_run        (MMPortProbe *self,
                                   MMPortProbeFlag flags,
                                   guint64 at_send_delay,
                                   gboolean at_remove_echo,
                                   gboolean at_send_lf,
                                   const MMPortProbeAtCommand *at_custom_probe,
                                   const MMAsyncMethod *at_custom_init,
                                   GCancellable *cancellable,
                                   GAsyncReadyCallback callback,
                                   gpointer user_data);
gboolean mm_port_probe_run_finish (MMPortProbe *self,
                                   GAsyncResult *result,
                                   GError **error);

gboolean mm_port_probe_run_cancel_at_probing (MMPortProbe *self);

/* Probing result getters */
MMPortType    mm_port_probe_get_port_type    (MMPortProbe *self);
gboolean      mm_port_probe_is_at            (MMPortProbe *self);
gboolean      mm_port_probe_is_qcdm          (MMPortProbe *self);
gboolean      mm_port_probe_is_qmi           (MMPortProbe *self);
gboolean      mm_port_probe_is_mbim          (MMPortProbe *self);
const gchar  *mm_port_probe_get_vendor       (MMPortProbe *self);
const gchar  *mm_port_probe_get_product      (MMPortProbe *self);
gboolean      mm_port_probe_is_icera         (MMPortProbe *self);
gboolean      mm_port_probe_is_ignored       (MMPortProbe *self);

/* Additional helpers */
gboolean mm_port_probe_list_has_at_port   (GList *list);
gboolean mm_port_probe_list_has_qmi_port  (GList *list);
gboolean mm_port_probe_list_has_mbim_port (GList *list);
gboolean mm_port_probe_list_is_icera      (GList *list);

#endif /* MM_PORT_PROBE_H */
