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

#ifndef MM_PLUGIN_MANAGER_H
#define MM_PLUGIN_MANAGER_H

#include <glib-object.h>

#include "mm-device.h"
#include "mm-plugin.h"
#include "mm-filter.h"
#include "mm-base-modem.h"

#define MM_TYPE_PLUGIN_MANAGER            (mm_plugin_manager_get_type ())
#define MM_PLUGIN_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MM_TYPE_PLUGIN_MANAGER, MMPluginManager))
#define MM_PLUGIN_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), MM_TYPE_PLUGIN_MANAGER, MMPluginManagerClass))
#define MM_IS_PLUGIN_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), MM_TYPE_PLUGIN_MANAGER))
#define MM_IS_PLUGIN_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), MM_TYPE_PLUGIN_MANAGER))
#define MM_PLUGIN_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), MM_TYPE_PLUGIN_MANAGER, MMPluginManagerClass))

#define MM_PLUGIN_MANAGER_PLUGIN_DIR "plugin-dir" /* Construct-only */
#define MM_PLUGIN_MANAGER_FILTER     "filter"     /* Construct-only */

typedef struct _MMPluginManager MMPluginManager;
typedef struct _MMPluginManagerClass MMPluginManagerClass;
typedef struct _MMPluginManagerPrivate MMPluginManagerPrivate;

struct _MMPluginManager {
    GObject parent;
    MMPluginManagerPrivate *priv;
};

struct _MMPluginManagerClass {
    GObjectClass parent;
};

GType            mm_plugin_manager_get_type (void);
MMPluginManager *mm_plugin_manager_new                         (const gchar          *plugindir,
                                                                MMFilter             *filter,
                                                                GError              **error);
void             mm_plugin_manager_device_support_check        (MMPluginManager      *self,
                                                                MMDevice             *device,
                                                                GAsyncReadyCallback   callback,
                                                                gpointer              user_data);
gboolean         mm_plugin_manager_device_support_check_cancel (MMPluginManager      *self,
                                                                MMDevice             *device);
MMPlugin *       mm_plugin_manager_device_support_check_finish (MMPluginManager      *self,
                                                                GAsyncResult         *res,
                                                                GError              **error);
MMPlugin        *mm_plugin_manager_peek_plugin                 (MMPluginManager      *self,
                                                                const gchar          *plugin_name);

#endif /* MM_PLUGIN_MANAGER_H */
