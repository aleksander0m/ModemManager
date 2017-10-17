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
 * Copyright (C) 2009 - 2012 Red Hat, Inc.
 * Copyright (C) 2011 - 2012 Aleksander Morgado <aleksander@gnu.org>
 * Copyright (C) 2012 Google, Inc.
 */

#include <string.h>
#include <ctype.h>

#include <gmodule.h>
#include <gio/gio.h>

#include <ModemManager.h>
#include <mm-errors-types.h>

#include "mm-plugin-manager.h"
#include "mm-plugin.h"
#include "mm-log.h"

static void initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_EXTENDED (MMPluginManager, mm_plugin_manager, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                               initable_iface_init))

enum {
    PROP_0,
    PROP_PLUGIN_DIR,
    PROP_FILTER,
    LAST_PROP
};

struct _MMPluginManagerPrivate {
    /* Path to look for plugins */
    gchar *plugin_dir;
    /* Device filter */
    MMFilter *filter;

    /* This list contains all plugins except for the generic one, order is not
     * important. It is loaded once when the program starts, and the list is NOT
     * expected to change after that.*/
    GList *plugins;
    /* Last, the generic plugin. */
    MMPlugin *generic;

    /* List of ongoing device support checks */
    GList *device_contexts;
};

/*****************************************************************************/
/* Build plugin list for a single port */

static GList *
plugin_manager_build_plugins_list (MMPluginManager *self,
                                   MMDevice        *device,
                                   MMKernelDevice  *port)
{
    GList *list = NULL;
    GList *l;
    gboolean supported_found = FALSE;

    for (l = self->priv->plugins; l && !supported_found; l = g_list_next (l)) {
        MMPluginSupportsHint hint;

        hint = mm_plugin_discard_port_early (MM_PLUGIN (l->data), device, port);
        switch (hint) {
        case MM_PLUGIN_SUPPORTS_HINT_UNSUPPORTED:
            /* Fully discard */
            break;
        case MM_PLUGIN_SUPPORTS_HINT_MAYBE:
            /* Maybe supported, add to tail of list */
            list = g_list_append (list, g_object_ref (l->data));
            break;
        case MM_PLUGIN_SUPPORTS_HINT_LIKELY:
            /* Likely supported, add to head of list */
            list = g_list_prepend (list, g_object_ref (l->data));
            break;
        case MM_PLUGIN_SUPPORTS_HINT_SUPPORTED:
            /* Really supported, clean existing list and add it alone */
            if (list) {
                g_list_free_full (list, g_object_unref);
                list = NULL;
            }
            list = g_list_prepend (list, g_object_ref (l->data));
            /* This will end the loop as well */
            supported_found = TRUE;
            break;
        default:
            g_assert_not_reached ();
        }
    }

    /* Add the generic plugin at the end of the list */
    if (self->priv->generic)
        list = g_list_append (list, g_object_ref (self->priv->generic));

    return list;
}

/*****************************************************************************/
/* Common context for async operations
 *
 * The DeviceContext and PortContext structs are not proper objects, and that
 * means that they cannot be given as core parameter of GIO async results.
 * Instead, we'll use the MMPluginManager as that core parameter always, and
 * we'll pass along a common context with all the remaining details as user
 * data.
 */

typedef struct _DeviceContext DeviceContext;
typedef struct _PortContext   PortContext;

static DeviceContext *device_context_ref   (DeviceContext *device_context);
static void           device_context_unref (DeviceContext *device_context);
static PortContext   *port_context_ref     (PortContext   *port_context);
static void           port_context_unref   (PortContext   *port_context);

typedef struct {
    MMPluginManager *self;
    DeviceContext   *device_context;
    PortContext     *port_context;
    GTask           *task;
} CommonAsyncContext;

static void
common_async_context_free (CommonAsyncContext *common)
{
    if (common->port_context)
        port_context_unref (common->port_context);
    if (common->device_context)
        device_context_unref (common->device_context);
    if (common->self)
        g_object_unref (common->self);
    if (common->task)
        g_object_unref (common->task);
    g_slice_free (CommonAsyncContext, common);
}

static CommonAsyncContext *
common_async_context_new (MMPluginManager *self,
                          DeviceContext   *device_context,
                          PortContext     *port_context,
                          GTask           *task)
{
    CommonAsyncContext *common;

    common = g_slice_new0 (CommonAsyncContext);
    common->self           = (self           ? g_object_ref       (self)           : NULL);
    common->device_context = (device_context ? device_context_ref (device_context) : NULL);
    common->port_context   = (port_context   ? port_context_ref   (port_context)   : NULL);
    common->task           = (task           ? g_object_ref       (task)           : NULL);
    return common;
}

/*****************************************************************************/
/* Port context */

/* Default time to defer probing checks */
#define DEFER_TIMEOUT_SECS 3

/*
 * Port context
 *
 * This structure hold all the probing information related to a single port.
 */
struct _PortContext {
    /* Reference counting */
    volatile gint ref_count;
    /* The name of the context */
    gchar *name;
    /* The device where the port is*/
    MMDevice *device;
    /* The reported kernel port object */
    MMKernelDevice *port;

    /* The operation task */
    GTask *task;
    /* Internal ancellable */
    GCancellable *cancellable;

    /* Timer tracking how much time is required for the port support check */
    GTimer *timer;

    /* This list contains all the plugins that have to be tested with a given
     * port. The list is created once when the task is started, and is never
     * modified afterwards. */
    GList *plugins;
    /* This is the current plugin being tested. If NULL, there are no more
     * plugins to try. */
    GList *current;
    /* A best plugin has been found for this port. */
    MMPlugin *best_plugin;
    /* A plugin was suggested for this port. */
    MMPlugin *suggested_plugin;

    /* The probe has been deferred */
    guint defer_id;
    /* The probe must be deferred until a result is suggested by other
     * port probe results (e.g. for WWAN ports). */
    gboolean defer_until_suggested;
};

static void
port_context_unref (PortContext *port_context)
{
    if (g_atomic_int_dec_and_test (&port_context->ref_count)) {
        /* There must never be a deferred task scheduled for this port */
        g_assert (port_context->defer_id == 0);

        /* The port support check task must have been completed previously */
        g_assert (!port_context->task);

        if (port_context->best_plugin)
            g_object_unref (port_context->best_plugin);
        if (port_context->suggested_plugin)
            g_object_unref (port_context->suggested_plugin);
        if (port_context->plugins)
            g_list_free_full (port_context->plugins, g_object_unref);
        if (port_context->cancellable)
            g_object_unref (port_context->cancellable);
        g_free (port_context->name);
        g_timer_destroy (port_context->timer);
        g_object_unref (port_context->port);
        g_object_unref (port_context->device);
        g_slice_free (PortContext, port_context);
    }
}

static PortContext *
port_context_ref (PortContext *port_context)
{
    g_atomic_int_inc (&port_context->ref_count);
    return port_context;
}

static MMPlugin *
port_context_run_finish (MMPluginManager  *self,
                         GAsyncResult     *res,
                         GError          **error)
{
    return g_task_propagate_pointer (G_TASK (res), error);
}

static void
port_context_complete (PortContext *port_context)
{
    GTask *task;

    /* If already completed, do nothing */
    if (!port_context->task)
        return;

    /* Steal the task from the context, we only will complete once */
    task = port_context->task;
    port_context->task = NULL;

    /* Log about the time required to complete the checks */
    mm_dbg ("[plugin manager] task %s: finished in '%lf' seconds",
            port_context->name, g_timer_elapsed (port_context->timer, NULL));

    if (!port_context->best_plugin)
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED, "Unsupported");
    else
        g_task_return_pointer (task, g_object_ref (port_context->best_plugin), g_object_unref);
    g_object_unref (task);
}

static void port_context_next (PortContext *port_context);

static void
port_context_supported (PortContext *port_context,
                        MMPlugin    *plugin)
{
    g_assert (plugin);

    mm_dbg ("[plugin manager] task %s: found best plugin for port (%s)",
            port_context->name, mm_plugin_get_name (plugin));

    /* Found a best plugin, store it to return it */
    port_context->best_plugin = g_object_ref (plugin);
    port_context_complete (port_context);
}

static gboolean
port_context_defer_ready (PortContext *port_context)
{
    port_context->defer_id = 0;
    port_context_next (port_context);
    return G_SOURCE_REMOVE;
}

static void
port_context_set_suggestion (PortContext *port_context,
                             MMPlugin    *suggested_plugin)
{
    gboolean forbidden_icera;

    /* Plugin suggestions serve two different purposes here:
     *  1) Finish all the probes which were deferred until suggested.
     *  2) Suggest to other probes which plugin to test next.
     *
     * The exception here is when we suggest the GENERIC plugin.
     * In this case, only purpose (1) is applied, this is, only
     * the deferred until suggested probes get finished.
     */

    /* Do nothing if already best plugin found, or if a plugin has already been
     * suggested before */
    if (port_context->best_plugin || port_context->suggested_plugin)
        return;

    /* Complete tasks which were deferred until suggested */
    if (port_context->defer_until_suggested) {
        /* Reset the defer until suggested flag; we consider this
         * cancelled probe completed now. */
        port_context->defer_until_suggested = FALSE;

        if (suggested_plugin) {
            mm_dbg ("[plugin manager] task %s: deferred task completed, got suggested plugin (%s)",
                    port_context->name, mm_plugin_get_name (suggested_plugin));
            /* Advance to the suggested plugin and re-check support there */
            port_context->suggested_plugin = g_object_ref (suggested_plugin);
            port_context->current = g_list_find (port_context->current, port_context->suggested_plugin);
            /* Schedule checking support */
            g_assert (port_context->defer_id == 0);
            port_context->defer_id = g_idle_add ((GSourceFunc) port_context_defer_ready, port_context);
            return;
        }

        mm_dbg ("[plugin manager] task %s: deferred task completed, no suggested plugin",
                port_context->name);
        port_context_complete (port_context);
        return;
    }

    /* If no plugin being suggested, done */
    if (!suggested_plugin)
        return;

    /* The GENERIC plugin is NEVER suggested to others */
    if (g_str_equal (mm_plugin_get_name (suggested_plugin), MM_PLUGIN_GENERIC_NAME))
        return;

    /* If the plugin has MM_PLUGIN_FORBIDDEN_ICERA set, we do *not* suggest
     * the plugin to others. Icera devices may not reply to the icera probing
     * in all ports, so if other ports need to be tested for icera support,
     * they should all go on. */
    g_object_get (suggested_plugin,
                  MM_PLUGIN_FORBIDDEN_ICERA, &forbidden_icera,
                  NULL);
    if (forbidden_icera)
        return;

    /* We should *not* cancel probing in the port if the plugin being
     * checked right now is not the one being suggested. Each port
     * should run its probing independently, and we'll later decide
     * which result applies to the whole device.
     */
    mm_dbg ("[plugin manager] task %s: got suggested plugin (%s)",
            port_context->name, mm_plugin_get_name (suggested_plugin));
    port_context->suggested_plugin = g_object_ref (suggested_plugin);
}

static void
port_context_unsupported (PortContext *port_context,
                          MMPlugin    *plugin)
{
    g_assert (plugin);

    /* If there is no suggested plugin, go on to the next one */
    if (!port_context->suggested_plugin) {
        port_context->current = g_list_next (port_context->current);
        port_context_next (port_context);
        return;
    }

    /* If the plugin that just completed the support check claims
     * not to support this port, but this plugin is clearly the
     * right plugin since it claimed this port's physical modem,
     * just cancel the port probing and avoid more tests.
     */
    if (port_context->suggested_plugin == plugin) {
        mm_dbg ("[plugin manager] task %s: ignoring port unsupported by physical modem's plugin",
                port_context->name);
        port_context_complete (port_context);
        return;
    }

    /* The last plugin we tried is NOT the one we got suggested, so
     * directly check support with the suggested plugin. If we
     * already checked its support, it won't be checked again. */
    port_context->current = g_list_find (port_context->current, port_context->suggested_plugin);
    port_context_next (port_context);
}

static void
port_context_defer (PortContext *port_context)
{
    /* Try with the suggested one after being deferred */
    if (port_context->suggested_plugin) {
        mm_dbg ("[plugin manager] task %s: deferring support check (%s suggested)",
                port_context->name, mm_plugin_get_name (MM_PLUGIN (port_context->suggested_plugin)));
        port_context->current = g_list_find (port_context->current, port_context->suggested_plugin);
    } else
        mm_dbg ("[plugin manager] task %s: deferring support check",
                port_context->name);

    /* Schedule checking support.
     *
     * In this case we don't pass a port context reference because we're able
     * to fully cancel the timeout ourselves. */
    port_context->defer_id = g_timeout_add_seconds (DEFER_TIMEOUT_SECS,
                                                    (GSourceFunc) port_context_defer_ready,
                                                    port_context);
}

static void
port_context_defer_until_suggested (PortContext *port_context,
                                    MMPlugin    *plugin)
{
    g_assert (plugin);

    /* If we arrived here and we already have a plugin suggested, use it */
    if (port_context->suggested_plugin) {
        /* We can finish this context */
        if (port_context->suggested_plugin == plugin) {
            mm_dbg ("[plugin manager] task %s: completed, got suggested plugin (%s)",
                    port_context->name, mm_plugin_get_name (port_context->suggested_plugin));
            /* Store best plugin and end operation */
            port_context->best_plugin = g_object_ref (port_context->suggested_plugin);
            port_context_complete (port_context);
            return;
        }

        /* Recheck support in deferred task */
        mm_dbg ("[plugin manager] task %s: re-checking support on deferred task, got suggested plugin (%s)",
                port_context->name, mm_plugin_get_name (port_context->suggested_plugin));
        port_context->current = g_list_find (port_context->current, port_context->suggested_plugin);
        port_context_next (port_context);
        return;
    }

    /* We are deferred until a suggested plugin is given. If last supports task
     * of a given device is finished without finding a best plugin, this task
     * will get finished reporting unsupported. */
    mm_dbg ("[plugin manager] task %s: deferring support check until result suggested",
            port_context->name);
    port_context->defer_until_suggested = TRUE;
}

static void
plugin_supports_port_ready (MMPlugin     *plugin,
                            GAsyncResult *res,
                            PortContext  *port_context)
{
    MMPluginSupportsResult  support_result;
    GError                 *error = NULL;

    /* Get supports check results */
    support_result = mm_plugin_supports_port_finish (plugin, res, &error);
    if (error) {
        g_assert_cmpuint (support_result, ==, MM_PLUGIN_SUPPORTS_PORT_UNKNOWN);
        mm_warn ("[plugin manager] task %s: error when checking support with plugin '%s': '%s'",
                 port_context->name, mm_plugin_get_name (plugin), error->message);
        g_error_free (error);
    }

    switch (support_result) {
    case MM_PLUGIN_SUPPORTS_PORT_SUPPORTED:
        port_context_supported (port_context, plugin);
        break;
    case MM_PLUGIN_SUPPORTS_PORT_UNKNOWN:
    case MM_PLUGIN_SUPPORTS_PORT_UNSUPPORTED:
        port_context_unsupported (port_context, plugin);
        break;
    case MM_PLUGIN_SUPPORTS_PORT_DEFER:
        port_context_defer (port_context);
        break;
    case MM_PLUGIN_SUPPORTS_PORT_DEFER_UNTIL_SUGGESTED:
        port_context_defer_until_suggested (port_context, plugin);
        break;
    }

    /* We received a full reference, to make sure the context was always
     * valid during the async call */
    port_context_unref (port_context);
}

static void
port_context_next (PortContext *port_context)
{
    MMPlugin *plugin;

    /* If we're cancelled, done */
    if (g_cancellable_is_cancelled (port_context->cancellable)) {
        port_context_complete (port_context);
        return;
    }

    /* Already checked all plugins? */
    if (!port_context->current) {
        port_context_complete (port_context);
        return;
    }

    /* Ask the current plugin to check support of this port.
     *
     * A full new reference to the port context is given as user data to the
     * async method because we want to make sure the context is still valid
     * once the method finishes. */
    plugin = MM_PLUGIN (port_context->current->data);
    mm_dbg ("[plugin manager] task %s: checking with plugin '%s'",
            port_context->name, mm_plugin_get_name (plugin));
    mm_plugin_supports_port (plugin,
                             port_context->device,
                             port_context->port,
                             port_context->cancellable,
                             (GAsyncReadyCallback) plugin_supports_port_ready,
                             port_context_ref (port_context));
}

static gboolean
port_context_cancel (PortContext *port_context)
{
    /* Port context cancellation, which only makes sense if the context is
     * actually being run, so just exit if it isn't. */
    if (!port_context->task)
        return FALSE;

    /* If cancelled already, do nothing */
    if (g_cancellable_is_cancelled (port_context->cancellable))
        return FALSE;

    mm_dbg ("[plugin manager) task %s: cancellation requested",
            port_context->name);

    /* Make sure we hold a port context reference while cancelling, as the
     * cancellable signal handlers may end up unref-ing our last reference
     * otherwise. */
    port_context_ref (port_context);
    {
        /* The port context is cancelled now */
        g_cancellable_cancel (port_context->cancellable);

        /* If the task was deferred, we can cancel and complete it right away */
        if (port_context->defer_id) {
            g_source_remove (port_context->defer_id);
            port_context->defer_id = 0;
            port_context_complete (port_context);
        }
        /* If the task was deferred until a result is suggested, we can also
         * complete it right away */
        else if (port_context->defer_until_suggested)
            port_context_complete (port_context);
        /* else, the task may be currently checking support with a given plugin */
    }
    port_context_unref (port_context);

    return TRUE;
}

static void
port_context_run (MMPluginManager     *self,
                  PortContext         *port_context,
                  GList               *plugins,
                  MMPlugin            *suggested,
                  GAsyncReadyCallback  callback,
                  gpointer             user_data)
{
    g_assert (!port_context->task);
    g_assert (!port_context->defer_id);
    g_assert (!port_context->plugins);
    g_assert (!port_context->current);
    g_assert (!port_context->suggested_plugin);

    /* Setup plugins to probe and first one to check. */
    port_context->plugins = g_list_copy_deep (plugins, (GCopyFunc) g_object_ref, NULL);
    port_context->current = port_context->plugins;

    /* If we got one suggested, it will be the first one */
    if (suggested) {
        port_context->suggested_plugin = g_object_ref (suggested);
        port_context->current = g_list_find (port_context->current, port_context->suggested_plugin);
        if (!port_context->current)
            mm_warn ("[plugin manager] task %s: suggested plugin (%s) not among the ones to test",
                     port_context->name, mm_plugin_get_name (suggested));
    }

    /* Log the list of plugins found and specify which are the ones that are going
     * to be run */
    {
        gboolean  suggested_found = FALSE;
        GList    *l;

        mm_dbg ("[plugin manager] task %s: found '%u' plugins to try",
                port_context->name, g_list_length (port_context->plugins));

        for (l = port_context->plugins; l; l = g_list_next (l)) {
            MMPlugin *plugin;

            plugin = MM_PLUGIN (l->data);
            if (suggested_found) {
                mm_dbg ("[plugin manager] task %s: may try with plugin '%s'",
                        port_context->name, mm_plugin_get_name (plugin));
                continue;
            }
            if (suggested && l == port_context->current) {
                suggested_found = TRUE;
                mm_dbg ("[plugin manager] task %s: will try with plugin '%s' (suggested)",
                        port_context->name, mm_plugin_get_name (plugin));
                continue;
            }
            if (suggested && !suggested_found) {
                mm_dbg ("[plugin manager] task %s: won't try with plugin '%s' (skipped)",
                        port_context->name, mm_plugin_get_name (plugin));
                continue;
            }
            mm_dbg ("[plugin manager] task %s: will try with plugin '%s'",
                    port_context->name, mm_plugin_get_name (plugin));
        }
    }

    /* The full port context is now cancellable. We pass this cancellable also
     * to the inner GTask, so that if we're cancelled we always return a
     * cancellation error, regardless of what the standard logic does. */
    port_context->cancellable = g_cancellable_new ();

    /* Create a inner task for the port context. The result we expect is the
     * best plugin found for the port. */
    port_context->task = g_task_new (self, port_context->cancellable, callback, user_data);

    mm_dbg ("[plugin manager) task %s: started", port_context->name);

    /* Go probe with the first plugin */
    port_context_next (port_context);
}

static PortContext *
port_context_new (MMPluginManager *self,
                  const gchar     *parent_name,
                  MMDevice        *device,
                  MMKernelDevice  *port)
{
    PortContext *port_context;

    port_context            = g_slice_new0 (PortContext);
    port_context->ref_count = 1;
    port_context->device    = g_object_ref (device);
    port_context->port      = g_object_ref (port);
    port_context->timer     = g_timer_new ();

    /* Set context name */
    port_context->name = g_strdup_printf ("%s,%s", parent_name, mm_kernel_device_get_name (port));

    return port_context;
}

/*****************************************************************************/
/* Device context */

/* Time to wait for ports to appear before starting to probe the first one */
#define MIN_WAIT_TIME_MSECS 1500

/* Time to wait for other ports to appear once the first port is exposed
 * (needs to be > MIN_WAIT_TIME_MSECS!!) */
#define MIN_PROBING_TIME_MSECS 2500

/* The wait time we define must always be less than the probing time */
G_STATIC_ASSERT (MIN_WAIT_TIME_MSECS < MIN_PROBING_TIME_MSECS);

/*
 * Device context
 *
 * This structure holds all the information related to a single device. This
 * information includes references to all port contexts generated in the device,
 * as well as a reference to the parent plugin manager object and the async
 * task to complete when finished.
 */
struct _DeviceContext {
    /* Reference counting */
    volatile gint ref_count;
    /* The name of the context */
    gchar *name;
    /* The plugin manager */
    MMPluginManager *self;
    /* The device for which we're looking support */
    MMDevice *device;

    /* The operation task */
    GTask *task;
    /* Internal ancellable */
    GCancellable *cancellable;

    /* Timer tracking how much time is required for the device support check */
    GTimer *timer;

    /* The best plugin at a given moment. Once the last port task finishes, this
     * will be the one being returned in the async result */
    MMPlugin *best_plugin;

    /* Minimum wait time. No port probing can start before this timeout expires.
     * Once the timeout is expired, the id is reset to 0. */
    guint min_wait_time_id;
    /* Port support check contexts waiting to be run after min wait time */
    GList *wait_port_contexts;

    /* Minimum probing_time. The device support check task cannot be finished
     * before this timeout expires. Once the timeout is expired, the id is reset
     * to 0. */
    guint min_probing_time_id;

    /* Signal connection ids for the grabbed/released signals from the device.
     * These are the signals that will give us notifications of what ports are
     * available (or suddenly unavailable) in the device. */
    gulong grabbed_id;
    gulong released_id;

    /* Port support check contexts being run */
    GList *port_contexts;
};

static void
device_context_unref (DeviceContext *device_context)
{
    if (g_atomic_int_dec_and_test (&device_context->ref_count)) {
        /* When the last reference is gone there must be no source scheduled and no
         * pending port tasks. */
        g_assert (!device_context->grabbed_id);
        g_assert (!device_context->released_id);
        g_assert (!device_context->min_wait_time_id);
        g_assert (!device_context->min_probing_time_id);
        g_assert (!device_context->port_contexts);

        /* The device support check task must have been completed previously */
        g_assert (!device_context->task);

        g_free (device_context->name);
        g_timer_destroy (device_context->timer);
        if (device_context->cancellable)
            g_object_unref (device_context->cancellable);
        if (device_context->best_plugin)
            g_object_unref (device_context->best_plugin);
        g_object_unref (device_context->device);
        g_object_unref (device_context->self);
        g_slice_free (DeviceContext, device_context);
    }
}

static DeviceContext *
device_context_ref (DeviceContext *device_context)
{
    g_atomic_int_inc (&device_context->ref_count);
    return device_context;
}

static PortContext *
device_context_peek_running_port_context (DeviceContext  *device_context,
                                          MMKernelDevice *port)
{
    GList *l;

    for (l = device_context->port_contexts; l; l = g_list_next (l)) {
        PortContext *port_context;

        port_context = (PortContext *)(l->data);
        if ((port_context->port == port) ||
            (!g_strcmp0 (mm_kernel_device_get_name (port_context->port), mm_kernel_device_get_name (port))))
            return port_context;
    }
    return NULL;
}

static PortContext *
device_context_peek_waiting_port_context (DeviceContext  *device_context,
                                          MMKernelDevice *port)
{
    GList *l;

    for (l = device_context->wait_port_contexts; l; l = g_list_next (l)) {
        PortContext *port_context;

        port_context = (PortContext *)(l->data);
        if ((port_context->port == port) ||
            (!g_strcmp0 (mm_kernel_device_get_name (port_context->port), mm_kernel_device_get_name (port))))
            return port_context;
    }
    return NULL;
}

static MMPlugin *
device_context_run_finish (MMPluginManager  *self,
                           GAsyncResult     *res,
                           GError          **error)
{
    return MM_PLUGIN (g_task_propagate_pointer (G_TASK (res), error));
}

static void
device_context_complete (DeviceContext *device_context)
{
    GTask *task;

    /* Steal the task from the context */
    g_assert (device_context->task);
    task = device_context->task;
    device_context->task = NULL;

    /* Log about the time required to complete the checks */
    mm_dbg ("[plugin manager] task %s: finished in '%lf' seconds",
            device_context->name, g_timer_elapsed (device_context->timer, NULL));

    /* Remove signal handlers */
    if (device_context->grabbed_id) {
        g_signal_handler_disconnect (device_context->device, device_context->grabbed_id);
        device_context->grabbed_id = 0;
    }
    if (device_context->released_id) {
        g_signal_handler_disconnect (device_context->device, device_context->released_id);
        device_context->released_id = 0;
    }

    /* Remove timeouts, if still around */
    if (device_context->min_wait_time_id) {
        g_source_remove (device_context->min_wait_time_id);
        device_context->min_wait_time_id = 0;
    }
    if (device_context->min_probing_time_id) {
        g_source_remove (device_context->min_probing_time_id);
        device_context->min_probing_time_id = 0;
    }

    /* Task completion */
    if (!device_context->best_plugin)
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED,
                                 "not supported by any plugin");
    else
        g_task_return_pointer (task, g_object_ref (device_context->best_plugin), g_object_unref);
    g_object_unref (task);
}

static void
device_context_suggest_plugin (DeviceContext *device_context,
                               PortContext   *port_context,
                               MMPlugin      *suggested_plugin)
{
    GList *l;
    GList *listdup;

    /* If the suggested plugin is NULL, we'll propagate the suggestion only if all
     * the port contexts are deferred until suggested. */
    if (!suggested_plugin) {
        for (l = device_context->port_contexts; l; l = g_list_next (l)) {
            PortContext *other_port_context = (PortContext *)(l->data);

            /* Do not propagate NULL if we find at least one probe which is not
             * waiting for the suggested plugin */
            if (other_port_context != port_context && !other_port_context->defer_until_suggested)
                return;
        }
    }

    /* Do the suggestion propagation.
     * Shallow copy, just so that we can iterate safely without worrying about the
     * original list being modified while hte completions happen */
    listdup = g_list_copy (device_context->port_contexts);
    for (l = listdup; l; l = g_list_next (l))
        port_context_set_suggestion ((PortContext *)(l->data), suggested_plugin);
    g_list_free (listdup);
}

static void
device_context_set_best_plugin (DeviceContext *device_context,
                                PortContext   *port_context,
                                MMPlugin      *best_plugin)
{
    if (!best_plugin) {
        /* If the port appeared after an already probed port, which decided that
         * the Generic plugin was the best one (which is by default not initially
         * suggested), we'll end up arriving here. Don't ignore it, it may well
         * be a wwan port that we do need to grab. */
        if (device_context->best_plugin) {
            mm_dbg ("[plugin manager] task %s: assuming port can be handled by the '%s' plugin",
                    port_context->name, mm_plugin_get_name (device_context->best_plugin));
            return;
        }

        /* Unsupported error, this is generic when we cannot find a plugin */
        mm_dbg ("[plugin manager] task %s: not supported by any plugin" ,
                port_context->name);

        /* Tell the device to ignore this port */
        mm_device_ignore_port (device_context->device, port_context->port);

        /* If this is the last valid probe which was running (i.e. the last one
         * not being deferred-until-suggested), cancel all remaining ones. */
        device_context_suggest_plugin (device_context, port_context, NULL);
        return;
    }

    /* Store the plugin as the best one in the device if this is the first
     * result we got. Also, if the previously suggested plugin was the GENERIC
     * one and now we're reporting a more specific one, use the new one.
     */
    if (!device_context->best_plugin ||
        (g_str_equal (mm_plugin_get_name (device_context->best_plugin), MM_PLUGIN_GENERIC_NAME) &&
         device_context->best_plugin != best_plugin)) {
        /* Only log best plugin if it's not the generic one */
        if (!g_str_equal (mm_plugin_get_name (best_plugin), MM_PLUGIN_GENERIC_NAME))
            mm_dbg ("[plugin manager] task %s: found best plugin: %s",
                    port_context->name, mm_plugin_get_name (best_plugin));
        /* Store and suggest this plugin also to other port probes */
        device_context->best_plugin = g_object_ref (best_plugin);
        device_context_suggest_plugin (device_context, port_context, best_plugin);
        return;
    }

    /* Warn if the best plugin found for this port differs from the
     * best plugin found for the the first probed port */
    if (!g_str_equal (mm_plugin_get_name (device_context->best_plugin), mm_plugin_get_name (best_plugin))) {
        /* Icera modems may not reply to the icera probing in all ports. We handle this by
         * checking the forbidden/allowed icera flags in both the current and the expected
         * plugins. If either of these plugins requires icera and the other doesn't, we
         * pick the Icera one as best plugin. */
        gboolean previous_forbidden_icera;
        gboolean previous_allowed_icera;
        gboolean new_forbidden_icera;
        gboolean new_allowed_icera;

        g_object_get (device_context->best_plugin,
                      MM_PLUGIN_ALLOWED_ICERA,   &previous_allowed_icera,
                      MM_PLUGIN_FORBIDDEN_ICERA, &previous_forbidden_icera,
                      NULL);
        g_assert (previous_allowed_icera == FALSE || previous_forbidden_icera == FALSE);

        g_object_get (best_plugin,
                      MM_PLUGIN_ALLOWED_ICERA,   &new_allowed_icera,
                      MM_PLUGIN_FORBIDDEN_ICERA, &new_forbidden_icera,
                      NULL);
        g_assert (new_allowed_icera == FALSE || new_forbidden_icera == FALSE);

        if (previous_allowed_icera && new_forbidden_icera)
            mm_warn ("[plugin manager] task %s: will use plugin '%s' instead of '%s', modem is icera-capable",
                     port_context->name,
                     mm_plugin_get_name (device_context->best_plugin),
                     mm_plugin_get_name (best_plugin));
        else if (new_allowed_icera && previous_forbidden_icera) {
            mm_warn ("[plugin manager] task %s: overriding previously selected device plugin '%s' with '%s', modem is icera-capable",
                     port_context->name,
                     mm_plugin_get_name (device_context->best_plugin),
                     mm_plugin_get_name (best_plugin));
            g_object_unref (device_context->best_plugin);
            device_context->best_plugin = g_object_ref (best_plugin);
        } else
            mm_warn ("[plugin manager] task %s: plugin mismatch error (device reports '%s', port reports '%s')",
                     port_context->name,
                     mm_plugin_get_name (device_context->best_plugin),
                     mm_plugin_get_name (best_plugin));
        return;
    }

    /* Device plugin equal to best plugin */
    mm_dbg ("[plugin manager] task %s: best plugin matches device reported one: %s",
            port_context->name, mm_plugin_get_name (best_plugin));
}

static void
device_context_continue (DeviceContext *device_context)
{
    GList   *l;
    GString *s = NULL;
    guint    n = 0;
    guint    n_active = 0;

    /* If there are no running port contexts around, we're free to finish */
    if (!device_context->port_contexts) {
        mm_dbg ("[plugin manager] task %s: no more ports to probe", device_context->name);
        device_context_complete (device_context);
        return;
    }

    /* We'll count how many port contexts are 'active' (i.e. not deferred
     * until a result is suggested). Also, prepare to log about the pending
     * ports */
    for (l = device_context->port_contexts; l; l = g_list_next (l)) {
        PortContext *port_context = (PortContext *) (l->data);
        const gchar *portname;

        portname = mm_kernel_device_get_name (port_context->port);
        if (!s)
            s = g_string_new (portname);
        else
            g_string_append_printf (s, ", %s", portname);

        /* Active? */
        if (!port_context->defer_until_suggested)
            n_active++;
        n++;
    }

    g_assert (n > 0 && s);
    mm_dbg ("[plugin Manager] task %s: still %u running probes (%u active): %s",
            device_context->name, n, n_active, s->str);
    g_string_free (s, TRUE);

    if (n_active == 0) {
        mm_dbg ("[plugin manager] task %s: no active tasks to probe", device_context->name);
        device_context_suggest_plugin (device_context, NULL, NULL);
    }
}

static void
port_context_run_ready (MMPluginManager    *self,
                        GAsyncResult       *res,
                        CommonAsyncContext *common)
{
    GError   *error = NULL;
    MMPlugin *best_plugin;

    /* Returns a full reference to the best plugin */
    best_plugin = port_context_run_finish (self, res, &error);
    if (!best_plugin) {
        /* The only error we can ignore is UNSUPPORTED */
        if (g_error_matches (error, MM_CORE_ERROR, MM_CORE_ERROR_UNSUPPORTED)) {
            /* This error is not critical */
            device_context_set_best_plugin (common->device_context, common->port_context, NULL);
        } else
            mm_warn ("[plugin manager] task %s: failed: %s", common->port_context->name, error->message);
        g_error_free (error);
    } else {
        /* Set the plugin as the best one in the device context */
        device_context_set_best_plugin (common->device_context, common->port_context, best_plugin);
        g_object_unref (best_plugin);
    }

    /* We MUST have the port context in the list at this point, because we're
     * going to remove the reference, so assert if this is not true. The caller
     * must always make sure that the port_context is available in the list */
    g_assert (g_list_find (common->device_context->port_contexts, common->port_context));
    common->device_context->port_contexts = g_list_remove (common->device_context->port_contexts,
                                                           common->port_context);
    port_context_unref (common->port_context);

    /* Continue the device context logic */
    device_context_continue (common->device_context);

    /* Cleanup the context of the async operation */
    common_async_context_free (common);
}

static gboolean
device_context_min_probing_time_elapsed (DeviceContext *device_context)
{
    device_context->min_probing_time_id = 0;

    mm_dbg ("[plugin manager] task %s: min probing time elapsed", device_context->name);

    /* Wakeup the device context logic */
    device_context_continue (device_context);
    return G_SOURCE_REMOVE;
}

static void
device_context_run_port_context (DeviceContext *device_context,
                                 PortContext   *port_context)
{
    GList           *plugins;
    MMPlugin        *suggested = NULL;
    MMPluginManager *self;

    /* Recover plugin manager */
    self = MM_PLUGIN_MANAGER (device_context->self);

    /* Setup plugins to probe and first one to check.
     * Make sure this plugins list is built after the MIN WAIT TIME has been expired
     * (so that per-driver filters work correctly) */
    plugins = plugin_manager_build_plugins_list (self, device_context->device, port_context->port);

    /* If we got one already set in the device context, it will be the first one,
     * unless it is the generic plugin */
    if (device_context->best_plugin &&
        !g_str_equal (mm_plugin_get_name (device_context->best_plugin), MM_PLUGIN_GENERIC_NAME)) {
        suggested = device_context->best_plugin;
    }

    port_context_run (self,
                      port_context,
                      plugins,
                      suggested,
                      (GAsyncReadyCallback) port_context_run_ready,
                      common_async_context_new (self,
                                                device_context,
                                                port_context,
                                                NULL));
    g_list_free_full (plugins, g_object_unref);
}

static gboolean
device_context_min_wait_time_elapsed (DeviceContext *device_context)
{
    MMPluginManager *self;
    GList           *l;
    GList           *tmp;

    self = device_context->self;

    device_context->min_wait_time_id = 0;
    mm_dbg ("[plugin manager] task %s: min wait time elapsed", device_context->name);

    /* Move list of port contexts out of the wait list */
    g_assert (!device_context->port_contexts);
    tmp = device_context->wait_port_contexts;
    device_context->wait_port_contexts = NULL;

    /* Launch supports check for each port in the Plugin Manager */
    for (l = tmp; l; l = g_list_next (l)) {
        PortContext *port_context = (PortContext *)(l->data);

        if (!mm_filter_device_and_port (self->priv->filter, port_context->device, port_context->port)) {
            /* If port is filtered, unref it right away */
            port_context_unref (port_context);
        } else {
            /* If port not filtered, store and run it */
            device_context->port_contexts = g_list_append (device_context->port_contexts, port_context);
            device_context_run_port_context (device_context, port_context);
        }
    }
    g_list_free (tmp);

    return G_SOURCE_REMOVE;
}

static void
device_context_port_released (DeviceContext  *device_context,
                              MMKernelDevice *port)
{
    PortContext *port_context;

    mm_dbg ("[plugin manager] task %s: port released: %s",
            device_context->name, mm_kernel_device_get_name (port));

    /* Check if there's a waiting port context */
    port_context = device_context_peek_waiting_port_context (device_context, port);
    if (port_context) {
        /* We didn't run the port context yet, we can remove it right away */
        device_context->wait_port_contexts = g_list_remove (device_context->wait_port_contexts, port_context);
        port_context_unref (port_context);
        return;
    }

    /* Now, check running port contexts, which will need cancellation if found */
    port_context = device_context_peek_running_port_context (device_context, port);
    if (port_context) {
        /* Request cancellation of this single port, will be completed asynchronously */
        port_context_cancel (port_context);
        return;
    }

    /* This is not something worth warning. If the probing task has already
     * been finished, it will already be removed from the list */
    mm_dbg ("[plugin manager] task %s: port wasn't found: %s",
            device_context->name, mm_kernel_device_get_name (port));
}

static void
device_context_port_grabbed (DeviceContext  *device_context,
                             MMKernelDevice *port)
{
    MMPluginManager *self;
    PortContext     *port_context;

    /* Recover plugin manager */
    self = MM_PLUGIN_MANAGER (device_context->self);

    mm_dbg ("[plugin manager] task %s: port grabbed: %s",
            device_context->name, mm_kernel_device_get_name (port));

    /* Ignore if for any reason we still have it in the running list */
    port_context = device_context_peek_running_port_context (device_context, port);
    if (port_context) {
        mm_warn ("[plugin manager] task %s: port context already being processed",
                 device_context->name);
        return;
    }

    /* Ignore if for any reason we still have it in the waiting list */
    port_context = device_context_peek_waiting_port_context (device_context, port);
    if (port_context) {
        mm_warn ("[plugin manager] task %s: port context already scheduled",
                 device_context->name);
        return;
    }

    /* Setup a new port context for the newly grabbed port */
    port_context = port_context_new (self,
                                     device_context->name,
                                     device_context->device,
                                     port);

    mm_dbg ("[plugin manager] task %s: new support task for port",
            port_context->name);

    /* Îf still waiting the min wait time, store it in the waiting list */
    if (device_context->min_wait_time_id) {
        mm_dbg ("[plugin manager) task %s: deferred until min wait time elapsed",
                port_context->name);
        /* Store the port reference in the list within the device */
        device_context->wait_port_contexts = g_list_prepend (device_context->wait_port_contexts, port_context);
        return;
    }

    /* Store the port reference in the list within the device */
    device_context->port_contexts = g_list_prepend (device_context->port_contexts, port_context) ;

    /* If the port has been grabbed after the min wait timeout expired, launch
     * probing directly */
    device_context_run_port_context (device_context, port_context);
}

static gboolean
device_context_cancel (DeviceContext *device_context)
{
    /* If cancelled already, do nothing */
    if (g_cancellable_is_cancelled (device_context->cancellable))
        return FALSE;

    mm_dbg ("[plugin manager) task %s: cancellation requested",
            device_context->name);

    /* The device context is cancelled now */
    g_cancellable_cancel (device_context->cancellable);

    /* Remove all port contexts in the waiting list. This will allow early cancellation
     * if it arrives before the min wait time has elapsed */
    if (device_context->wait_port_contexts) {
        g_assert (!device_context->port_contexts);
        g_list_free_full (device_context->wait_port_contexts, (GDestroyNotify) port_context_unref);
        device_context->wait_port_contexts = NULL;
    }

    /* Cancel all ongoing port contexts, if they're not already cancelled */
    if (device_context->port_contexts) {
        g_assert (!device_context->wait_port_contexts);
        /* Request cancellation, will be completed asynchronously */
        g_list_foreach (device_context->port_contexts, (GFunc) port_context_cancel, NULL);
    }

    /* Wakeup the device context logic. If we were still waiting for the
     * min probing time, this will complete the device context. */
    device_context_continue (device_context);
    return TRUE;
}

static void
device_context_run (MMPluginManager     *self,
                    DeviceContext       *device_context,
                    GAsyncReadyCallback  callback,
                    gpointer             user_data)
{
    g_assert (!device_context->task);
    g_assert (!device_context->grabbed_id);
    g_assert (!device_context->released_id);
    g_assert (!device_context->min_wait_time_id);
    g_assert (!device_context->min_probing_time_id);

    /* Connect to device port grabbed/released notifications from the device */
    device_context->grabbed_id = g_signal_connect_swapped (device_context->device,
                                                           MM_DEVICE_PORT_GRABBED,
                                                           G_CALLBACK (device_context_port_grabbed),
                                                           device_context);
    device_context->released_id = g_signal_connect_swapped (device_context->device,
                                                            MM_DEVICE_PORT_RELEASED,
                                                            G_CALLBACK (device_context_port_released),
                                                            device_context);

    /* Set the initial waiting timeout. We don't want to probe any port before
     * this timeout expires, so that we get as many ports added in the device
     * as possible. If we don't do this, some plugin filters won't work properly,
     * like the 'forbidden-drivers' one.
     */
    device_context->min_wait_time_id = g_timeout_add (MIN_WAIT_TIME_MSECS,
                                                      (GSourceFunc) device_context_min_wait_time_elapsed,
                                                      device_context);

    /* Set the initial probing timeout. We force the probing time of the device to
     * be at least this amount of time, so that the kernel has enough time to
     * bring up ports. Given that we launch this only when the first port of the
     * device has been exposed in udev, this timeout effectively means that we
     * leave up to 2s to the remaining ports to appear.
     */
    device_context->min_probing_time_id = g_timeout_add (MIN_PROBING_TIME_MSECS,
                                                         (GSourceFunc) device_context_min_probing_time_elapsed,
                                                         device_context);

    /* The full device context is now cancellable. We pass this cancellable also
     * to the inner GTask, so that if we're cancelled we always return a
     * cancellation error, regardless of what the standard logic does. */
    device_context->cancellable = g_cancellable_new ();

    /* Create a inner task for the device context. We'll complete this task when
     * the last port has been probed. */
    device_context->task = g_task_new (self, device_context->cancellable, callback, user_data);
}

static DeviceContext *
device_context_new (MMPluginManager *self,
                    MMDevice        *device)
{
    static gulong  unique_task_id = 0;
    DeviceContext *device_context;

    /* Create new device context and store the task */
    device_context              = g_slice_new0 (DeviceContext);
    device_context->ref_count   = 1;
    device_context->self        = g_object_ref (self);
    device_context->device      = g_object_ref (device);
    device_context->timer       = g_timer_new ();

    /* Set context name (just for logging) */
    device_context->name = g_strdup_printf ("%lu", unique_task_id++);

    return device_context;
}

/*****************************************************************************/
/* Look for plugin to support the given device
 *
 * This operation is initiated when the new MMDevice is detected. Once that
 * happens, a new support check for the whole device will arrive at the plugin
 * manager.
 *
 * Ports in the device, though, are added dynamically and automatically
 * afterwards once the device support check has been created. It is the device
 * support check context itself adding the newly added ports.
 *
 * The device support check task is finished once all port support check tasks
 * have also been finished.
 *
 * Given that the ports are added dynamically, there is some minimum duration
 * for the device support check task, otherwise we may end up not detecting
 * any port.
 *
 * The device support check tasks are stored also in the plugin manager, so
 * that the cancellation API doesn't require anything more specific than the
 * device for which the support check task should be cancelled.
 */

MMPlugin *
mm_plugin_manager_device_support_check_finish (MMPluginManager  *self,
                                               GAsyncResult     *res,
                                               GError          **error)
{
    return MM_PLUGIN (g_task_propagate_pointer (G_TASK (res), error));
}

static DeviceContext *
plugin_manager_peek_device_context (MMPluginManager *self,
                                    MMDevice        *device)
{
    GList *l;

    for (l = self->priv->device_contexts; l; l = g_list_next (l)) {
        DeviceContext *device_context;

        device_context = (DeviceContext *)(l->data);
        if ((device == device_context->device) ||
            (!g_strcmp0 (mm_device_get_uid (device_context->device), mm_device_get_uid (device))))
            return device_context;
    }
    return NULL;
}

gboolean
mm_plugin_manager_device_support_check_cancel (MMPluginManager *self,
                                               MMDevice        *device)
{
    DeviceContext *device_context;

    /* If the device context isn't found, ignore the cancellation request. */
    device_context = plugin_manager_peek_device_context (self, device);
    if (!device_context)
        return FALSE;

    /* Request cancellation, will be completed asynchronously */
    return device_context_cancel (device_context);
}

static void
device_context_run_ready (MMPluginManager    *self,
                          GAsyncResult       *res,
                          CommonAsyncContext *common)
{
    GError   *error = NULL;
    MMPlugin *best_plugin;

    /* We get a full reference back */
    best_plugin = device_context_run_finish (self, res, &error);

    /*
     * Once the task is finished, we can also remove it from the plugin manager
     * list. We MUST have the port context in the list at this point, because
     * we're going to dispose the reference, so assert if this is not true.
     */
    g_assert (g_list_find (common->self->priv->device_contexts, common->device_context));
    common->self->priv->device_contexts = g_list_remove (common->self->priv->device_contexts,
                                                         common->device_context);
    device_context_unref (common->device_context);

    /* Report result or error once removed from our internal list */
    if (!best_plugin)
        g_task_return_error (common->task, error);
    else
        g_task_return_pointer (common->task, best_plugin, g_object_unref);
    common_async_context_free (common);
}

void
mm_plugin_manager_device_support_check (MMPluginManager     *self,
                                        MMDevice            *device,
                                        GAsyncReadyCallback  callback,
                                        gpointer             user_data)
{
    DeviceContext *device_context;
    GTask         *task;

    /*
     * Create a new task for the device support check request.
     *
     * Note that we handle cancellations ourselves, as we don't want the caller
     * to be required to keep track of a GCancellable for each of these tasks.
     */
    task = g_task_new (G_OBJECT (self), NULL, callback, user_data);

    /* Fail if there is already a task for the same device */
    device_context = plugin_manager_peek_device_context (self, device);
    if (device_context) {
        g_task_return_new_error (task, MM_CORE_ERROR, MM_CORE_ERROR_IN_PROGRESS,
                                 "Device support check task already available for device '%s'",
                                 mm_device_get_uid (device));
        g_object_unref (task);
        return;
    }

    /* Create new device context */
    device_context = device_context_new (self, device);

    /* Track the device context in the list within the plugin manager. */
    self->priv->device_contexts = g_list_prepend (self->priv->device_contexts, device_context);

    mm_dbg ("[plugin manager] task %s: new support task for device: %s",
            device_context->name, mm_device_get_uid (device_context->device));

    /* Run device context */
    device_context_run (self,
                        device_context,
                        (GAsyncReadyCallback) device_context_run_ready,
                        common_async_context_new (self,
                                                  device_context,
                                                  NULL,
                                                  task));
    g_object_unref (task);
}

/*****************************************************************************/
/* Look for plugin */

MMPlugin *
mm_plugin_manager_peek_plugin (MMPluginManager *self,
                               const gchar *plugin_name)
{
    GList *l;

    if (self->priv->generic && g_str_equal (plugin_name, mm_plugin_get_name (self->priv->generic)))
        return self->priv->generic;

    for (l = self->priv->plugins; l; l = g_list_next (l)) {
        MMPlugin *plugin = MM_PLUGIN (l->data);

        if (g_str_equal (plugin_name, mm_plugin_get_name (plugin)))
            return plugin;
    }

    return NULL;
}

/*****************************************************************************/

static MMPlugin *
load_plugin (const gchar *path)
{
    MMPlugin *plugin = NULL;
    GModule *module;
    MMPluginCreateFunc plugin_create_func;
    gint *major_plugin_version;
    gint *minor_plugin_version;
    gchar *path_display;

    /* Get printable UTF-8 string of the path */
    path_display = g_filename_display_name (path);

    module = g_module_open (path, G_MODULE_BIND_LAZY);
    if (!module) {
        mm_warn ("[plugin manager] could not load plugin '%s': %s", path_display, g_module_error ());
        goto out;
    }

    if (!g_module_symbol (module, "mm_plugin_major_version", (gpointer *) &major_plugin_version)) {
        mm_warn ("[plugin manager] could not load plugin '%s': Missing major version info", path_display);
        goto out;
    }

    if (*major_plugin_version != MM_PLUGIN_MAJOR_VERSION) {
        mm_warn ("[plugin manager] could not load plugin '%s': Plugin major version %d, %d is required",
                 path_display, *major_plugin_version, MM_PLUGIN_MAJOR_VERSION);
        goto out;
    }

    if (!g_module_symbol (module, "mm_plugin_minor_version", (gpointer *) &minor_plugin_version)) {
        mm_warn ("[plugin manager] could not load plugin '%s': Missing minor version info", path_display);
        goto out;
    }

    if (*minor_plugin_version != MM_PLUGIN_MINOR_VERSION) {
        mm_warn ("[plugin manager] could not load plugin '%s': Plugin minor version %d, %d is required",
                   path_display, *minor_plugin_version, MM_PLUGIN_MINOR_VERSION);
        goto out;
    }

    if (!g_module_symbol (module, "mm_plugin_create", (gpointer *) &plugin_create_func)) {
        mm_warn ("[plugin manager] could not load plugin '%s': %s", path_display, g_module_error ());
        goto out;
    }

    plugin = (*plugin_create_func) ();
    if (plugin)
        g_object_weak_ref (G_OBJECT (plugin), (GWeakNotify) g_module_close, module);
    else
        mm_warn ("[plugin manager] could not load plugin '%s': initialization failed", path_display);

out:
    if (module && !plugin)
        g_module_close (module);

    g_free (path_display);

    return plugin;
}

static gboolean
load_plugins (MMPluginManager *self,
              GError **error)
{
    GDir *dir = NULL;
    const gchar *fname;
    gchar *plugindir_display = NULL;

    if (!g_module_supported ()) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_UNSUPPORTED,
                     "modules are not supported on your platform!");
        goto out;
    }

    /* Get printable UTF-8 string of the path */
    plugindir_display = g_filename_display_name (self->priv->plugin_dir);

    mm_dbg ("[plugin manager] looking for plugins in '%s'", plugindir_display);
    dir = g_dir_open (self->priv->plugin_dir, 0, NULL);
    if (!dir) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_NO_PLUGINS,
                     "plugin directory '%s' not found",
                     plugindir_display);
        goto out;
    }

    while ((fname = g_dir_read_name (dir)) != NULL) {
        gchar *path;
        MMPlugin *plugin;

        if (!g_str_has_suffix (fname, G_MODULE_SUFFIX))
            continue;

        path = g_module_build_path (self->priv->plugin_dir, fname);
        plugin = load_plugin (path);
        g_free (path);

        if (!plugin)
            continue;

        mm_dbg ("[plugin manager] loaded plugin '%s'", mm_plugin_get_name (plugin));

        if (g_str_equal (mm_plugin_get_name (plugin), MM_PLUGIN_GENERIC_NAME))
            /* Generic plugin */
            self->priv->generic = plugin;
        else
            /* Vendor specific plugin */
            self->priv->plugins = g_list_append (self->priv->plugins, plugin);
    }

    /* Check the generic plugin once all looped */
    if (!self->priv->generic)
        mm_warn ("[plugin manager] generic plugin not loaded");

    /* Treat as error if we don't find any plugin */
    if (!self->priv->plugins && !self->priv->generic) {
        g_set_error (error,
                     MM_CORE_ERROR,
                     MM_CORE_ERROR_NO_PLUGINS,
                     "no plugins found in plugin directory '%s'",
                     plugindir_display);
        goto out;
    }

    mm_dbg ("[plugin manager] successfully loaded %u plugins",
            g_list_length (self->priv->plugins) + !!self->priv->generic);

out:
    if (dir)
        g_dir_close (dir);
    g_free (plugindir_display);

    /* Return TRUE if at least one plugin found */
    return (self->priv->plugins || self->priv->generic);
}

MMPluginManager *
mm_plugin_manager_new (const gchar  *plugin_dir,
                       MMFilter     *filter,
                       GError      **error)
{
    return g_initable_new (MM_TYPE_PLUGIN_MANAGER,
                           NULL,
                           error,
                           MM_PLUGIN_MANAGER_PLUGIN_DIR, plugin_dir,
                           MM_PLUGIN_MANAGER_FILTER,     filter,
                           NULL);
}

static void
mm_plugin_manager_init (MMPluginManager *manager)
{
    /* Initialize opaque pointer to private data */
    manager->priv = G_TYPE_INSTANCE_GET_PRIVATE (manager,
                                                 MM_TYPE_PLUGIN_MANAGER,
                                                 MMPluginManagerPrivate);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
    MMPluginManagerPrivate *priv = MM_PLUGIN_MANAGER (object)->priv;

    switch (prop_id) {
    case PROP_PLUGIN_DIR:
        g_free (priv->plugin_dir);
        priv->plugin_dir = g_value_dup_string (value);
        break;
    case PROP_FILTER:
        priv->filter = g_value_dup_object (value);
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
    MMPluginManagerPrivate *priv = MM_PLUGIN_MANAGER (object)->priv;

    switch (prop_id) {
    case PROP_PLUGIN_DIR:
        g_value_set_string (value, priv->plugin_dir);
        break;
    case PROP_FILTER:
        g_value_set_object (value, priv->filter);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
        break;
    }
}

static gboolean
initable_init (GInitable *initable,
               GCancellable *cancellable,
               GError **error)
{
    /* Load the list of plugins */
    return load_plugins (MM_PLUGIN_MANAGER (initable), error);
}

static void
dispose (GObject *object)
{
    MMPluginManager *self = MM_PLUGIN_MANAGER (object);

    /* Cleanup list of plugins */
    if (self->priv->plugins) {
        g_list_free_full (self->priv->plugins, g_object_unref);
        self->priv->plugins = NULL;
    }
    g_clear_object (&self->priv->generic);

    g_free (self->priv->plugin_dir);
    self->priv->plugin_dir = NULL;

    g_clear_object (&self->priv->filter);

    G_OBJECT_CLASS (mm_plugin_manager_parent_class)->dispose (object);
}

static void
initable_iface_init (GInitableIface *iface)
{
    iface->init = initable_init;
}

static void
mm_plugin_manager_class_init (MMPluginManagerClass *manager_class)
{
    GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

    g_type_class_add_private (object_class, sizeof (MMPluginManagerPrivate));

    /* Virtual methods */
    object_class->dispose = dispose;
    object_class->set_property = set_property;
    object_class->get_property = get_property;

    /* Properties */
    g_object_class_install_property
        (object_class, PROP_PLUGIN_DIR,
         g_param_spec_string (MM_PLUGIN_MANAGER_PLUGIN_DIR,
                              "Plugin directory",
                              "Where to look for plugins",
                              NULL,
                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
    g_object_class_install_property
        (object_class, PROP_FILTER,
         g_param_spec_object (MM_PLUGIN_MANAGER_FILTER,
                              "Filter",
                              "Device filter",
                              MM_TYPE_FILTER,
                              G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}
