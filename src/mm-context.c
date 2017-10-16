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
 * Copyright (C) 2012 Aleksander Morgado <aleksander@gnu.org>
 */

#include <config.h>
#include <stdlib.h>

#include <ModemManager.h>
#define _LIBMM_INSIDE_MM
#include <libmm-glib.h>

#include "mm-context.h"

/*****************************************************************************/
/* Application context */

#if defined WITH_UDEV
# define NO_AUTO_SCAN_OPTION_FLAG 0
# define NO_AUTO_SCAN_DEFAULT     FALSE
#else
/* Keep the option when udev disabled, just so that the unit test setup can
 * unconditionally use --no-auto-scan */
# define NO_AUTO_SCAN_OPTION_FLAG G_OPTION_FLAG_HIDDEN
# define NO_AUTO_SCAN_DEFAULT     TRUE
#endif

static gboolean      help_flag;
static gboolean      version_flag;
static gboolean      debug;
static MMFilterRule  filter_policy = MM_FILTER_POLICY_DEFAULT;
static gboolean      no_auto_scan = NO_AUTO_SCAN_DEFAULT;
static const gchar  *initial_kernel_events;

static gboolean
filter_policy_option_arg (const gchar  *option_name,
                          const gchar  *value,
                          gpointer      data,
                          GError      **error)
{
    if (!g_ascii_strcasecmp (value, "default")) {
        filter_policy = MM_FILTER_POLICY_DEFAULT;
        return TRUE;
    }

    if (!g_ascii_strcasecmp (value, "whitelist-only")) {
        filter_policy = MM_FILTER_POLICY_WHITELIST_ONLY;
        return TRUE;
    }

    if (!g_ascii_strcasecmp (value, "strict")) {
        filter_policy = MM_FILTER_POLICY_STRICT;
        return TRUE;
    }

    if (!g_ascii_strcasecmp (value, "paranoid")) {
        filter_policy = MM_FILTER_POLICY_PARANOID;
        return TRUE;
    }

    g_set_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED,
                 "Invalid filter policy value given: %s",
                 value);
    return FALSE;
}

static const GOptionEntry entries[] = {
    {
        "filter-policy", 0, 0, G_OPTION_ARG_CALLBACK, filter_policy_option_arg,
        "Filter policy: one of DEFAULT, WHITELIST-ONLY, STRICT, PARANOID",
        "[POLICY]"
    },
    {
        "no-auto-scan", 0, NO_AUTO_SCAN_OPTION_FLAG, G_OPTION_ARG_NONE, &no_auto_scan,
        "Don't auto-scan looking for devices",
        NULL
    },
    {
        "initial-kernel-events", 0, 0, G_OPTION_ARG_FILENAME, &initial_kernel_events,
        "Path to initial kernel events file",
        "[PATH]"
    },
    {
        "debug", 0, 0, G_OPTION_ARG_NONE, &debug,
        "Run with extended debugging capabilities",
        NULL
    },
    {
        "version", 'V', 0, G_OPTION_ARG_NONE, &version_flag,
        "Print version",
        NULL
    },
    {
        "help", 'h', 0, G_OPTION_ARG_NONE, &help_flag,
        "Show help",
        NULL
    },
    { NULL }
};

gboolean
mm_context_get_debug (void)
{
    return debug;
}

const gchar *
mm_context_get_initial_kernel_events (void)
{
    return initial_kernel_events;
}

gboolean
mm_context_get_no_auto_scan (void)
{
    return no_auto_scan;
}

MMFilterRule
mm_context_get_filter_policy (void)
{
    return filter_policy;
}

/*****************************************************************************/
/* Log context */

static const gchar *log_level;
static const gchar *log_file;
static gboolean     log_journal;
static gboolean     log_show_ts;
static gboolean     log_rel_ts;

static const GOptionEntry log_entries[] = {
    {
        "log-level", 0, 0, G_OPTION_ARG_STRING, &log_level,
        "Log level: one of ERR, WARN, INFO, DEBUG",
        "[LEVEL]"
    },
    {
        "log-file", 0, 0, G_OPTION_ARG_FILENAME, &log_file,
        "Path to log file",
        "[PATH]"
    },
#if defined WITH_SYSTEMD_JOURNAL
    {
        "log-journal", 0, 0, G_OPTION_ARG_NONE, &log_journal,
        "Log to systemd journal",
        NULL
    },
#endif
    {
        "log-timestamps", 0, 0, G_OPTION_ARG_NONE, &log_show_ts,
        "Show timestamps in log output",
        NULL
    },
    {
        "log-relative-timestamps", 0, 0, G_OPTION_ARG_NONE, &log_rel_ts,
        "Use relative timestamps (from MM start)",
        NULL
    },
    { NULL }
};

static GOptionGroup *
log_get_option_group (void)
{
    GOptionGroup *group;

    group = g_option_group_new ("log",
                                "Logging options",
                                "Show logging options",
                                NULL,
                                NULL);
    g_option_group_add_entries (group, log_entries);
    return group;
}

const gchar *
mm_context_get_log_level (void)
{
    return log_level;
}

const gchar *
mm_context_get_log_file (void)
{
    return log_file;
}

gboolean
mm_context_get_log_journal (void)
{
    return log_journal;
}

gboolean
mm_context_get_log_timestamps (void)
{
    return log_show_ts;
}

gboolean
mm_context_get_log_relative_timestamps (void)
{
    return log_rel_ts;
}

/*****************************************************************************/
/* Test context */

static gboolean  test_session;
static gboolean  test_enable;
static gchar    *test_plugin_dir;

static const GOptionEntry test_entries[] = {
    {
        "test-session", 0, 0, G_OPTION_ARG_NONE, &test_session,
        "Run in session DBus",
        NULL
    },
    {
        "test-enable", 0, 0, G_OPTION_ARG_NONE, &test_enable,
        "Enable the Test interface in the daemon",
        NULL
    },
    {
        "test-plugin-dir", 0, 0, G_OPTION_ARG_FILENAME, &test_plugin_dir,
        "Path to look for plugins",
        "[PATH]"
    },
    { NULL }
};

static GOptionGroup *
test_get_option_group (void)
{
    GOptionGroup *group;

    group = g_option_group_new ("test",
                                "Test options",
                                "Show Test options",
                                NULL,
                                NULL);
    g_option_group_add_entries (group, test_entries);
    return group;
}

gboolean
mm_context_get_test_session (void)
{
    return test_session;
}

gboolean
mm_context_get_test_enable (void)
{
    return test_enable;
}

const gchar *
mm_context_get_test_plugin_dir (void)
{
    return test_plugin_dir ? test_plugin_dir : PLUGINDIR;
}

/*****************************************************************************/

static void
print_version (void)
{
    g_print ("\n"
             "ModemManager " MM_DIST_VERSION "\n"
             "Copyright (C) 2008-2017 The ModemManager authors\n"
             "License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl-2.0.html>\n"
             "This is free software: you are free to change and redistribute it.\n"
             "There is NO WARRANTY, to the extent permitted by law.\n"
             "\n");
}

static void
print_help (GOptionContext *context)
{
    gchar *str;

    /* Always print --help-all */
    str = g_option_context_get_help (context, FALSE, NULL);
    g_print ("%s", str);
    g_free (str);
}

void
mm_context_init (gint argc,
                 gchar **argv)
{
    GError *error = NULL;
    GOptionContext *ctx;

    ctx = g_option_context_new (NULL);
    g_option_context_set_summary (ctx, "DBus system service to control mobile broadband modems.");
    g_option_context_add_main_entries (ctx, entries, NULL);
    g_option_context_add_group (ctx, log_get_option_group ());
    g_option_context_add_group (ctx, test_get_option_group ());
    g_option_context_set_help_enabled (ctx, FALSE);

    if (!g_option_context_parse (ctx, &argc, &argv, &error)) {
        g_warning ("error: %s", error->message);
        g_error_free (error);
        exit (1);
    }

    if (version_flag) {
        print_version ();
        g_option_context_free (ctx);
        exit (EXIT_SUCCESS);
    }

    if (help_flag) {
        print_help (ctx);
        g_option_context_free (ctx);
        exit (EXIT_SUCCESS);
    }

    g_option_context_free (ctx);

    /* Additional setup to be done on debug mode */
    if (debug) {
        log_level = "DEBUG";
        if (!log_show_ts && !log_rel_ts)
            log_show_ts = TRUE;
    }

    /* Initial kernel events processing may only be used if autoscan is disabled */
#if defined WITH_UDEV
    if (!no_auto_scan && initial_kernel_events) {
        g_warning ("error: --initial-kernel-events must be used only if --no-auto-scan is also used");
        exit (1);
    }
#endif
}
