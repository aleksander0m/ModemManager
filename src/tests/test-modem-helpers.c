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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include <glib.h>
#include <glib-object.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include <libmm-glib.h>
#include "mm-modem-helpers.h"
#include "mm-log.h"

#if defined ENABLE_TEST_MESSAGE_TRACES
#define trace(message, ...) g_print (message, ##__VA_ARGS__)
#else
#define trace(...)
#endif

#define g_assert_cmpfloat_tolerance(val1, val2, tolerance)  \
    g_assert_cmpfloat (fabs (val1 - val2), <, tolerance)

/*****************************************************************************/
/* Test IFC=? responses */

static void
test_ifc_response (const gchar         *str,
                   const MMFlowControl  expected)
{
    MMFlowControl  mask;
    GError        *error = NULL;

    mask = mm_parse_ifc_test_response (str, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (mask, ==, expected);
}

static void
test_ifc_response_all_simple (void)
{
    test_ifc_response ("+IFC (0,1,2),(0,1,2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_all_groups (void)
{
    test_ifc_response ("+IFC (0-2),(0-2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_none_only (void)
{
    test_ifc_response ("+IFC (0),(0)", MM_FLOW_CONTROL_NONE);
}

static void
test_ifc_response_xon_xoff_only (void)
{
    test_ifc_response ("+IFC (1),(1)", MM_FLOW_CONTROL_XON_XOFF);
}

static void
test_ifc_response_rts_cts_only (void)
{
    test_ifc_response ("+IFC (2),(2)", MM_FLOW_CONTROL_RTS_CTS);
}

static void
test_ifc_response_no_xon_xoff (void)
{
    test_ifc_response ("+IFC (0,2),(0,2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_no_xon_xoff_in_ta (void)
{
    test_ifc_response ("+IFC (0,1,2),(0,2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_no_xon_xoff_in_te (void)
{
    test_ifc_response ("+IFC (0,2),(0,1,2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_no_rts_cts_simple (void)
{
    test_ifc_response ("+IFC (0,1),(0,1)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF));
}

static void
test_ifc_response_no_rts_cts_groups (void)
{
    test_ifc_response ("+IFC (0-1),(0-1)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF));
}

static void
test_ifc_response_all_simple_and_unknown (void)
{
    test_ifc_response ("+IFC (0,1,2,3),(0,1,2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF | MM_FLOW_CONTROL_RTS_CTS));
}

static void
test_ifc_response_all_groups_and_unknown (void)
{
    test_ifc_response ("+IFC (0-3),(0-2)", (MM_FLOW_CONTROL_NONE | MM_FLOW_CONTROL_XON_XOFF | MM_FLOW_CONTROL_RTS_CTS));
}

/*****************************************************************************/
/* Test WS46=? responses */

static void
test_ws46_response (const gchar       *str,
                    const MMModemMode *expected,
                    guint              n_expected)
{
    guint   i;
    GArray *modes;
    GError *error = NULL;

    modes = mm_3gpp_parse_ws46_test_response (str, &error);
    g_assert_no_error (error);
    g_assert (modes != NULL);
    g_assert_cmpuint (modes->len, ==, n_expected);

    for (i = 0; i < n_expected; i++) {
        guint j;

        for (j = 0; j < modes->len; j++) {
            if (expected[i] == g_array_index (modes, MMModemMode, j))
                break;
        }
        g_assert_cmpuint (j, !=, modes->len);
    }
    g_array_unref (modes);
}

static void
test_ws46_response_generic_2g3g4g (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G,
        MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
        MM_MODEM_MODE_4G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
    };
    const gchar *str = "+WS46: (12,22,25,28,29)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_generic_2g3g (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G,
        MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
    };
    const gchar *str = "+WS46: (12,22,25)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_generic_2g3g_v2 (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G,
        MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
    };
    const gchar *str = "+WS46: (12,22,29)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_cinterion (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G,
        MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
        MM_MODEM_MODE_4G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
    };
    const gchar *str = "(12,22,25,28,29)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_telit_le866 (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_4G,
    };
    const gchar *str = "(28)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_range_1 (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_4G,
        MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
    };
    const gchar *str = "+WS46: (29-31)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_ws46_response_range_2 (void)
{
    static const MMModemMode expected[] = {
        MM_MODEM_MODE_2G,
        MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
        MM_MODEM_MODE_4G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_3G,
        MM_MODEM_MODE_2G | MM_MODEM_MODE_4G,
        MM_MODEM_MODE_3G | MM_MODEM_MODE_4G,
    };
    const gchar *str = "+WS46: (12,22,25,28-31)";

    test_ws46_response (str, expected, G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test CMGL responses */

static void
test_cmgl_response (const gchar *str,
                    const MM3gppPduInfo *expected,
                    guint n_expected)
{
    guint i;
    GList *list;
    GError *error = NULL;

    list = mm_3gpp_parse_pdu_cmgl_response (str, &error);
    g_assert_no_error (error);
    g_assert (list != NULL);
    g_assert_cmpuint (g_list_length (list), ==, n_expected);

    for (i = 0; i < n_expected; i++) {
        GList *l;

        /* Look for the pdu with the expected index */
        for (l = list; l; l = g_list_next (l)) {
            MM3gppPduInfo *info = l->data;

            /* Found */
            if (info->index == expected[i].index) {
                g_assert_cmpint (info->status, ==, expected[i].status);
                g_assert_cmpstr (info->pdu, ==, expected[i].pdu);
                break;
            }
        }
        g_assert (l != NULL);
    }

    mm_3gpp_pdu_info_list_free (list);
}

static void
test_cmgl_response_generic (void *f, gpointer d)
{
    const gchar *str =
        "+CMGL: 0,1,,147\r\n07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07";

    const MM3gppPduInfo expected [] = {
        {
            .index = 0,
            .status = 1,
            .pdu = "07914306073011F00405812261F700003130916191314095C27"
            "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
            "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
            "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
            "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07"
        }
    };

    test_cmgl_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_cmgl_response_generic_multiple (void *f, gpointer d)
{
    const gchar *str =
        "+CMGL: 0,1,,147\r\n07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07\r\n"
        "+CMGL: 1,1,,147\r\n07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07\r\n"
        "+CMGL: 2,1,,147\r\n07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07";

    const MM3gppPduInfo expected [] = {
        {
            .index = 0,
            .status = 1,
            .pdu = "07914306073011F00405812261F700003130916191314095C27"
            "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
            "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
            "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
            "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07"
        },
        {
            .index = 1,
            .status = 1,
            .pdu = "07914306073011F00405812261F700003130916191314095C27"
            "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
            "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
            "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
            "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07"
        },
        {
            .index = 2,
            .status = 1,
            .pdu = "07914306073011F00405812261F700003130916191314095C27"
            "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
            "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
            "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
            "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07"
        }
    };

    test_cmgl_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_cmgl_response_pantech (void *f, gpointer d)
{
    const gchar *str =
        "+CMGL: 17,3,35\r\n079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020";

    const MM3gppPduInfo expected [] = {
        {
            .index = 17,
            .status = 3,
            .pdu = "079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020"
        }
    };

    test_cmgl_response (str, expected, G_N_ELEMENTS (expected));
}

static void
test_cmgl_response_pantech_multiple (void *f, gpointer d)
{
    const gchar *str =
        "+CMGL: 17,3,35\r\n079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020\r\n"
        "+CMGL: 15,3,35\r\n079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020\r\n"
        "+CMGL: 13,3,35\r\n079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020\r\n"
        "+CMGL: 11,3,35\r\n079100F40D1101000F001000B917118336058F300";

    const MM3gppPduInfo expected [] = {
        {
            .index = 17,
            .status = 3,
            .pdu = "079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020"
        },
        {
            .index = 15,
            .status = 3,
            .pdu = "079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020"
        },
        {
            .index = 13,
            .status = 3,
            .pdu = "079100F40D1101000F001000B917118336058F300001954747A0E4ACF41F27298CDCE83C6EF371B0402814020"
        },
        {
            .index = 11,
            .status = 3,
            .pdu = "079100F40D1101000F001000B917118336058F300"
        }
    };

    test_cmgl_response (str, expected, G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test CMGR responses */

static void
test_cmgr_response (const gchar *str,
                    const MM3gppPduInfo *expected)
{
    MM3gppPduInfo *info;
    GError *error = NULL;

    info = mm_3gpp_parse_cmgr_read_response (str, 0, &error);
    g_assert_no_error (error);
    g_assert (info != NULL);

    /* Ignore index, it is not included in CMGR response */
    g_assert_cmpint (info->status, ==, expected->status);
    g_assert_cmpstr (info->pdu, ==, expected->pdu);

    mm_3gpp_pdu_info_free (info);
}

static void
test_cmgr_response_generic (void *f, gpointer d)
{
    const gchar *str =
        "+CMGR: 1,,147 07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07";

    const MM3gppPduInfo expected = {
        .index = 0,
        .status = 1,
        .pdu = "07914306073011F00405812261F700003130916191314095C27"
        "4D96D2FBBD3E437280CB2BEC961F3DB5D76818EF2F0381D9E83E06F39A8CC2E9FD372F"
        "77BEE0249CBE37A594E0E83E2F532085E2F93CB73D0B93CA7A7DFEEB01C447F93DF731"
        "0BD3E07CDCB727B7A9C7ECF41E432C8FC96B7C32079189E26874179D0F8DD7E93C3A0B"
        "21B246AA641D637396C7EBBCB22D0FD7E77B5D376B3AB3C07"
    };

    test_cmgr_response (str, &expected);
}

/* Telit HE910 places empty quotation marks in the <alpha> field and a CR+LF
 * before the PDU */
static void
test_cmgr_response_telit (void *f, gpointer d)
{
    const gchar *str =
        "+CMGR: 0,\"\",50\r\n07916163838428F9040B916121021021F7000051905141642"
        "20A23C4B0BCFD5E8740C4B0BCFD5E83C26E3248196687C9A0301D440DBBC3677918";

    const MM3gppPduInfo expected = {
        .index = 0,
        .status = 0,
        .pdu = "07916163838428F9040B916121021021F7000051905141642"
        "20A23C4B0BCFD5E8740C4B0BCFD5E83C26E3248196687C9A0301D440DBBC3677918"
    };

    test_cmgr_response (str, &expected);
}

/*****************************************************************************/
/* Test COPS responses */

static void
test_cops_results (const gchar *desc,
                   const gchar *reply,
                   MM3gppNetworkInfo *expected_results,
                   guint32 expected_results_len)
{
    GList *l;
    GError *error = NULL;
    GList *results;

    trace ("\nTesting %s +COPS response...\n", desc);

    results = mm_3gpp_parse_cops_test_response (reply, &error);
    g_assert (results);
    g_assert_no_error (error);
    g_assert_cmpuint (g_list_length (results), ==, expected_results_len);

    for (l = results; l; l = g_list_next (l)) {
        MM3gppNetworkInfo *info = l->data;
        gboolean found = FALSE;
        guint i;

        for (i = 0; !found && i < expected_results_len; i++) {
            MM3gppNetworkInfo *expected;

            expected = &expected_results[i];
            if (g_str_equal (info->operator_code, expected->operator_code) &&
                info->access_tech == expected->access_tech) {
                found = TRUE;

                g_assert_cmpuint (info->status, ==, expected->status);

                if (expected->operator_long)
                    g_assert_cmpstr (info->operator_long, ==, expected->operator_long);
                else
                    g_assert (info->operator_long == NULL);

                if (expected->operator_short)
                    g_assert_cmpstr (info->operator_short, ==, expected->operator_short);
                else
                    g_assert (info->operator_short == NULL);

                g_debug ("info: %s, expected: %s", info->operator_code, expected->operator_code);
            }
        }

        g_assert (found == TRUE);
    }

    mm_3gpp_network_info_list_free (results);
}

static void
test_cops_response_tm506 (void *f, gpointer d)
{
    const gchar *reply = "+COPS: (2,\"\",\"T-Mobile\",\"31026\",0),(2,\"T - Mobile\",\"T - Mobile\",\"310260\"),2),(1,\"AT&T\",\"AT&T\",\"310410\"),0)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, NULL, "T-Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T - Mobile", "T - Mobile", "310260", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM }
    };

    test_cops_results ("TM-506", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gt3gplus (void *f, gpointer d)
{
    const char *reply = "+COPS: (1,\"T-Mobile US\",\"TMO US\",\"31026\",0),(1,\"Cingular\",\"Cingular\",\"310410\",0),,(0, 1, 3),(0-2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile US", "TMO US", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "Cingular", "Cingular", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("GlobeTrotter 3G+ (nozomi)", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_ac881 (void *f, gpointer d)
{
    const char *reply = "+COPS: (1,\"T-Mobile\",\"TMO\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Sierra AirCard 881", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gtmax36 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile US\",\"TMO US\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0, 1,)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile US", "TMO US", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Option GlobeTrotter MAX 3.6", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_ac860 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"TMO\",\"31026\",0),(1,\"Cingular\",\"Cinglr\",\"310410\",2),(1,\"Cingular\",\"Cinglr\",\"310410\",0),,)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "Cingular", "Cinglr", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "Cingular", "Cinglr", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Sierra AirCard 860", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gtm378 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"T-Mobile\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0, 1, 3),(0-2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "T-Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Option GTM378", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_motoc (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"\",\"310260\"),(0,\"Cingular Wireless\",\"\",\"310410\")";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", NULL, "310260", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_UNKNOWN, "Cingular Wireless", NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("BUSlink SCWi275u (Motorola C-series)", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_mf627a (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"AT&T@\",\"AT&TD\",\"310410\",0),(3,\"Voicestream Wireless Corporation\",\"VSTREAM\",\"31026\",0),";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "AT&T@", "AT&TD", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, "Voicestream Wireless Corporation", "VSTREAM", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("ZTE MF627 (A)", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_mf627b (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"AT&Tp\",\"AT&T@\",\"310410\",0),(3,\"\",\"\",\"31026\",0),";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "AT&Tp", "AT&T@", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("ZTE MF627 (B)", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_e160g (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"TMO\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Huawei E160G", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_mercury (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"\",\"\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),(1,\"T-Mobile\",\"TMO\",\"31026\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, NULL, NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Sierra AT&T USBConnect Mercury", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_quicksilver (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"AT&T\",\"\",\"310410\",0),(2,\"\",\"\",\"3104100\",2),(1,\"AT&T\",\"\",\"310260\",0),,(0-4),(0-2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "AT&T", NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, NULL, NULL, "3104100", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", NULL, "310260", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Option AT&T Quicksilver", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_icon225 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile US\",\"TMO US\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0, 1, 3),(0-2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile US", "TMO US", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Option iCON 225", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_icon452 (void *f, gpointer d)
{
    const char *reply = "+COPS: (1,\"T-Mobile US\",\"TMO US\",\"31026\",0),(2,\"T-Mobile\",\"T-Mobile\",\"310260\",2),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile US", "TMO US", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "T-Mobile", "310260", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM }
    };

    test_cops_results ("Option iCON 452", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_f3507g (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T - Mobile\",\"T - Mobile\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T - Mobile", "T - Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS }
    };

    test_cops_results ("Ericsson F3507g", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_f3607gw (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T - Mobile\",\"T - Mobile\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\"),2),(1,\"AT&T\",\"AT&T\",\"310410\"),0)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T - Mobile", "T - Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM }
    };

    test_cops_results ("Ericsson F3607gw", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_mc8775 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"T-Mobile\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "T-Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM }
    };

    test_cops_results ("Sierra MC8775", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_n80 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T - Mobile\",,\"31026\"),(1,\"Einstein PCS\",,\"31064\"),(1,\"Cingular\",,\"31041\"),,(0,1,3),(0,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T - Mobile", NULL, "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "Einstein PCS", NULL, "31064", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "Cingular", NULL, "31041", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Nokia N80", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_e1550 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"TMO\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Huawei E1550", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_mf622 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"T-Mobile\",\"31026\",0),(1,\"\",\"\",\"310410\",0),";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "T-Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, NULL, NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("ZTE MF622", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_e226 (void *f, gpointer d)
{
    const char *reply = "+COPS: (1,\"\",\"\",\"31026\",0),(1,\"\",\"\",\"310410\",2),(1,\"\",\"\",\"310410\",0),,(0,1,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, NULL, NULL, "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, NULL, NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, NULL, NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Huawei E226", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_xu870 (void *f, gpointer d)
{
    const char *reply = "+COPS: (0,\"AT&T MicroCell\",\"AT&T MicroCell\",\"310410\",2)\r\n+COPS: (1,\"AT&T MicroCell\",\"AT&T MicroCell\",\"310410\",0)\r\n+COPS: (1,\"T-Mobile\",\"TMO\",\"31026\",0)\r\n";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_UNKNOWN, "AT&T MicroCell", "AT&T MicroCell", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T MicroCell", "AT&T MicroCell", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile", "TMO", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Novatel XU870", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gtultraexpress (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile US\",\"TMO US\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile US", "TMO US", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Option GlobeTrotter Ultra Express", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_n2720 (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T - Mobile\",,\"31026\",0),\r\n(1,\"AT&T\",,\"310410\",0),,(0,1,3),(0,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T - Mobile", NULL, "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", NULL, "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Nokia 2720", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gobi (void *f, gpointer d)
{
    const char *reply = "+COPS: (2,\"T-Mobile\",\"T-Mobile\",\"31026\",0),(1,\"AT&T\",\"AT&T\",\"310410\",2),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "T-Mobile", "T-Mobile", "31026", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_UMTS },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Qualcomm Gobi", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_sek600i (void *f, gpointer d)
{
    /* Phone is stupid enough to support 3G but not report cell technology,
     * mixing together 2G and 3G cells without any way of distinguishing
     * which is which...
     */
    const char *reply = "+COPS: (2,\"blau\",\"\",\"26203\"),(2,\"blau\",\"\",\"26203\"),(3,\"\",\"\",\"26201\"),(3,\"\",\"\",\"26202\"),(3,\"\",\"\",\"26207\"),(3,\"\",\"\",\"26201\"),(3,\"\",\"\",\"26207\")";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "blau", NULL, "26203", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_CURRENT, "blau", NULL, "26203", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "26201", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "26202", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "26207", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "26201", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_FORBIDDEN, NULL, NULL, "26207", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Sony-Ericsson K600i", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_samsung_z810 (void *f, gpointer d)
{
    /* Ensure commas within quotes don't trip up the parser */
    const char *reply = "+COPS: (1,\"T-Mobile USA, In\",\"T-Mobile\",\"310260\",0),(1,\"AT&T\",\"AT&T\",\"310410\",0),,(0,1,2,3,4),(0,1,2)";
    static MM3gppNetworkInfo expected[] = {
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "T-Mobile USA, In", "T-Mobile", "310260", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
        { MM_MODEM_3GPP_NETWORK_AVAILABILITY_AVAILABLE, "AT&T", "AT&T", "310410", MM_MODEM_ACCESS_TECHNOLOGY_GSM },
    };

    test_cops_results ("Samsung Z810", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cops_response_gsm_invalid (void *f, gpointer d)
{
    const gchar *reply = "+COPS: (0,1,2,3),(1,2,3,4)";
    GList *results;
    GError *error = NULL;

    results = mm_3gpp_parse_cops_test_response (reply, &error);
    g_assert (results == NULL);
    g_assert_no_error (error);
}

static void
test_cops_response_umts_invalid (void *f, gpointer d)
{
    const char *reply = "+COPS: (0,1,2,3,4),(1,2,3,4,5)";
   GList *results;
    GError *error = NULL;

    results = mm_3gpp_parse_cops_test_response (reply, &error);
    g_assert (results == NULL);
    g_assert_no_error (error);
}

/*****************************************************************************/
/* Test COPS? responses */

typedef struct {
    const gchar             *str;
    guint                    mode;
    guint                    format;
    const gchar             *operator;
    MMModemAccessTechnology  act;
} CopsQueryData;

static void
test_cops_query_data (const CopsQueryData *item)
{
    gboolean                 result;
    GError                  *error = NULL;
    guint                    mode = G_MAXUINT;
    guint                    format = G_MAXUINT;
    gchar                   *operator = NULL;
    MMModemAccessTechnology  act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;

    result = mm_3gpp_parse_cops_read_response (item->str,
                                               &mode,
                                               &format,
                                               &operator,
                                               &act,
                                               &error);
    g_assert_no_error (error);
    g_assert (result);
    g_assert_cmpuint (mode,     ==, item->mode);
    g_assert_cmpuint (format,   ==, item->format);
    g_assert_cmpstr  (operator, ==, item->operator);
    g_assert_cmpuint (act,      ==, item->act);

    g_free (operator);
}

static const CopsQueryData cops_query_data[] = {
    {
        .str = "+COPS: 1,0,\"CHINA MOBILE\"",
        .mode = 1,
        .format = 0,
        .operator = "CHINA MOBILE",
        .act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN
    },
    {
        .str = "+COPS: 1,0,\"CHINA MOBILE\",7",
        .mode = 1,
        .format = 0,
        .operator = "CHINA MOBILE",
        .act = MM_MODEM_ACCESS_TECHNOLOGY_LTE
    },
    {
        .str = "+COPS: 1,2,\"46000\"",
        .mode = 1,
        .format = 2,
        .operator = "46000",
        .act = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN
    },
    {
        .str = "+COPS: 1,2,\"46000\",7",
        .mode = 1,
        .format = 2,
        .operator = "46000",
        .act = MM_MODEM_ACCESS_TECHNOLOGY_LTE
    },
};

static void
test_cops_query (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cops_query_data); i++)
        test_cops_query_data (&cops_query_data[i]);
}

/*****************************************************************************/

typedef struct {
    const gchar    *input;
    MMModemCharset  charset;
    const gchar    *normalized;
} NormalizeOperatorTest;

static const NormalizeOperatorTest normalize_operator_tests[] = {
    /* charset unknown */
    { "Verizon", MM_MODEM_CHARSET_UNKNOWN, "Verizon" },
    { "311480",  MM_MODEM_CHARSET_UNKNOWN, "311480"  },
    /* charset configured as IRA (ASCII) */
    { "Verizon", MM_MODEM_CHARSET_IRA, "Verizon" },
    { "311480",  MM_MODEM_CHARSET_IRA, "311480"  },
    /* charset configured as GSM7 */
    { "Verizon", MM_MODEM_CHARSET_GSM, "Verizon" },
    { "311480",  MM_MODEM_CHARSET_GSM, "311480"  },
    /* charset configured as UCS2 */
    { "0056006500720069007A006F006E", MM_MODEM_CHARSET_UCS2, "Verizon" },
    { "003300310031003400380030",     MM_MODEM_CHARSET_UCS2, "311480"  },
    { "Verizon",                      MM_MODEM_CHARSET_UCS2, "Verizon" },
    { "311480",                       MM_MODEM_CHARSET_UCS2, "311480"  },
};

static void
common_test_normalize_operator (const NormalizeOperatorTest *t)
{
    gchar *str;

    str = g_strdup (t->input);
    mm_3gpp_normalize_operator (&str, t->charset);
    if (!t->normalized)
        g_assert (!str);
    else
        g_assert_cmpstr (str, ==, t->normalized);
    g_free (str);
}

static void
test_normalize_operator (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (normalize_operator_tests); i++)
        common_test_normalize_operator (&normalize_operator_tests[i]);
}

/*****************************************************************************/
/* Test CREG/CGREG responses and unsolicited messages */

typedef struct {
    GPtrArray *solicited_creg;
    GPtrArray *unsolicited_creg;
} RegTestData;

static RegTestData *
reg_test_data_new (void)
{
    RegTestData *data;

    data = g_malloc0 (sizeof (RegTestData));
    data->solicited_creg = mm_3gpp_creg_regex_get (TRUE);
    data->unsolicited_creg = mm_3gpp_creg_regex_get (FALSE);
    return data;
}

static void
reg_test_data_free (RegTestData *data)
{
    mm_3gpp_creg_regex_destroy (data->solicited_creg);
    mm_3gpp_creg_regex_destroy (data->unsolicited_creg);
    g_free (data);
}

typedef struct {
    MMModem3gppRegistrationState state;
    gulong lac;
    gulong ci;
    MMModemAccessTechnology act;

    guint regex_num;
    gboolean cgreg;
    gboolean cereg;
} CregResult;

static void
test_creg_match (const char *test,
                 gboolean solicited,
                 const char *reply,
                 RegTestData *data,
                 const CregResult *result)
{
    int i;
    GMatchInfo *info  = NULL;
    MMModem3gppRegistrationState state = MM_MODEM_3GPP_REGISTRATION_STATE_UNKNOWN;
    MMModemAccessTechnology access_tech = MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN;
    gulong lac = 0, ci = 0;
    GError *error = NULL;
    gboolean success, cgreg = FALSE, cereg = FALSE;
    guint regex_num = 0;
    GPtrArray *array;

    g_assert (reply);
    g_assert (test);
    g_assert (data);
    g_assert (result);

    trace ("\nTesting '%s' +C%sREG %s response...\n",
           test,
           result->cgreg ? "G" : "",
           solicited ? "solicited" : "unsolicited");

    array = solicited ? data->solicited_creg : data->unsolicited_creg;
    for (i = 0; i < array->len; i++) {
        GRegex *r = g_ptr_array_index (array, i);

        if (g_regex_match (r, reply, 0, &info)) {
            trace ("  matched with %d\n", i);
            regex_num = i + 1;
            break;
        }
        g_match_info_free (info);
        info = NULL;
    }

    trace ("  regex_num (%u) == result->regex_num (%u)\n",
           regex_num,
           result->regex_num);

    g_assert (info != NULL);
    g_assert_cmpuint (regex_num, ==, result->regex_num);

    success = mm_3gpp_parse_creg_response (info, &state, &lac, &ci, &access_tech, &cgreg, &cereg, &error);
    g_match_info_free (info);
    g_assert (success);
    g_assert_no_error (error);
    g_assert_cmpuint (state, ==, result->state);
    g_assert (lac == result->lac);
    g_assert (ci == result->ci);

    trace ("  access_tech (%d) == result->act (%d)\n",
           access_tech, result->act);
    g_assert_cmpuint (access_tech, ==, result->act);
    g_assert_cmpuint (cgreg, ==, result->cgreg);
    g_assert_cmpuint (cereg, ==, result->cereg);
}

static void
test_creg1_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 1,3";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 2, FALSE, FALSE };

    test_creg_match ("CREG=1", TRUE, reply, data, &result);
}

static void
test_creg1_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 3\r\n";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 1, FALSE, FALSE };

    test_creg_match ("CREG=1", FALSE, reply, data, &result);
}

static void
test_creg2_mercury_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 0,1,84CD,00D30173";
    const CregResult result = { 1, 0x84cd, 0xd30173, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    test_creg_match ("Sierra Mercury CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_mercury_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 1,84CD,00D30156\r\n";
    const CregResult result = { 1, 0x84cd, 0xd30156, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 3, FALSE, FALSE };

    test_creg_match ("Sierra Mercury CREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_sek850i_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 2,1,\"CE00\",\"01CEAD8F\"";
    const CregResult result = { 1, 0xce00, 0x01cead8f, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    test_creg_match ("Sony Ericsson K850i CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_sek850i_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 1,\"CE00\",\"00005449\"\r\n";
    const CregResult result = { 1, 0xce00, 0x5449, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 3, FALSE, FALSE };

    test_creg_match ("Sony Ericsson K850i CREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_e160g_solicited_unregistered (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 2,0,00,0";
    const CregResult result = { 0, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    test_creg_match ("Huawei E160G unregistered CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_e160g_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 2,1,8BE3,2BAF";
    const CregResult result = { 1, 0x8be3, 0x2baf, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    test_creg_match ("Huawei E160G CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_e160g_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 2,8BE3,2BAF\r\n";
    const CregResult result = { 2, 0x8be3, 0x2baf, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 3, FALSE, FALSE };

    test_creg_match ("Huawei E160G CREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_tm506_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG: 2,1,\"8BE3\",\"00002BAF\"";
    const CregResult result = { 1, 0x8BE3, 0x2BAF, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    /* Test leading zeros in the CI */
    test_creg_match ("Sony Ericsson TM-506 CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_xu870_unsolicited_unregistered (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 2,,\r\n";
    const CregResult result = { 2, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 3, FALSE, FALSE };

    test_creg_match ("Novatel XU870 unregistered CREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_iridium_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG:002,001,\"18d8\",\"ffff\"";
    const CregResult result = { 1, 0x18D8, 0xFFFF, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 5, FALSE, FALSE };

    test_creg_match ("Iridium, CREG=2", TRUE, reply, data, &result);
}

static void
test_creg2_no_leading_zeros_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG:2,1,0001,0010";
    const CregResult result = { 1, 0x0001, 0x0010, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 4, FALSE, FALSE };

    test_creg_match ("solicited CREG=2 with no leading zeros in integer fields", TRUE, reply, data, &result);
}

static void
test_creg2_leading_zeros_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CREG:002,001,\"0001\",\"0010\"";
    const CregResult result = { 1, 0x0001, 0x0010, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 5, FALSE, FALSE };

    test_creg_match ("solicited CREG=2 with leading zeros in integer fields", TRUE, reply, data, &result);
}

static void
test_creg2_no_leading_zeros_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 1,0001,0010,0\r\n";
    const CregResult result = { 1, 0x0001, 0x0010, MM_MODEM_ACCESS_TECHNOLOGY_GSM, 6, FALSE, FALSE };

    test_creg_match ("unsolicited CREG=2 with no leading zeros in integer fields", FALSE, reply, data, &result);
}

static void
test_creg2_leading_zeros_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 001,\"0001\",\"0010\",000\r\n";
    const CregResult result = { 1, 0x0001, 0x0010, MM_MODEM_ACCESS_TECHNOLOGY_GSM, 7, FALSE, FALSE };

    test_creg_match ("unsolicited CREG=2 with leading zeros in integer fields", FALSE, reply, data, &result);
}

static void
test_creg2_ublox_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const gchar *reply = "\r\n+CREG: 2,6,\"8B37\",\"0A265185\",7\r\n";
    /* NOTE: '6' means registered for "SMS only", home network; we just assume UNKNOWN in this case */
    const CregResult result = { MM_MODEM_3GPP_REGISTRATION_STATE_HOME_SMS_ONLY, 0x8B37, 0x0A265185, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 8, FALSE, FALSE };

    test_creg_match ("Ublox Toby-L2 solicited while on LTE", TRUE, reply, data, &result);
}

static void
test_creg2_ublox_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const gchar *reply = "\r\n+CREG: 6,\"8B37\",\"0A265185\",7\r\n";
    /* NOTE: '6' means registered for "SMS only", home network; we just assume UNKNOWN in this case */
    const CregResult result = { MM_MODEM_3GPP_REGISTRATION_STATE_HOME_SMS_ONLY, 0x8B37, 0x0A265185, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 6, FALSE, FALSE };

    test_creg_match ("Ublox Toby-L2 unsolicited while on LTE", FALSE, reply, data, &result);
}

static void
test_cgreg1_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CGREG: 1,3";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 2, TRUE, FALSE };

    test_creg_match ("CGREG=1", TRUE, reply, data, &result);
}

static void
test_cgreg1_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 3\r\n";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 1, TRUE, FALSE };

    test_creg_match ("CGREG=1", FALSE, reply, data, &result);
}

static void
test_cgreg2_f3607gw_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CGREG: 2,1,\"8BE3\",\"00002B5D\",3";
    const CregResult result = { 1, 0x8BE3, 0x2B5D, MM_MODEM_ACCESS_TECHNOLOGY_EDGE, 8, TRUE, FALSE };

    test_creg_match ("Ericsson F3607gw CGREG=2", TRUE, reply, data, &result);
}

static void
test_cgreg2_f3607gw_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 1,\"8BE3\",\"00002B5D\",3\r\n";
    const CregResult result = { 1, 0x8BE3, 0x2B5D, MM_MODEM_ACCESS_TECHNOLOGY_EDGE, 6, TRUE, FALSE };

    test_creg_match ("Ericsson F3607gw CGREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_md400_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 2,5,\"0502\",\"0404736D\"\r\n";
    const CregResult result = { 5, 0x0502, 0x0404736D, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 4, FALSE, FALSE };

    test_creg_match ("Sony-Ericsson MD400 CREG=2", FALSE, reply, data, &result);
}

static void
test_cgreg2_md400_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 5,\"0502\",\"0404736D\",2\r\n";
    const CregResult result = { 5, 0x0502, 0x0404736D, MM_MODEM_ACCESS_TECHNOLOGY_UMTS, 6, TRUE, FALSE };

    test_creg_match ("Sony-Ericsson MD400 CGREG=2", FALSE, reply, data, &result);
}

static void
test_creg_cgreg_multi_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 5\r\n\r\n+CGREG: 0\r\n";
    const CregResult result = { 5, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 1, FALSE, FALSE };

    test_creg_match ("Multi CREG/CGREG", FALSE, reply, data, &result);
}

static void
test_creg_cgreg_multi2_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 0\r\n\r\n+CREG: 5\r\n";
    const CregResult result = { 0, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 1, TRUE, FALSE };

    test_creg_match ("Multi CREG/CGREG #2", FALSE, reply, data, &result);
}

static void
test_cgreg2_x220_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 2,1, 81ED, 1A9CEB\r\n";
    const CregResult result = { 1, 0x81ED, 0x1A9CEB, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 4, TRUE, FALSE };

    /* Tests random spaces in response */
    test_creg_match ("Alcatel One-Touch X220D CGREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_s8500_wave_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 2,1,000B,2816, B, C2816\r\n";
    const CregResult result = { 1, 0x000B, 0x2816, MM_MODEM_ACCESS_TECHNOLOGY_GSM, 9, FALSE, FALSE };

    test_creg_match ("Samsung Wave S8500 CREG=2", FALSE, reply, data, &result);
}

static void
test_creg2_gobi_weird_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CREG: 2,1,  0 5, 2715\r\n";
    const CregResult result = { 1, 0x0000, 0x2715, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 4, FALSE, FALSE };

    test_creg_match ("Qualcomm Gobi 1000 CREG=2", TRUE, reply, data, &result);
}

static void
test_cgreg2_unsolicited_with_rac (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 1,\"1422\",\"00000142\",3,\"00\"\r\n";
    const CregResult result = { 1, 0x1422, 0x0142, MM_MODEM_ACCESS_TECHNOLOGY_EDGE, 10, TRUE, FALSE };

    test_creg_match ("CGREG=2 with RAC", FALSE, reply, data, &result);
}

static void
test_cereg1_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CEREG: 1,3";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 2, FALSE, TRUE };

    test_creg_match ("CEREG=1", TRUE, reply, data, &result);
}

static void
test_cereg1_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 3\r\n";
    const CregResult result = { 3, 0, 0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN , 1, FALSE, TRUE };

    test_creg_match ("CEREG=1", FALSE, reply, data, &result);
}

static void
test_cereg2_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 2,1, 1F00, 79D903 ,7\r\n";
    const CregResult result = { 1, 0x1F00, 0x79D903, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 8, FALSE, TRUE };

    test_creg_match ("CEREG=2", TRUE, reply, data, &result);
}

static void
test_cereg2_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 1, 1F00, 79D903 ,7\r\n";
    const CregResult result = { 1, 0x1F00, 0x79D903, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 6, FALSE, TRUE };

    test_creg_match ("CEREG=2", FALSE, reply, data, &result);
}

static void
test_cereg2_altair_lte_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 1, 2, 0001, 00000100, 7\r\n";
    const CregResult result = { 2, 0x0001, 0x00000100, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 8, FALSE, TRUE };

    test_creg_match ("Altair LTE CEREG=2", FALSE, reply, data, &result);
}

static void
test_cereg2_altair_lte_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 2, 0001, 00000100, 7\r\n";
    const CregResult result = { 2, 0x0001, 0x00000100, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 6, FALSE, TRUE };

    test_creg_match ("Altair LTE CEREG=2", FALSE, reply, data, &result);
}

static void
test_cereg2_novatel_lte_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 2,1, 1F00, 20 ,79D903 ,7\r\n";
    const CregResult result = { 1, 0x1F00, 0x79D903, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 13, FALSE, TRUE };

    test_creg_match ("Novatel LTE E362 CEREG=2", TRUE, reply, data, &result);
}

static void
test_cereg2_novatel_lte_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CEREG: 1, 1F00, 20 ,79D903 ,7\r\n";
    const CregResult result = { 1, 0x1F00, 0x79D903, MM_MODEM_ACCESS_TECHNOLOGY_LTE, 12, FALSE, TRUE };

    test_creg_match ("Novatel LTE E362 CEREG=2", FALSE, reply, data, &result);
}

static void
test_cgreg2_thuraya_solicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "+CGREG: 1, \"0426\", \"F0,0F\"";
    const CregResult result = { 1, 0x0426, 0x00F0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 11, TRUE, FALSE };

    test_creg_match ("Thuraya solicited CREG=2", TRUE, reply, data, &result);
}

static void
test_cgreg2_thuraya_unsolicited (void *f, gpointer d)
{
    RegTestData *data = (RegTestData *) d;
    const char *reply = "\r\n+CGREG: 1, \"0426\", \"F0,0F\"\r\n";
    const CregResult result = { 1, 0x0426, 0x00F0, MM_MODEM_ACCESS_TECHNOLOGY_UNKNOWN, 11, TRUE, FALSE };

    test_creg_match ("Thuraya unsolicited CREG=2", FALSE, reply, data, &result);
}

/*****************************************************************************/
/* Test CSCS responses */

static void
test_cscs_icon225_support_response (void *f, gpointer d)
{
    const char *reply = "\r\n+CSCS: (\"IRA\",\"GSM\",\"UCS2\")\r\n";
    MMModemCharset charsets = MM_MODEM_CHARSET_UNKNOWN;
    gboolean success;

    success = mm_3gpp_parse_cscs_test_response (reply, &charsets);
    g_assert (success);

    g_assert (charsets == (MM_MODEM_CHARSET_IRA |
                           MM_MODEM_CHARSET_GSM |
                           MM_MODEM_CHARSET_UCS2));
}

static void
test_cscs_sierra_mercury_support_response (void *f, gpointer d)
{
    const char *reply = "\r\n+CSCS: (\"IRA\",\"GSM\",\"UCS2\",\"PCCP437\")\r\n";
    MMModemCharset charsets = MM_MODEM_CHARSET_UNKNOWN;
    gboolean success;

    success = mm_3gpp_parse_cscs_test_response (reply, &charsets);
    g_assert (success);

    g_assert (charsets == (MM_MODEM_CHARSET_IRA |
                           MM_MODEM_CHARSET_GSM |
                           MM_MODEM_CHARSET_UCS2 |
                           MM_MODEM_CHARSET_PCCP437));
}

static void
test_cscs_buslink_support_response (void *f, gpointer d)
{
    const char *reply = "\r\n+CSCS: (\"8859-1\",\"ASCII\",\"GSM\",\"UCS2\",\"UTF8\")\r\n";
    MMModemCharset charsets = MM_MODEM_CHARSET_UNKNOWN;
    gboolean success;

    success = mm_3gpp_parse_cscs_test_response (reply, &charsets);
    g_assert (success);

    g_assert (charsets == (MM_MODEM_CHARSET_8859_1 |
                           MM_MODEM_CHARSET_IRA |
                           MM_MODEM_CHARSET_GSM |
                           MM_MODEM_CHARSET_UCS2 |
                           MM_MODEM_CHARSET_UTF8));
}

static void
test_cscs_blackberry_support_response (void *f, gpointer d)
{
    const char *reply = "\r\n+CSCS: \"IRA\"\r\n";
    MMModemCharset charsets = MM_MODEM_CHARSET_UNKNOWN;
    gboolean success;

    success = mm_3gpp_parse_cscs_test_response (reply, &charsets);
    g_assert (success);

    g_assert (charsets == MM_MODEM_CHARSET_IRA);
}

/*****************************************************************************/
/* Test Device Identifier builders */

typedef struct {
    char *devid;
    char *desc;
    guint vid;
    guint pid;
    const char *ati;
    const char *ati1;
    const char *gsn;
    const char *revision;
    const char *model;
    const char *manf;
} DevidItem;

static DevidItem devids[] = {
    { "36e7a8e78637fd380b2664507ea5de8fc317d05b",
      "Huawei E1550",
      0x12d1, 0x1001,
      "\nManufacturer: huawei\n"
        "Model: E1550\n"
        "Revision: 11.608.09.01.21\n"
        "IMEI: 235012412595195\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      NULL,
      "\n235012412595195\n",
      "\n11.608.09.01.21\n",
      "\nE1550\n",
      "\nhuawei\n"
    },
    { "33b0fc4a06af5448df656ce12925979acf1cb600",
      "Huawei EC121",
      0x12d1, 0x1411,
      "\nManufacturer: HUAWEI INCORPORATED\n"
        "Model: EC121\n"
        "Revision: 11.100.17.00.114\n"
        "ESN: +GSN:12de4fa6\n"
        "+CIS707-A, +MS, +ES, +DS, +FCLASS\n",
      NULL,
      "\n12de4fa6\n",
      "\n11.100.17.00.114\n",
      "\nEC121\n",
      "\nHUAWEI INCORPORATED\n"
    },
    { "d17f016a402354eaa1e24855f4308fafca9cadb1",
      "Sierra USBConnect Mercury",
      0x1199, 0x6880,
      "\nManufacturer: Sierra Wireless, Inc.\n"
        "Model: C885\n"
        "Revision: J1_0_1_26AP C:/WS/FW/J1_0_1_26AP/MSM7200A/SRC/AMSS 2009/01/30 07:58:06\n"
        "IMEI: 987866969112306\n"
        "IMEI SV: 6\n"
        "FSN: D603478104511\n"
        "3GPP Release 6\n"
        "+GCAP: +CGSM,+DS,+ES\n",
      NULL,
      "\n987866969112306\n",
      "\nJ1_0_1_26AP C:/WS/FW/J1_0_1_26AP/MSM7200A/SRC/AMSS 2009/01/30 07:58:06\n",
      "\nC885\n",
      "\nSierra Wireless, Inc.\n"
    },
    { "345e9eaad7624393aca85cde9bd859edf462414c",
      "ZTE MF627",
      0x19d2, 0x0031,
      "\nManufacturer: ZTE INCORPORATED\n"
        "Model: MF627\n"
        "Revision: BD_3GHAP673A4V1.0.0B02\n"
        "IMEI: 023589923858188\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      NULL,
      "\n023589923858188\n",
      "\nBD_3GHAP673A4V1.0.0B02\n",
      "\nMF627\n",
      "\nZTE INCORPORATED\n"
    },
    { "69fa133a668b6f4dbf39b73500fd153ec240c73f",
      "Sony-Ericsson MD300",
      0x0fce, 0xd0cf,
      "\nMD300\n",
      "\nR3A018\n",
      "\n349583712939483\n",
      "\nR3A018\n",
      "\nMD300\n",
      "\nSony Ericsson\n"
    },
    { "3dad89ed7d774938c38188cf29cf1c211e9d360b",
      "Option iCON 7.2",
      0x0af0, 0x6901,
      "\nManufacturer: Option N.V.\n"
        "Model: GTM378\n"
        "Revision: 2.5.21Hd (Date: Jun 17 2008, Time: 12:30:47)\n",
      NULL,
      "\n129512359199159,SE393939TS\n",
      "\n2.5.21Hd (Date: Jun 17 2008, Time: 12:30:47)\n",
      "\nGTM378\n",
      "\nOption N.V.\n"
    },
    { "b0acccb956c9eaf2076e03697e74bf998dc44179",
      "ZTE MF622",
      0x19d2, 0x0001,
      NULL,
      NULL,
      "\n235251122555115\n",
      "\n3UKP671M3V1.0.0B08 3UKP671M3V1.0.0B08 1  [Jan 07 2008 16:00:00]\n",
      "\nMF622\n",
      "\nZTE INCORPORATED\n"
    },
    { "29a5b258f1dc6f50c66a1a9a1ecdde97560799ab",
      "Option 452",
      0x0af0, 0x7901,
      "\nManufacturer: Option N.V.\n"
        "Model: GlobeTrotter HSUPA Modem\n"
        "Revision: 2.12.0.0Hd (Date: Oct 29 2009, Time: 09:56:48)\n",
      "\nManufacturer: Option N.V.\n"
        "Model: GlobeTrotter HSUPA Modem\n"
        "Revision: 2.12.0.0Hd (Date: Oct 29 2009, Time: 09:56:48)\n",
      "\n000125491259519,PH2155R3TR\n",
      "\n2.12.0.0Hd (Date: Oct 29 2009, Time: 09:56:48)\n",
      "\nGlobeTrotter HSUPA Modem\n",
      "\nOption N.V.\n"
    },
    { "c756c67e960e693d5d221e381ea170b60bb9288f",
      "Novatel XU870",
      0x413c, 0x8118,
      "\nManufacturer: Novatel Wireless Incorporated\n"
        "Model: DELL XU870 ExpressCard\n"
        "Revision: 9.5.05.01-02  [2006-10-20 17:19:09]\n"
        "IMEI: 012051505051501\n"
        "+GCAP: +CGSM,+DS\n",
      "\nManufacturer: Novatel Wireless Incorporated\n"
        "Model: DELL XU870 ExpressCard\n"
        "Revision: 9.5.05.01-02  [2006-10-20 17:19:09]\n"
        "IMEI: 012051505051501\n"
        "+GCAP: +CGSM,+DS\n",
      "\n012051505051501\n",
      "\n9.5.05.01-02  [2006-10-20 17:19:09]\n",
      "\nDELL XU870 ExpressCard\n",
      "\nNovatel Wireless Incorporated\n"
    },
    { "4162ba918ab54b7776bccc3830e6c6b7a6738244",
      "Zoom 4596",
      0x1c9e, 0x9603,
      "\nManufacturer: Manufacturer\n"
        "Model: HSPA USB MODEM\n"
        "Revision: LQA0021.1.1_M573A\n"
        "IMEI: 239664699635121\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      "\nManufacturer: Manufacturer\n"
        "Model: HSPA USB MODEM\n"
        "Revision: LQA0021.1.1_M573A\n"
        "IMEI: 239664699635121\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      "\n239664699635121\n",
      "\nLQA0021.1.1_M573A\n",
      "\nHSPA USB MODEM\n",
      "\nManufacturer\n"
    },
    { "6d3a2fccd3588943a8962fd1e0d3ba752c706660",
      "C-MOTECH CDX-650",
      0x16d8, 0x6512,
      "\nManufacturer: C-MOTECH Co., Ltd.\r\r\n"
        "Model: CDX-650 \r\r\n"
        "Revision: CDX65UAC03\r\r\n"
        "Esn: 3B0C4B98\r\r\n"
        "+GCAP: +CIS707A, +MS, +ES, +DS, +FCLASS\r\n",
      "\nManufacturer: C-MOTECH Co., Ltd.\r\r\n"
        "Model: CDX-650 \r\r\n"
        "Revision: CDX65UAC03\r\r\n"
        "Esn: 3B0C4B98\r\r\n"
        "+GCAP: +CIS707A, +MS, +ES, +DS, +FCLASS\r\n",
      "\n0x3B0C4B98\n",
      "\nCDX65UAC03  1  [Oct 17 2007 13:30:00]\n",
      "\nModel CDX-650 \n",
      "\nC-MOTECH Co., Ltd.\n"
    },
    { "cf50da63e6d48beb1d1c3b41d70ef6fa534c3e13",
      "BUSlink SCWi275u",
      0x22b8, 0x3802,
      "\n144\n",
      "\n000\n",
      NULL,
      "\n\"ADE_05_00_06032300I\"\n",
      "\n\"GSM900\",\"GSM1800\",\"GSM1900\",\"GSM850\",\"MODEL=I250-000\"\n",
      "\n\"Motorola CE, Copyright 2000\"\n"
    },
    { "2aff568f2b60f3d6f3f6cac708ed5dce77b12b96",
      "Motorola ROKR E2",
      0x22b8, 0x3802,
      NULL,
      NULL,
      "\n\"626936926396996\"\n",
      "\n\"R564_G_12.00.47P\"\n",
      "\n\"E2\"\n",
      "\n\"Motorola\"\n"
    },
    { "a7136c6067a43f055ca093cee75cb98ce6c9658e",
      "Sony-Ericsson W580i",
      0x0fce, 0xd089,
      "\nSony Ericsson W580\n",
      "\nCXC1123481\n",
      "\n012505051512505\n",
      "\nR8BE001 080115 1451 CXC1123481_NAM_1_LA\n",
      "\nAAC-1052042-BV\n",
      "\nSony Ericsson\n"
    },
    { "b80ee70214bdf9672f2a268ce165ecfd9def5721",
      "Huawei E226",
      0x12d1, 0x1003,
      "\nManufacturer: huawei\n"
        "Model: E226\n"
        "Revision: 11.310.15.00.150\n"
        "IMEI: 232363662362362\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      "\nManufacturer: huawei\n"
        "Model: E226\n"
        "Revision: 11.310.15.00.150\n"
        "IMEI: 232363662362362\n"
        "+GCAP: +CGSM,+FCLASS,+DS\n",
      "\n232363662362362\n",
      "\n11.310.15.00.150\n",
      "\nE226\n",
      "\nhuawei\n"
    },
    { "d902e1f234863aa107bfc2d0faefbee5ed6901f1",
      "LG LX265",
      0x1004, 0x6000,
      "\nManufacturer: +GMI: LG Electronics Inc.\n"
        "Model: +GMI: LG Electronics Inc.+GMM: Model:LG-LX265\n"
        "Revision: +GMR: LX265V05, 50571\n"
        "ESN: +GSN: 0x9235EB52\n"
        "+GCAP: +CIS707-A, +MS, +ES, +DS, +FCLASS\n",
      "\nManufacturer: +GMI: LG Electronics Inc.\n"
        "Model: +GMI: LG Electronics Inc.+GMM: Model:LG-LX265\n"
        "Revision: +GMR: LX265V05, 50571\n"
        "ESN: +GSN: 0x9235EB52\n"
        "+GCAP: +CIS707-A, +MS, +ES, +DS, +FCLASS\n",
      "\n0x9235EB52\n",
      "\nLX265V05, 50571\n",
      "\nModel:LG-LX265\n",
      "\nLG Electronics Inc.\n"
    },
    { "543c2920e450e20a46368861fdec3a3b97ba8663",
      "Nokia 2720a BT",
      0x0000, 0x0000,
      "\nNokia\n",
      "\n012350150101501\n",
      "\n012350150101501\n",
      "\nV 08.62\n"
        "24-07-09\n"
        "RM-520\n"
        "(c) Nokia            \n",
      "\nNokia 2720a-2b\n",
      "\nNokia\n"
    },
    { "6386ffa7a39ced3c9bfd1d693b90975661e54a86",
      "Gobi 1000",
      0x03f0, 0x1f1d,
      "\nManufacturer: QUALCOMM INCORPORATED\n"
        "Model: 88\n"
        "Revision: D1020-SUUAASFA-4352  1  [Apr 14 2008 18:00:00]\n"
        "IMEI: 239639269236269\n"
        "+GCAP: +CGSM,+DS\n",
      "\nManufacturer: QUALCOMM INCORPORATED\n"
        "Model: 88\n"
        "Revision: D1020-SUUAASFA-4352  1  [Apr 14 2008 18:00:00]\n"
        "IMEI: 239639269236269\n"
        "+GCAP: +CGSM,+DS\n",
      "\n239639269236269\n",
      "\nD1020-SUUAASFA-4352  1  [Apr 14 2008 18:00:00]\n",
      "\n88\n",
      "\nQUALCOMM INCORPORATED\n"
    },
    { NULL }
};

static void
test_devid_item (void *f, gpointer d)
{
    DevidItem *item = (DevidItem *) d;
    char *devid;

    trace ("%s... ", item->desc);
    devid = mm_create_device_identifier (item->vid,
                                         item->pid,
                                         item->ati,
                                         item->ati1,
                                         item->gsn,
                                         item->revision,
                                         item->model,
                                         item->manf);
    g_assert (devid);
    if (strcmp (devid, item->devid))
        g_message ("%s", devid);
    g_assert (!strcmp (devid, item->devid));
    g_free (devid);
}

/*****************************************************************************/
/* Test CMER test responses */

static void
test_cmer_response (const gchar    *str,
                    MM3gppCmerMode  expected_modes,
                    MM3gppCmerInd   expected_inds)
{
    gboolean        ret;
    MM3gppCmerMode  modes = MM_3GPP_CMER_MODE_NONE;
    MM3gppCmerInd   inds = MM_3GPP_CMER_IND_NONE;
    GError         *error = NULL;

    ret = mm_3gpp_parse_cmer_test_response (str, &modes, &inds, &error);
    g_assert_no_error (error);
    g_assert (ret);

    g_assert_cmpuint (modes, ==, expected_modes);
    g_assert_cmpuint (inds,  ==, expected_inds);
}

static void
test_cmer_response_cinterion_pls8 (void)
{
    static const gchar *str = "+CMER: (0-3),(0),(0),(0-1),(0-1)";
    static const MM3gppCmerMode expected_modes = (        \
        MM_3GPP_CMER_MODE_DISCARD_URCS |                  \
        MM_3GPP_CMER_MODE_DISCARD_URCS_IF_LINK_RESERVED | \
        MM_3GPP_CMER_MODE_BUFFER_URCS_IF_LINK_RESERVED |  \
        MM_3GPP_CMER_MODE_FORWARD_URCS);
    static const MM3gppCmerInd expected_inds = (        \
        MM_3GPP_CMER_IND_DISABLE |                      \
        MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND);

    test_cmer_response (str, expected_modes, expected_inds);
}

static void
test_cmer_response_sierra_em7345 (void)
{
    static const gchar *str = "+CMER: 1,0,0,(0-1),0";
    static const MM3gppCmerMode expected_modes = (          \
        MM_3GPP_CMER_MODE_DISCARD_URCS_IF_LINK_RESERVED);
    static const MM3gppCmerInd expected_inds = (        \
        MM_3GPP_CMER_IND_DISABLE |                      \
        MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND);

    test_cmer_response (str, expected_modes, expected_inds);
}

static void
test_cmer_response_cinterion_ehs5 (void)
{
    static const gchar *str = "+CMER: (1,2),0,0,(0-1),0";
    static const MM3gppCmerMode expected_modes = (        \
        MM_3GPP_CMER_MODE_DISCARD_URCS_IF_LINK_RESERVED | \
        MM_3GPP_CMER_MODE_BUFFER_URCS_IF_LINK_RESERVED);
    static const MM3gppCmerInd expected_inds = (        \
        MM_3GPP_CMER_IND_DISABLE |                      \
        MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND);

    test_cmer_response (str, expected_modes, expected_inds);
}

static void
test_cmer_request_cinterion_ehs5 (void)
{
    gchar *str;

    str = mm_3gpp_build_cmer_set_request (MM_3GPP_CMER_MODE_BUFFER_URCS_IF_LINK_RESERVED, MM_3GPP_CMER_IND_ENABLE_NOT_CAUSED_BY_CIND);
    g_assert_cmpstr (str, ==, "+CMER=2,0,0,1");
    g_free (str);
}

/*****************************************************************************/
/* Test CIND responses */

typedef struct {
    const char *desc;
    const gint min;
    const gint max;
} CindEntry;

static void
test_cind_results (const char *desc,
                   const char *reply,
                   CindEntry *expected_results,
                   guint32 expected_results_len)
{
    guint i;
    GError *error = NULL;
    GHashTable *results;

    trace ("\nTesting %s +CIND response...\n", desc);

    results = mm_3gpp_parse_cind_test_response (reply, &error);
    g_assert (results);
    g_assert (error == NULL);

    g_assert (g_hash_table_size (results) == expected_results_len);

    for (i = 0; i < expected_results_len; i++) {
        CindEntry *expected = &expected_results[i];
        MM3gppCindResponse *compare;

        compare = g_hash_table_lookup (results, expected->desc);
        g_assert (compare);
        g_assert_cmpint (i + 1, ==, mm_3gpp_cind_response_get_index (compare));
        g_assert_cmpint (expected->min, ==, mm_3gpp_cind_response_get_min (compare));
        g_assert_cmpint (expected->max, ==, mm_3gpp_cind_response_get_max (compare));
    }

    g_hash_table_destroy (results);
}

static void
test_cind_response_linktop_lw273 (void *f, gpointer d)
{
    const char *reply = "+CIND: (\"battchg\",(0-5)),(\"signal\",(0-5)),(\"batterywarning\",(0-1)),(\"chargerconnected\",(0-1)),(\"service\",(0-1)),(\"sounder\",(0-1)),(\"message\",(0-1)),()";
    static CindEntry expected[] = {
        { "battchg", 0, 5 },
        { "signal", 0, 5 },
        { "batterywarning", 0, 1 },
        { "chargerconnected", 0, 1 },
        { "service", 0, 1 },
        { "sounder", 0, 1 },
        { "message", 0, 1 }
    };

    test_cind_results ("LW273", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cind_response_moto_v3m (void *f, gpointer d)
{
    const char *reply = "+CIND: (\"Voice Mail\",(0,1)),(\"service\",(0,1)),(\"call\",(0,1)),(\"Roam\",(0-2)),(\"signal\",(0-5)),(\"callsetup\",(0-3)),(\"smsfull\",(0,1))";
    static CindEntry expected[] = {
        { "voicemail", 0, 1 },
        { "service", 0, 1 },
        { "call", 0, 1 },
        { "roam", 0, 2 },
        { "signal", 0, 5 },
        { "callsetup", 0, 3 },
        { "smsfull", 0, 1 }
    };

    test_cind_results ("Motorola V3m", reply, &expected[0], G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test ICCID parsing */

static void
test_iccid_parse_quoted_swap_19_digit (void *f, gpointer d)
{
    const char *raw_iccid = "\"984402003576012594F9\"";
    const char *expected = "8944200053671052499";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (parsed, ==, expected);
    g_free (parsed);
}

static void
test_iccid_parse_unquoted_swap_20_digit (void *f, gpointer d)
{
    const char *raw_iccid = "98231420326409614067";
    const char *expected = "89324102234690160476";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (parsed, ==, expected);
    g_free (parsed);
}

static void
test_iccid_parse_unquoted_unswapped_19_digit (void *f, gpointer d)
{
    const char *raw_iccid = "8944200053671052499F";
    const char *expected = "8944200053671052499";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (parsed, ==, expected);
    g_free (parsed);
}

static void
test_iccid_parse_quoted_unswapped_20_digit (void *f, gpointer d)
{
    const char *raw_iccid = "\"89324102234690160476\"";
    const char *expected = "89324102234690160476";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert_no_error (error);
    g_assert_cmpstr (parsed, ==, expected);
    g_free (parsed);
}

static void
test_iccid_parse_short (void *f, gpointer d)
{
    const char *raw_iccid = "982314203264096";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert (parsed == NULL);
    g_assert_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED);
    g_error_free (error);
}

static void
test_iccid_parse_invalid_chars (void *f, gpointer d)
{
    const char *raw_iccid = "98231420326ab9614067";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert (parsed == NULL);
    g_assert_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED);
    g_error_free (error);
}

static void
test_iccid_parse_quoted_invalid_mii (void *f, gpointer d)
{
    const char *raw_iccid = "\"0044200053671052499\"";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert (parsed == NULL);
    g_assert_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED);
    g_error_free (error);
}

static void
test_iccid_parse_unquoted_invalid_mii (void *f, gpointer d)
{
    const char *raw_iccid = "0044200053671052499";
    char *parsed;
    GError *error = NULL;

    parsed = mm_3gpp_parse_iccid (raw_iccid, &error);
    g_assert (parsed == NULL);
    g_assert_error (error, MM_CORE_ERROR, MM_CORE_ERROR_FAILED);
    g_error_free (error);
}

/*****************************************************************************/
/* Test APN cmp */

typedef struct {
    const gchar *existing;
    const gchar *requested;
    gboolean     match_expected;
} TestApnCmp;

static const TestApnCmp test_apn_cmp[] = {
    { "m2m.com.attz",                      "m2m.com.attz",                      TRUE  },
    { "m2m.com.attz",                      "M2M.COM.ATTZ",                      TRUE  },
    { "M2M.COM.ATTZ",                      "m2m.com.attz",                      TRUE  },
    { "m2m.com.attz.mnc170.mcc310.gprs",   "m2m.com.attz",                      TRUE  },
    { "ac.vodafone.es.MNC001.MCC214.GPRS", "ac.vodafone.es",                    TRUE  },
    { "m2m.com.attz",                      "m2m.com.attz.mnc170.mcc310.gprs",   FALSE },
    { "ac.vodafone.es",                    "ac.vodafone.es.MNC001.MCC214.GPRS", FALSE },
    { "internet.test",                     "internet",                          FALSE },
    { "internet.test",                     "INTERNET",                          FALSE },
    { "internet.test",                     "internet.tes",                      FALSE },
    { "",                                  "",                                  FALSE },
};

static void
test_cmp_apn_name (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (test_apn_cmp); i++) {
        g_debug ("Comparing requested '%s' vs existing '%s': %s match",
                 test_apn_cmp[i].requested,
                 test_apn_cmp[i].existing,
                 test_apn_cmp[i].match_expected ? "should" : "shouldn't");
        g_assert (mm_3gpp_cmp_apn_name (test_apn_cmp[i].requested, test_apn_cmp[i].existing) == test_apn_cmp[i].match_expected);
    }
}

/*****************************************************************************/
/* Test CGDCONT test responses */

static void
test_cgdcont_test_results (const gchar *desc,
                           const gchar *reply,
                           MM3gppPdpContextFormat *expected_results,
                           guint32 expected_results_len)
{
    GList *l;
    GError *error = NULL;
    GList *results;

    trace ("\nTesting %s +CGDCONT test response...\n", desc);

    results = mm_3gpp_parse_cgdcont_test_response (reply, &error);
    g_assert (results);
    g_assert_no_error (error);
    g_assert_cmpuint (g_list_length (results), ==, expected_results_len);

    for (l = results; l; l = g_list_next (l)) {
        MM3gppPdpContextFormat *format = l->data;
        gboolean found = FALSE;
        guint i;

        for (i = 0; !found && i < expected_results_len; i++) {
            MM3gppPdpContextFormat *expected;

            expected = &expected_results[i];
            if (format->pdp_type == expected->pdp_type) {
                found = TRUE;

                g_assert_cmpuint (format->min_cid, ==, expected->min_cid);
                g_assert_cmpuint (format->max_cid, ==, expected->max_cid);
            }
        }

        g_assert (found == TRUE);
    }

    mm_3gpp_pdp_context_format_list_free (results);
}

static void
test_cgdcont_test_response_single (void *f, gpointer d)
{
    const gchar *reply = "+CGDCONT: (1-10),\"IP\",,,(0,1),(0,1)";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 10, MM_BEARER_IP_FAMILY_IPV4 }
    };

    test_cgdcont_test_results ("Single", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgdcont_test_response_multiple (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: (1-10),\"IP\",,,(0,1),(0,1)\r\n"
        "+CGDCONT: (1-10),\"IPV6\",,,(0,1),(0,1)\r\n"
        "+CGDCONT: (1-10),\"IPV4V6\",,,(0,1),(0,1)\r\n";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 10, MM_BEARER_IP_FAMILY_IPV4 },
        { 1, 10, MM_BEARER_IP_FAMILY_IPV6 },
        { 1, 10, MM_BEARER_IP_FAMILY_IPV4V6 }
    };

    test_cgdcont_test_results ("Multiple", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgdcont_test_response_multiple_and_ignore (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: (1-16),\"IP\",,,(0-2),(0-4)\r\n"
        "+CGDCONT: (1-16),\"PPP\",,,(0-2),(0-4)\r\n"
        "+CGDCONT: (1-16),\"IPV6\",,,(0-2),(0-4)\r\n";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 16, MM_BEARER_IP_FAMILY_IPV4 },
        /* PPP is ignored */
        { 1, 16, MM_BEARER_IP_FAMILY_IPV6 }
    };

    test_cgdcont_test_results ("Multiple and Ignore", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgdcont_test_response_single_context (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: (1),\"IP\",,,(0),(0)\r\n"
        "+CGDCONT: (1),\"IPV6\",,,(0),(0)\r\n";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 1, MM_BEARER_IP_FAMILY_IPV4 },
        { 1, 1, MM_BEARER_IP_FAMILY_IPV6 }
    };

    test_cgdcont_test_results ("Single Context", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgdcont_test_response_thuraya (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: ( 1 ) , \"IP\" ,,, (0-2),(0-3)\r\n"
        "+CGDCONT: , \"PPP\" ,,, (0-2),(0-3)\r\n";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 1, MM_BEARER_IP_FAMILY_IPV4 }
    };

    test_cgdcont_test_results ("Thuraya", reply, &expected[0], G_N_ELEMENTS (expected));
}


static void
test_cgdcont_test_response_cinterion_phs8 (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: (1-17,101-116),\"IP\",,,(0),(0-4)\r\n";
    static MM3gppPdpContextFormat expected[] = {
        { 1, 17, MM_BEARER_IP_FAMILY_IPV4 }
    };

    test_cgdcont_test_results ("Cinterion PHS8-USA REVISION 03.001", reply, &expected[0], G_N_ELEMENTS (expected));
}



/*****************************************************************************/
/* Test CGDCONT read responses */

static void
test_cgdcont_read_results (const gchar *desc,
                           const gchar *reply,
                           MM3gppPdpContext *expected_results,
                           guint32 expected_results_len)
{
    GList *l;
    GError *error = NULL;
    GList *results;

    trace ("\nTesting %s +CGDCONT response...\n", desc);

    results = mm_3gpp_parse_cgdcont_read_response (reply, &error);
    g_assert (results);
    g_assert_no_error (error);
    g_assert_cmpuint (g_list_length (results), ==, expected_results_len);

    for (l = results; l; l = g_list_next (l)) {
        MM3gppPdpContext *pdp = l->data;
        gboolean found = FALSE;
        guint i;

        for (i = 0; !found && i < expected_results_len; i++) {
            MM3gppPdpContext *expected;

            expected = &expected_results[i];
            if (pdp->cid == expected->cid) {
                found = TRUE;

                g_assert_cmpuint (pdp->pdp_type, ==, expected->pdp_type);
                g_assert_cmpstr (pdp->apn, ==, expected->apn);
            }
        }

        g_assert (found == TRUE);
    }

    mm_3gpp_pdp_context_list_free (results);
}

static void
test_cgdcont_read_response_nokia (void *f, gpointer d)
{
    const gchar *reply = "+CGDCONT: 1,\"IP\",,,0,0";
    static MM3gppPdpContext expected[] = {
        { 1, MM_BEARER_IP_FAMILY_IPV4, NULL }
    };

    test_cgdcont_read_results ("Nokia", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgdcont_read_response_samsung (void *f, gpointer d)
{
    const gchar *reply =
        "+CGDCONT: 1,\"IP\",\"nate.sktelecom.com\",\"\",0,0\r\n"
        "+CGDCONT: 2,\"IP\",\"epc.tmobile.com\",\"\",0,0\r\n"
        "+CGDCONT: 3,\"IP\",\"MAXROAM.com\",\"\",0,0\r\n";
    static MM3gppPdpContext expected[] = {
        { 1, MM_BEARER_IP_FAMILY_IPV4, "nate.sktelecom.com" },
        { 2, MM_BEARER_IP_FAMILY_IPV4, "epc.tmobile.com"    },
        { 3, MM_BEARER_IP_FAMILY_IPV4, "MAXROAM.com"        }
    };

    test_cgdcont_read_results ("Samsung", reply, &expected[0], G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test CGDCONT read responses */

static void
test_cgact_read_results (const gchar *desc,
                         const gchar *reply,
                         MM3gppPdpContextActive *expected_results,
                         guint32 expected_results_len)
{
    GList *l;
    GError *error = NULL;
    GList *results;

    trace ("\nTesting %s +CGACT response...\n", desc);

    results = mm_3gpp_parse_cgact_read_response (reply, &error);
    g_assert_no_error (error);
    if (expected_results_len) {
        g_assert (results);
        g_assert_cmpuint (g_list_length (results), ==, expected_results_len);
    }

    for (l = results; l; l = g_list_next (l)) {
        MM3gppPdpContextActive *pdp = l->data;
        gboolean found = FALSE;
        guint i;

        for (i = 0; !found && i < expected_results_len; i++) {
            MM3gppPdpContextActive *expected;

            expected = &expected_results[i];
            if (pdp->cid == expected->cid) {
                found = TRUE;
                g_assert_cmpuint (pdp->active, ==, expected->active);
            }
        }

        g_assert (found == TRUE);
    }

    mm_3gpp_pdp_context_active_list_free (results);
}

static void
test_cgact_read_response_none (void)
{
    test_cgact_read_results ("none", "", NULL, 0);
}

static void
test_cgact_read_response_single_inactive (void)
{
    const gchar *reply = "+CGACT: 1,0\r\n";
    static MM3gppPdpContextActive expected[] = {
        { 1, FALSE },
    };

    test_cgact_read_results ("single inactive", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgact_read_response_single_active (void)
{
    const gchar *reply = "+CGACT: 1,1\r\n";
    static MM3gppPdpContextActive expected[] = {
        { 1, TRUE },
    };

    test_cgact_read_results ("single active", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgact_read_response_multiple (void)
{
    const gchar *reply =
        "+CGACT: 1,0\r\n"
        "+CGACT: 4,1\r\n"
        "+CGACT: 5,0\r\n";
    static MM3gppPdpContextActive expected[] = {
        { 1, FALSE },
        { 4, TRUE },
        { 5, FALSE },
    };

    test_cgact_read_results ("multiple", reply, &expected[0], G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test CGPADDR exec responses */

static void
test_cgpaddr_exec_results (const gchar                   *desc,
                           const gchar                   *reply,
                           const MM3gppPdpContextAddress *expected_results,
                           guint32                        expected_results_len)
{
    GList  *l;
    GError *error = NULL;
    GList  *results;

    trace ("\nTesting %s +CGPADDR response...\n", desc);

    results = mm_3gpp_parse_cgpaddr_exec_response (reply, &error);
    g_assert_no_error (error);
    if (expected_results_len) {
        g_assert (results);
        g_assert_cmpuint (g_list_length (results), ==, expected_results_len);
    }

    for (l = results; l; l = g_list_next (l)) {
        MM3gppPdpContextAddress *pdp = l->data;
        gboolean found = FALSE;
        guint i;

        for (i = 0; !found && i < expected_results_len; i++) {
            const MM3gppPdpContextAddress *expected;

            expected = &expected_results[i];
            if (pdp->cid == expected->cid) {
                found = TRUE;
                g_assert_cmpstr (pdp->address, ==, expected->address);
            }
        }

        g_assert (found == TRUE);
    }

    mm_3gpp_pdp_context_address_list_free (results);
}

static void
test_cgpaddr_exec_response_none (void)
{
    test_cgpaddr_exec_results ("none", "", NULL, 0);
}

static void
test_cgpaddr_exec_response_single_context_single_address (void)
{
    const gchar *reply = "+CGPADDR: 1,98.99.100.101\r\n";
    static const MM3gppPdpContextAddress expected[] = {
        { 1, "98.99.100.101" },
    };

    test_cgpaddr_exec_results ("single context, single address", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgpaddr_exec_response_single_context_multiple_addresses (void)
{
    const gchar *reply = "+CGPADDR: 1,98.99.100.101,123.124.125.126\r\n";
    static const MM3gppPdpContextAddress expected[] = {
        { 1, "98.99.100.101" },
    };

    test_cgpaddr_exec_results ("single context, multiple addresses", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgpaddr_exec_response_multiple_contexts_single_address (void)
{
    const gchar *reply =
        "+CGPADDR: 1,98.99.100.101\r\n"
        "+CGPADDR: 4,98.99.100.102\r\n"
        "+CGPADDR: 5,98.99.100.103\r\n";
    static MM3gppPdpContextAddress expected[] = {
        { 1, "98.99.100.101" },
        { 4, "98.99.100.102" },
        { 5, "98.99.100.103" },
    };

    test_cgpaddr_exec_results ("multiple context, single address", reply, &expected[0], G_N_ELEMENTS (expected));
}

static void
test_cgpaddr_exec_response_multiple_contexts_multiple_addresses (void)
{
    const gchar *reply =
        "+CGPADDR: 1,98.99.100.101,123.124.125.126\r\n"
        "+CGPADDR: 4,98.99.100.102\r\n"
        "+CGPADDR: 5,98.99.100.103,123.124.125.127\r\n";
    static MM3gppPdpContextAddress expected[] = {
        { 1, "98.99.100.101" },
        { 4, "98.99.100.102" },
        { 5, "98.99.100.103" },
    };

    test_cgpaddr_exec_results ("multiple context, single address", reply, &expected[0], G_N_ELEMENTS (expected));
}

/*****************************************************************************/
/* Test CPMS responses */

static gboolean
is_storage_supported (GArray *supported,
                      MMSmsStorage storage)
{
    guint i;

    for (i = 0; i < supported->len; i++) {
        if (storage == g_array_index (supported, MMSmsStorage, i))
            return TRUE;
    }

    return FALSE;
}

static void
test_cpms_response_cinterion (void *f, gpointer d)
{
    /* Use different sets for each on purpose, even if weird */
    const gchar *reply = "+CPMS: (\"ME\",\"MT\"),(\"ME\",\"SM\",\"MT\"),(\"SM\",\"MT\")";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting Cinterion +CPMS=? response...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 2);
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_ME));
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_MT));
    g_assert_cmpuint (mem2->len, ==, 3);
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_ME));
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_SM));
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_MT));
    g_assert_cmpuint (mem3->len, ==, 2);
    g_assert (is_storage_supported (mem3, MM_SMS_STORAGE_SM));
    g_assert (is_storage_supported (mem3, MM_SMS_STORAGE_MT));

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

static void
test_cpms_response_huawei_mu609 (void *f, gpointer d)
{
    /* Use different sets for each on purpose, even if weird */
    const gchar *reply = "+CPMS: \"ME\",\"MT\",\"SM\"";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting Huawei MU609 +CPMS=? response...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 1);
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_ME));
    g_assert_cmpuint (mem2->len, ==, 1);
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_MT));
    g_assert_cmpuint (mem3->len, ==, 1);
    g_assert (is_storage_supported (mem3, MM_SMS_STORAGE_SM));

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

static void
test_cpms_response_nokia_c6 (void *f, gpointer d)
{
    /* Use different sets for each on purpose, even if weird */
    const gchar *reply = "+CPMS: (),(),()";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting Nokia C6 response...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 0);
    g_assert_cmpuint (mem2->len, ==, 0);
    g_assert_cmpuint (mem3->len, ==, 0);

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

static void
test_cpms_response_mixed (void *f, gpointer d)
{
    /*
     * First:    ("ME","MT")  2-item group
     * Second:   "ME"         1 item
     * Third:    ("SM")       1-item group
     */
    const gchar *reply = "+CPMS: (\"ME\",\"MT\"),\"ME\",(\"SM\")";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting mixed +CPMS=? response...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 2);
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_ME));
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_MT));
    g_assert_cmpuint (mem2->len, ==, 1);
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_ME));
    g_assert_cmpuint (mem3->len, ==, 1);
    g_assert (is_storage_supported (mem3, MM_SMS_STORAGE_SM));

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

static void
test_cpms_response_mixed_spaces (void *f, gpointer d)
{
    /* Test with whitespaces here and there */
    const gchar *reply = "+CPMS:     (  \"ME\"  ,  \"MT\"  )   ,  \"ME\" ,   (  \"SM\"  )";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting mixed +CPMS=? response with spaces...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 2);
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_ME));
    g_assert (is_storage_supported (mem1, MM_SMS_STORAGE_MT));
    g_assert_cmpuint (mem2->len, ==, 1);
    g_assert (is_storage_supported (mem2, MM_SMS_STORAGE_ME));
    g_assert_cmpuint (mem3->len, ==, 1);
    g_assert (is_storage_supported (mem3, MM_SMS_STORAGE_SM));

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

static void
test_cpms_response_empty_fields (void *f, gpointer d)
{
    /*
     * First:    ()    Empty group
     * Second:         Empty item
     * Third:    (  )  Empty group with spaces
     */
    const gchar *reply = "+CPMS: (),,(  )";
    GArray *mem1 = NULL;
    GArray *mem2 = NULL;
    GArray *mem3 = NULL;

    trace ("\nTesting mixed +CPMS=? response...\n");

    g_assert (mm_3gpp_parse_cpms_test_response (reply, &mem1, &mem2, &mem3));
    g_assert_cmpuint (mem1->len, ==, 0);
    g_assert_cmpuint (mem2->len, ==, 0);
    g_assert_cmpuint (mem3->len, ==, 0);

    g_array_unref (mem1);
    g_array_unref (mem2);
    g_array_unref (mem3);
}

typedef struct {
    const gchar *query;
    MMSmsStorage mem1_want;
    MMSmsStorage mem2_want;
} CpmsQueryTest;

CpmsQueryTest cpms_query_test[] = {
    {"+CPMS: \"ME\",1,100,\"MT\",5,100,\"TA\",1,100", 2, 3},
    {"+CPMS: \"SM\",100,100,\"SR\",5,10,\"TA\",1,100", 1, 4},
    {"+CPMS: \"XX\",100,100,\"BM\",5,10,\"TA\",1,100", 0, 5},
    {"+CPMS: \"XX\",100,100,\"YY\",5,10,\"TA\",1,100", 0, 0},
    {NULL, 0, 0}
};

static void
test_cpms_query_response (void *f, gpointer d) {
    MMSmsStorage mem1;
    MMSmsStorage mem2;
    gboolean ret;
    GError *error = NULL;
    int i;

    for (i = 0; cpms_query_test[i].query != NULL; i++){
        ret = mm_3gpp_parse_cpms_query_response (cpms_query_test[i].query,
                                                 &mem1,
                                                 &mem2,
                                                 &error);
        g_assert (ret);
        g_assert_no_error (error);
        g_assert_cmpuint (cpms_query_test[i].mem1_want, ==, mem1);
        g_assert_cmpuint (cpms_query_test[i].mem2_want, ==, mem2);
    }
}

/*****************************************************************************/
/* Test CNUM responses */

static void
test_cnum_results (const gchar *desc,
                   const gchar *reply,
                   const GStrv expected)
{
    GStrv results;
    guint i;

    trace ("\nTesting +CNUM response (%s)...\n", desc);

    results = mm_3gpp_parse_cnum_exec_response (reply);
    g_assert (results);
    g_assert_cmpuint (g_strv_length (results), ==, g_strv_length (expected));

    for (i = 0; results[i]; i++) {
        guint j;

        for (j = 0; expected[j]; j++) {
            if (g_str_equal (results[i], expected[j]))
                break;
        }

        /* Ensure the result is found in the expected list */
        g_assert (expected[j]);
    }

    g_strfreev (results);
}

static void
test_cnum_response_generic (void *f, gpointer d)
{
    const gchar *reply = "+CNUM: \"something\",\"1234567890\",161";
    const gchar *expected[] = {
        "1234567890",
        NULL
    };

    test_cnum_results ("Generic", reply, (GStrv)expected);
}

static void
test_cnum_response_generic_without_detail (void *f, gpointer d)
{
    const gchar *reply = "+CNUM: ,\"1234567890\",161";
    const gchar *expected[] = {
        "1234567890",
        NULL
    };

    test_cnum_results ("Generic, without detail", reply, (GStrv)expected);
}

static void
test_cnum_response_generic_detail_unquoted (void *f, gpointer d)
{
    const gchar *reply = "+CNUM: something,\"1234567890\",161";
    const gchar *expected[] = {
        "1234567890",
        NULL
    };

    test_cnum_results ("Generic, detail unquoted", reply, (GStrv)expected);
}

static void
test_cnum_response_generic_international_number (void *f, gpointer d)
{
    const gchar *reply = "+CNUM: something,\"+34600000001\",145";
    const gchar *expected[] = {
        "+34600000001",
        NULL
    };

    test_cnum_results ("Generic, international number", reply, (GStrv)expected);
}

static void
test_cnum_response_generic_multiple_numbers (void *f, gpointer d)
{
    const gchar *reply =
        "+CNUM: something,\"+34600000001\",145\r\n"
        "+CNUM: ,\"+34600000002\",145\r\n"
        "+CNUM: \"another\",\"1234567890\",161";
    const gchar *expected[] = {
        "+34600000001",
        "+34600000002",
        "1234567890",
        NULL
    };

    test_cnum_results ("Generic, multiple numbers", reply, (GStrv)expected);
}

/*****************************************************************************/
/* Test operator ID parsing */

static void
common_parse_operator_id (const gchar *operator_id,
                          gboolean expected_success,
                          guint16 expected_mcc,
                          guint16 expected_mnc)
{
    guint16 mcc;
    guint16 mnc;
    gboolean result;
    GError *error = NULL;

    if (expected_mcc) {
        trace ("\nParsing Operator ID '%s' "
               "(%" G_GUINT16_FORMAT ", %" G_GUINT16_FORMAT  ")...\n",
               operator_id, expected_mcc, expected_mnc);
        result = mm_3gpp_parse_operator_id (operator_id, &mcc, &mnc, &error);
    } else {
        trace ("\nValidating Operator ID '%s'...\n", operator_id);
        result = mm_3gpp_parse_operator_id (operator_id, NULL, NULL, &error);
    }

    if (error)
        trace ("\tGot %s error: %s...\n",
               expected_success ? "unexpected" : "expected",
               error->message);

    g_assert (result == expected_success);

    if (expected_success) {
        g_assert_no_error (error);
        if (expected_mcc) {
            g_assert_cmpuint (expected_mcc, ==, mcc);
            g_assert_cmpuint (expected_mnc, ==, mnc);
        }
    } else {
        g_assert (error != NULL);
        g_error_free (error);
    }
}


static void
test_parse_operator_id (void *f, gpointer d)
{
    trace ("\n");
    /* Valid MCC+MNC(2) */
    common_parse_operator_id ("41201",  TRUE, 412, 1);
    common_parse_operator_id ("41201",  TRUE, 0, 0);
    /* Valid MCC+MNC(3) */
    common_parse_operator_id ("342600", TRUE, 342, 600);
    common_parse_operator_id ("342600", TRUE, 0, 0);
    /* Valid MCC+MNC(2, == 0) */
    common_parse_operator_id ("72400", TRUE, 724, 0);
    common_parse_operator_id ("72400", TRUE, 0, 0);
    /* Valid MCC+MNC(3, == 0) */
    common_parse_operator_id ("724000", TRUE, 724, 0);
    common_parse_operator_id ("724000", TRUE, 0, 0);

    /* Invalid MCC=0 */
    common_parse_operator_id ("000600", FALSE, 0, 0);
    /* Invalid, non-digits */
    common_parse_operator_id ("000Z00", FALSE, 0, 0);
    /* Invalid, short */
    common_parse_operator_id ("123", FALSE, 0, 0);
    /* Invalid, long */
    common_parse_operator_id ("1234567", FALSE, 0, 0);
}

/*****************************************************************************/
/* Test +CDS unsolicited message parsing */

static void
common_parse_cds (const gchar *str,
                  guint expected_pdu_len,
                  const gchar *expected_pdu)
{
    GMatchInfo *match_info;
    GRegex *regex;
    gchar *pdu_len_str;
    gchar *pdu;

    regex = mm_3gpp_cds_regex_get ();
    g_regex_match (regex, str, 0, &match_info);
    g_assert (g_match_info_matches (match_info));

    pdu_len_str = g_match_info_fetch (match_info, 1);
    g_assert (pdu_len_str != NULL);
    g_assert_cmpuint ((guint) atoi (pdu_len_str), == , expected_pdu_len);

    pdu = g_match_info_fetch (match_info, 2);
    g_assert (pdu != NULL);

    g_assert_cmpstr (pdu, ==, expected_pdu);

    g_free (pdu);
    g_free (pdu_len_str);

    g_match_info_free (match_info);
    g_regex_unref (regex);
}

static void
test_parse_cds (void *f, gpointer d)
{
    /* <CR><LF>+CDS: 24<CR><LF>07914356060013F1065A098136395339F6219011700463802190117004638030<CR><LF> */
    common_parse_cds ("\r\n+CDS: 24\r\n07914356060013F1065A098136395339F6219011700463802190117004638030\r\n",
                      24,
                      "07914356060013F1065A098136395339F6219011700463802190117004638030");
}

typedef struct {
    const char *gsn;
    const char *expected_imei;
    const char *expected_esn;
    const char *expected_meid;
    gboolean expect_success;
} TestGsnItem;

static void
test_cdma_parse_gsn (void *f, gpointer d)
{
    static const TestGsnItem items[] = {
        { "0x6744775\r\n",  /* leading zeros skipped, no hex digits */
          NULL,
          "06744775",
          NULL,
          TRUE },
        { "0x2214A600\r\n",
          NULL,
          "2214A600",
          NULL,
          TRUE },
        { "0x80C98A1\r\n",  /* leading zeros skipped, some hex digits */
          NULL,
          "080C98A1",
          NULL,
          TRUE },
        { "6030C012\r\n",   /* no leading 0x */
          NULL,
          "6030C012",
          NULL,
          TRUE },
        { "45317471585658170:2161753034\r\n0x00A1000013FB653A:0x80D9BBCA\r\n",
          NULL,
          "80D9BBCA",
          "A1000013FB653A",
          TRUE },
        { "354237065082227\r\n",  /* GSM IMEI */
          "354237065082227",
          NULL, NULL, TRUE },
        { "356936001568843,NL2A62Z0N5\r\n",  /* IMEI + serial number */
          "356936001568843",
          NULL, NULL, TRUE },
        { "adsfasdfasdfasdf", NULL, NULL, FALSE },
        { "0x6030Cfgh", NULL, NULL, FALSE },
        { NULL }
    };

    const TestGsnItem *iter;

    for (iter = &items[0]; iter && iter->gsn; iter++) {
        char *imei = NULL, *esn = NULL, *meid = NULL;
        gboolean success;

        success = mm_parse_gsn (iter->gsn, &imei, &meid, &esn);
        g_assert_cmpint (success, ==, iter->expect_success);
        g_assert_cmpstr (iter->expected_imei, ==, imei);
        g_assert_cmpstr (iter->expected_meid, ==, meid);
        g_assert_cmpstr (iter->expected_esn, ==, esn);
        g_free (imei);
        g_free (meid);
        g_free (esn);
    }
}

/*****************************************************************************/

static gboolean
find_mode_combination (GArray *modes,
                       MMModemMode allowed,
                       MMModemMode preferred)
{
    guint i;

    for (i = 0; i < modes->len; i++) {
        MMModemModeCombination *mode;

        mode = &g_array_index (modes, MMModemModeCombination, i);
        if (mode->allowed == allowed && mode->preferred == preferred)
            return TRUE;
    }

    return FALSE;
}

static GArray *
build_mode_all (MMModemMode all_mask)
{
    MMModemModeCombination all_item;
    GArray *all;

    all_item.allowed = all_mask;
    all_item.preferred = MM_MODEM_MODE_NONE;
    all = g_array_sized_new (FALSE, FALSE, sizeof (MMModemModeCombination), 1);
    g_array_append_val (all, all_item);
    return all;
}

static void
test_supported_mode_filter (void *f, gpointer d)
{
    MMModemModeCombination mode;
    GArray *all;
    GArray *combinations;
    GArray *filtered;

    /* Build array of combinations */
    combinations = g_array_sized_new (FALSE, FALSE, sizeof (MMModemModeCombination), 5);

    /* 2G only */
    mode.allowed = MM_MODEM_MODE_2G;
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);
    /* 3G only */
    mode.allowed = MM_MODEM_MODE_3G;
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);
    /* 2G and 3G */
    mode.allowed = (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G);
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);
    /* 4G only */
    mode.allowed = MM_MODEM_MODE_4G;
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);
    /* 3G and 4G */
    mode.allowed = (MM_MODEM_MODE_3G | MM_MODEM_MODE_4G);
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);
    /* 2G, 3G and 4G */
    mode.allowed = (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G);
    mode.preferred = MM_MODEM_MODE_NONE;
    g_array_append_val (combinations, mode);

    /* Only 2G supported */
    all = build_mode_all (MM_MODEM_MODE_2G);
    filtered = mm_filter_supported_modes (all, combinations);
    g_assert_cmpuint (filtered->len, ==, 1);
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_2G, MM_MODEM_MODE_NONE));
    g_array_unref (filtered);
    g_array_unref (all);

    /* Only 3G supported */
    all = build_mode_all (MM_MODEM_MODE_3G);
    filtered = mm_filter_supported_modes (all, combinations);
    g_assert_cmpuint (filtered->len, ==, 1);
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_3G, MM_MODEM_MODE_NONE));
    g_array_unref (filtered);
    g_array_unref (all);

    /* 2G and 3G supported */
    all = build_mode_all (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G);
    filtered = mm_filter_supported_modes (all, combinations);
    g_assert_cmpuint (filtered->len, ==, 3);
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_2G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_3G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G), MM_MODEM_MODE_NONE));
    g_array_unref (filtered);
    g_array_unref (all);

    /* 3G and 4G supported */
    all = build_mode_all (MM_MODEM_MODE_3G | MM_MODEM_MODE_4G);
    filtered = mm_filter_supported_modes (all, combinations);
    g_assert_cmpuint (filtered->len, ==, 3);
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_3G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_4G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, (MM_MODEM_MODE_3G | MM_MODEM_MODE_4G), MM_MODEM_MODE_NONE));
    g_array_unref (filtered);
    g_array_unref (all);

    /* 2G, 3G and 4G supported */
    all = build_mode_all (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G);
    filtered = mm_filter_supported_modes (all, combinations);
    g_assert_cmpuint (filtered->len, ==, 6);
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_2G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_3G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G), MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, MM_MODEM_MODE_4G, MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, (MM_MODEM_MODE_3G | MM_MODEM_MODE_4G), MM_MODEM_MODE_NONE));
    g_assert (find_mode_combination (filtered, (MM_MODEM_MODE_2G | MM_MODEM_MODE_3G | MM_MODEM_MODE_4G), MM_MODEM_MODE_NONE));
    g_array_unref (filtered);
    g_array_unref (all);

    g_array_unref (combinations);
}

/*****************************************************************************/

static gboolean
find_capability_combination (GArray *capabilities,
                             MMModemCapability capability)
{
    guint i;

    for (i = 0; i < capabilities->len; i++) {
        MMModemCapability capability_i;

        capability_i = g_array_index (capabilities, MMModemCapability, i);
        if (capability_i == capability)
            return TRUE;
    }

    return FALSE;
}

static void
test_supported_capability_filter (void *f, gpointer d)
{
    MMModemCapability capability;
    GArray *combinations;
    GArray *filtered;

    combinations = g_array_sized_new (FALSE, FALSE, sizeof (MMModemCapability), 6);

    /* GSM/UMTS only */
    capability = MM_MODEM_CAPABILITY_GSM_UMTS;
    g_array_append_val (combinations, capability);
    /* CDMA/EVDO only */
    capability = MM_MODEM_CAPABILITY_CDMA_EVDO;
    g_array_append_val (combinations, capability);
    /* GSM/UMTS and CDMA/EVDO */
    capability = (MM_MODEM_CAPABILITY_CDMA_EVDO | MM_MODEM_CAPABILITY_GSM_UMTS);
    g_array_append_val (combinations, capability);
    /* GSM/UMTS+LTE */
    capability = (MM_MODEM_CAPABILITY_GSM_UMTS | MM_MODEM_CAPABILITY_LTE);
    g_array_append_val (combinations, capability);
    /* CDMA/EVDO+LTE */
    capability = (MM_MODEM_CAPABILITY_CDMA_EVDO | MM_MODEM_CAPABILITY_LTE);
    g_array_append_val (combinations, capability);
    /* GSM/UMTS+CDMA/EVDO+LTE */
    capability = (MM_MODEM_CAPABILITY_GSM_UMTS | MM_MODEM_CAPABILITY_CDMA_EVDO | MM_MODEM_CAPABILITY_LTE);
    g_array_append_val (combinations, capability);

    /* Only GSM-UMTS supported */
    filtered = mm_filter_supported_capabilities (MM_MODEM_CAPABILITY_GSM_UMTS, combinations);
    g_assert_cmpuint (filtered->len, ==, 1);
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_GSM_UMTS));
    g_array_unref (filtered);

    /* Only CDMA-EVDO supported */
    filtered = mm_filter_supported_capabilities (MM_MODEM_CAPABILITY_CDMA_EVDO, combinations);
    g_assert_cmpuint (filtered->len, ==, 1);
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_CDMA_EVDO));
    g_array_unref (filtered);

    /* GSM-UMTS and CDMA-EVDO supported */
    filtered = mm_filter_supported_capabilities ((MM_MODEM_CAPABILITY_CDMA_EVDO |
                                                  MM_MODEM_CAPABILITY_GSM_UMTS),
                                                 combinations);
    g_assert_cmpuint (filtered->len, ==, 3);
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_CDMA_EVDO));
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_GSM_UMTS));
    g_assert (find_capability_combination (filtered, (MM_MODEM_CAPABILITY_GSM_UMTS |
                                                      MM_MODEM_CAPABILITY_CDMA_EVDO)));
    g_array_unref (filtered);

    /* GSM-UMTS, CDMA-EVDO and LTE supported */
    filtered = mm_filter_supported_capabilities ((MM_MODEM_CAPABILITY_CDMA_EVDO |
                                                  MM_MODEM_CAPABILITY_GSM_UMTS |
                                                  MM_MODEM_CAPABILITY_LTE),
                                                 combinations);
    g_assert_cmpuint (filtered->len, ==, 6);
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_CDMA_EVDO));
    g_assert (find_capability_combination (filtered, MM_MODEM_CAPABILITY_GSM_UMTS));
    g_assert (find_capability_combination (filtered, (MM_MODEM_CAPABILITY_GSM_UMTS |
                                                      MM_MODEM_CAPABILITY_CDMA_EVDO)));
    g_assert (find_capability_combination (filtered, (MM_MODEM_CAPABILITY_GSM_UMTS |
                                                      MM_MODEM_CAPABILITY_LTE)));
    g_assert (find_capability_combination (filtered, (MM_MODEM_CAPABILITY_CDMA_EVDO |
                                                      MM_MODEM_CAPABILITY_LTE)));
    g_assert (find_capability_combination (filtered, (MM_MODEM_CAPABILITY_GSM_UMTS |
                                                      MM_MODEM_CAPABILITY_CDMA_EVDO |
                                                      MM_MODEM_CAPABILITY_LTE)));
    g_array_unref (filtered);

    g_array_unref (combinations);
}

/*****************************************************************************/
/* Test +CCLK responses */

typedef struct {
    const gchar *str;
    gboolean ret;
    gboolean test_iso8601;
    gboolean test_tz;
    gchar *iso8601;
    gint32 offset;
} CclkTest;

static const CclkTest cclk_tests[] = {
    { "+CCLK: \"14/08/05,04:00:21\"", TRUE, TRUE, FALSE,
        "2014-08-05T04:00:21+00:00", 0 },
    { "+CCLK: \"14/08/05,04:00:21\"", TRUE, FALSE, TRUE,
        "2014-08-05T04:00:21+00:00", 0 },
    { "+CCLK: \"14/08/05,04:00:21\"", TRUE, TRUE, TRUE,
        "2014-08-05T04:00:21+00:00", 0 },

    { "+CCLK: \"14/08/05,04:00:21+40\"", TRUE, TRUE, FALSE,
        "2014-08-05T04:00:21+10:00", 600 },
    { "+CCLK: \"14/08/05,04:00:21+40\"", TRUE, FALSE, TRUE,
        "2014-08-05T04:00:21+10:00", 600 },
    { "+CCLK: \"14/08/05,04:00:21+40\"", TRUE, TRUE, TRUE,
        "2014-08-05T04:00:21+10:00", 600 },

    { "+CCLK: \"15/02/28,20:30:40-32\"", TRUE, TRUE, FALSE,
        "2015-02-28T20:30:40-08:00", -480 },
    { "+CCLK: \"15/02/28,20:30:40-32\"", TRUE, FALSE, TRUE,
        "2015-02-28T20:30:40-08:00", -480 },
    { "+CCLK: \"15/02/28,20:30:40-32\"", TRUE, TRUE, TRUE,
        "2015-02-28T20:30:40-08:00", -480 },

    { "+CCLK: 17/07/26,11:42:15+01", TRUE, TRUE, FALSE,
      "2017-07-26T11:42:15+00:15", 15 },
    { "+CCLK: 17/07/26,11:42:15+01", TRUE, FALSE, TRUE,
      "2017-07-26T11:42:15+00:15", 15 },
    { "+CCLK: 17/07/26,11:42:15+01", TRUE, TRUE, TRUE,
      "2017-07-26T11:42:15+00:15", 15 },

    { "+CCLK:   \"15/02/28,20:30:40-32\"", TRUE, TRUE, FALSE,
        "2015-02-28T20:30:40-08:00", -480 },
    { "+CCLK:   \"15/02/28,20:30:40-32\"", TRUE, FALSE, TRUE,
        "2015-02-28T20:30:40-08:00", -480 },
    { "+CCLK:   \"15/02/28,20:30:40-32\"", TRUE, TRUE, TRUE,
        "2015-02-28T20:30:40-08:00", -480 },

    { "+CCLK:   17/07/26,11:42:15+01", TRUE, TRUE, FALSE,
      "2017-07-26T11:42:15+00:15", 15 },
    { "+CCLK:   17/07/26,11:42:15+01", TRUE, FALSE, TRUE,
      "2017-07-26T11:42:15+00:15", 15 },
    { "+CCLK:   17/07/26,11:42:15+01", TRUE, TRUE, TRUE,
      "2017-07-26T11:42:15+00:15", 15 },

    { "+CCLK: \"XX/XX/XX,XX:XX:XX+XX\"", FALSE, TRUE, FALSE,
        NULL, MM_NETWORK_TIMEZONE_OFFSET_UNKNOWN },

    { NULL, FALSE, FALSE, FALSE, NULL, MM_NETWORK_TIMEZONE_OFFSET_UNKNOWN }
};

static void
test_cclk_response (void)
{
    guint i;

    for (i = 0; cclk_tests[i].str; i++) {
        GError *error = NULL;
        gchar *iso8601 = NULL;
        MMNetworkTimezone *tz = NULL;
        gboolean ret;

        ret = mm_parse_cclk_response (cclk_tests[i].str,
                                      cclk_tests[i].test_iso8601 ? &iso8601 : NULL,
                                      cclk_tests[i].test_tz ? &tz : NULL,
                                      &error);

        g_assert (ret == cclk_tests[i].ret);
        g_assert (ret == (error ? FALSE : TRUE));

        g_clear_error (&error);

        if (cclk_tests[i].test_iso8601)
            g_assert_cmpstr (cclk_tests[i].iso8601, ==, iso8601);

        if (cclk_tests[i].test_tz) {
            g_assert (mm_network_timezone_get_offset (tz) == cclk_tests[i].offset);
            g_assert (mm_network_timezone_get_dst_offset (tz) == MM_NETWORK_TIMEZONE_OFFSET_UNKNOWN);
            g_assert (mm_network_timezone_get_leap_seconds (tz) == MM_NETWORK_TIMEZONE_LEAP_SECONDS_UNKNOWN);
        }

        if (iso8601)
            g_free (iso8601);

        if (tz)
            g_object_unref (tz);
    }
}


/*****************************************************************************/
/* Test +CRSM responses */

typedef struct {
    const gchar *str;
    gboolean ret;
    guint sw1;
    guint sw2;
    gchar *hex;
} CrsmTest;

static const CrsmTest crsm_tests[] = {
    { "+CRSM: 144, 0, 0054485552415941FFFFFFFFFFFFFFFFFF", TRUE, 144, 0, "0054485552415941FFFFFFFFFFFFFFFFFF" },
    { "+CRSM: 144, 0,0054485552415941FFFFFFFFFFFFFFFFFF", TRUE, 144, 0, "0054485552415941FFFFFFFFFFFFFFFFFF" },
    { "+CRSM: 144, 0, \"0054485552415941FFFFFFFFFFFFFFFFFF\"", TRUE, 144, 0, "0054485552415941FFFFFFFFFFFFFFFFFF" },
    { "+CRSM: 144, 0,\"0054485552415941FFFFFFFFFFFFFFFFFF\"", TRUE, 144, 0, "0054485552415941FFFFFFFFFFFFFFFFFF" },
    { NULL, FALSE, 0, 0, NULL }
};

static void
test_crsm_response (void)
{
    guint i;

    for (i = 0; crsm_tests[i].str; i++) {
        GError *error = NULL;
        guint sw1 = 0;
        guint sw2 = 0;
        gchar *hex = 0;
        gboolean ret;

        ret = mm_3gpp_parse_crsm_response (crsm_tests[i].str,
                                           &sw1,
                                           &sw2,
                                           &hex,
                                           &error);

        g_assert (ret == crsm_tests[i].ret);
        g_assert (ret == (error ? FALSE : TRUE));

        g_clear_error (&error);

        g_assert (sw1 == crsm_tests[i].sw1);
        g_assert (sw2 == crsm_tests[i].sw2);

        g_assert_cmpstr (crsm_tests[i].hex, ==, hex);

        g_free (hex);
    }
}

/*****************************************************************************/
/* Test CGCONTRDP=N responses */

typedef struct {
    const gchar *str;
    guint        cid;
    guint        bearer_id;
    const gchar *apn;
    const gchar *local_address;
    const gchar *subnet;
    const gchar *gateway_address;
    const gchar *dns_primary_address;
    const gchar *dns_secondary_address;
} CgcontrdpResponseTest;

static const CgcontrdpResponseTest cgcontrdp_response_tests[] = {
    /* Post TS 27.007 v9.4.0 format */
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49.255.255.255.255\",\"2.197.17.49\",\"10.207.43.46\",\"10.206.56.132\",\"0.0.0.0\",\"0.0.0.0\",0",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
        .dns_primary_address = "10.207.43.46",
        .dns_secondary_address = "10.206.56.132",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49.255.255.255.255\",\"2.197.17.49\",\"10.207.43.46\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
        .dns_primary_address = "10.207.43.46",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49.255.255.255.255\",\"2.197.17.49\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49.255.255.255.255\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
    },
    /* Pre TS 27.007 v9.4.0 format */
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49\",\"255.255.255.255\",\"2.197.17.49\",\"10.207.43.46\",\"10.206.56.132\",\"0.0.0.0\",\"0.0.0.0\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
        .dns_primary_address = "10.207.43.46",
        .dns_secondary_address = "10.206.56.132",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49\",\"255.255.255.255\",\"2.197.17.49\",\"10.207.43.46\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
        .dns_primary_address = "10.207.43.46",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49\",\"255.255.255.255\",\"2.197.17.49\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
        .gateway_address = "2.197.17.49",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49\",\"255.255.255.255\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
        .subnet = "255.255.255.255",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\",\"2.197.17.49\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
        .local_address = "2.197.17.49",
    },
    /* Common */
    {
        .str = "+CGCONTRDP: 4,5,\"ibox.tim.it.mnc001.mcc222.gprs\"",
        .cid = 4,
        .bearer_id = 5,
        .apn = "ibox.tim.it.mnc001.mcc222.gprs",
    },
    {
        .str = "+CGCONTRDP: 4,5,\"\"",
        .cid = 4,
        .bearer_id = 5,
    },
};

static void
test_cgcontrdp_response (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cgcontrdp_response_tests); i++) {
        GError   *error = NULL;
        gboolean  success;
        guint     cid = G_MAXUINT;
        guint     bearer_id = G_MAXUINT;
        gchar    *apn = NULL;
        gchar    *local_address = NULL;
        gchar    *subnet = NULL;
        gchar    *gateway_address = NULL;
        gchar    *dns_primary_address = NULL;
        gchar    *dns_secondary_address = NULL;

        success = mm_3gpp_parse_cgcontrdp_response (cgcontrdp_response_tests[i].str,
                                                    &cid,
                                                    &bearer_id,
                                                    &apn,
                                                    &local_address,
                                                    &subnet,
                                                    &gateway_address,
                                                    &dns_primary_address,
                                                    &dns_secondary_address,
                                                    &error);
        g_assert_no_error (error);
        g_assert (success);
        g_assert_cmpuint (cgcontrdp_response_tests[i].cid,                   ==, cid);
        g_assert_cmpuint (cgcontrdp_response_tests[i].bearer_id,             ==, bearer_id);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].apn,                   ==, apn);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].local_address,         ==, local_address);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].subnet,                ==, subnet);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].gateway_address,       ==, gateway_address);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].dns_primary_address,   ==, dns_primary_address);
        g_assert_cmpstr  (cgcontrdp_response_tests[i].dns_secondary_address, ==, dns_secondary_address);

        g_free (apn);
        g_free (local_address);
        g_free (subnet);
        g_free (gateway_address);
        g_free (dns_primary_address);
        g_free (dns_secondary_address);
    }
}

/*****************************************************************************/
/* Test CFUN? response */

typedef struct {
    const gchar *str;
    guint        state;
} CfunQueryTest;

static const CfunQueryTest cfun_query_tests[] = {
    { "+CFUN: 1",     1 },
    { "+CFUN: 1,0",   1 },
    { "+CFUN: 0",     0 },
    { "+CFUN: 0,0",   0 },
    { "+CFUN: 19",   19 },
    { "+CFUN: 19,0", 19 },
};

static void
test_cfun_response (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cfun_query_tests); i++) {
        GError   *error = NULL;
        gboolean  success;
        guint     state = G_MAXUINT;

        success = mm_3gpp_parse_cfun_query_response (cfun_query_tests[i].str, &state, &error);
        g_assert_no_error (error);
        g_assert (success);
        g_assert_cmpuint (cfun_query_tests[i].state, ==, state);
    }
}

/*****************************************************************************/
/* Test +CESQ responses */

typedef struct {
    const gchar *str;

    gboolean gsm_info;
    guint    rxlev;
    gdouble  rssi;
    guint    ber;

    gboolean umts_info;
    guint    rscp_level;
    gdouble  rscp;
    guint    ecn0_level;
    gdouble  ecio;

    gboolean lte_info;
    guint    rsrq_level;
    gdouble  rsrq;
    guint    rsrp_level;
    gdouble  rsrp;
} CesqResponseTest;

static const CesqResponseTest cesq_response_tests[] = {
    {
        .str       = "+CESQ: 99,99,255,255,20,80",
        .gsm_info  = FALSE, .rxlev = 99, .ber = 99,
        .umts_info = FALSE, .rscp_level = 255, .ecn0_level = 255,
        .lte_info  = TRUE,  .rsrq_level = 20, .rsrq = -10.0, .rsrp_level = 80, .rsrp = -61.0,
    },
    {
        .str       = "+CESQ: 99,99,95,40,255,255",
        .gsm_info  = FALSE, .rxlev = 99, .ber = 99,
        .umts_info = TRUE,  .rscp_level = 95, .rscp = -26.0, .ecn0_level = 40, .ecio = -4.5,
        .lte_info  = FALSE, .rsrq_level = 255, .rsrp_level = 255,
    },
    {
        .str       = "+CESQ: 10,6,255,255,255,255",
        .gsm_info  = TRUE,  .rxlev = 10, .rssi = -101.0, .ber = 6,
        .umts_info = FALSE, .rscp_level = 255, .ecn0_level = 255,
        .lte_info  = FALSE, .rsrq_level = 255, .rsrp_level = 255,
    }
};

static void
test_cesq_response (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cesq_response_tests); i++) {
        GError   *error = NULL;
        gboolean  success;
        guint rxlev = G_MAXUINT;
        guint ber = G_MAXUINT;
        guint rscp = G_MAXUINT;
        guint ecn0 = G_MAXUINT;
        guint rsrq = G_MAXUINT;
        guint rsrp = G_MAXUINT;

        success = mm_3gpp_parse_cesq_response (cesq_response_tests[i].str,
                                               &rxlev, &ber,
                                               &rscp, &ecn0,
                                               &rsrq, &rsrp,
                                               &error);
        g_assert_no_error (error);
        g_assert (success);

        g_assert_cmpuint (cesq_response_tests[i].rxlev,      ==, rxlev);
        g_assert_cmpuint (cesq_response_tests[i].ber,        ==, ber);
        g_assert_cmpuint (cesq_response_tests[i].rscp_level, ==, rscp);
        g_assert_cmpuint (cesq_response_tests[i].ecn0_level, ==, ecn0);
        g_assert_cmpuint (cesq_response_tests[i].rsrq_level, ==, rsrq);
        g_assert_cmpuint (cesq_response_tests[i].rsrp_level, ==, rsrp);
    }
}

static void
test_cesq_response_to_signal (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cesq_response_tests); i++) {
        GError   *error = NULL;
        gboolean  success;
        MMSignal *gsm  = NULL;
        MMSignal *umts = NULL;
        MMSignal *lte  = NULL;

        success = mm_3gpp_cesq_response_to_signal_info (cesq_response_tests[i].str,
                                                        &gsm, &umts, &lte,
                                                        &error);
        g_assert_no_error (error);
        g_assert (success);

        if (cesq_response_tests[i].gsm_info) {
            g_assert (gsm);
            g_assert_cmpfloat_tolerance (mm_signal_get_rssi (gsm), cesq_response_tests[i].rssi, 0.1);
            g_object_unref (gsm);
        } else
            g_assert (!gsm);

        if (cesq_response_tests[i].umts_info) {
            g_assert (umts);
            g_assert_cmpfloat_tolerance (mm_signal_get_rscp (umts), cesq_response_tests[i].rscp, 0.1);
            g_assert_cmpfloat_tolerance (mm_signal_get_ecio (umts), cesq_response_tests[i].ecio, 0.1);
            g_object_unref (umts);
        } else
            g_assert (!umts);

        if (cesq_response_tests[i].lte_info) {
            g_assert (lte);
            g_assert_cmpfloat_tolerance (mm_signal_get_rsrq (lte), cesq_response_tests[i].rsrq, 0.1);
            g_assert_cmpfloat_tolerance (mm_signal_get_rsrp (lte), cesq_response_tests[i].rsrp, 0.1);
            g_object_unref (lte);
        } else
            g_assert (!lte);
    }
}

typedef struct {
    const gchar       *str;
    MMModemPowerState  state;
} CfunQueryGenericTest;

static const CfunQueryGenericTest cfun_query_generic_tests[] = {
    { "+CFUN: 1",     MM_MODEM_POWER_STATE_ON  },
    { "+CFUN: 1,0",   MM_MODEM_POWER_STATE_ON  },
    { "+CFUN: 0",     MM_MODEM_POWER_STATE_OFF },
    { "+CFUN: 0,0",   MM_MODEM_POWER_STATE_OFF },
    { "+CFUN: 4",     MM_MODEM_POWER_STATE_LOW },
    { "+CFUN: 4,0",   MM_MODEM_POWER_STATE_LOW },
};

static void
test_cfun_generic_response (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (cfun_query_generic_tests); i++) {
        GError   *error = NULL;
        gboolean  success;
        MMModemPowerState state = MM_MODEM_POWER_STATE_UNKNOWN;

        success = mm_3gpp_parse_cfun_query_generic_response (cfun_query_generic_tests[i].str, &state, &error);
        g_assert_no_error (error);
        g_assert (success);
        g_assert_cmpuint (cfun_query_generic_tests[i].state, ==, state);
    }
}

/*****************************************************************************/

typedef struct {
    gchar *str;
    gint expected_number_list[9];
} TestParseNumberList;

static const TestParseNumberList test_parse_number_list_item [] = {
    { "1-6",          { 1, 2, 3, 4, 5, 6, -1 } },
    { "0,1,2,4,6",    { 0, 1, 2, 4, 6, -1 } },
    { "1,3-5,7,9-11", { 1, 3, 4, 5, 7, 9, 10, 11, -1 } },
    { "9-11,7,3-5",   { 3, 4, 5, 7, 9, 10, 11, -1 } },
    { "",             { -1 } },
    { NULL,           { -1 } },
};

static void
test_parse_uint_list (void)
{
    guint i;

    for (i = 0; i < G_N_ELEMENTS (test_parse_number_list_item); i++) {
        GArray *array;
        GError *error = NULL;
        guint   j;

        array = mm_parse_uint_list (test_parse_number_list_item[i].str, &error);
        g_assert_no_error (error);
        if (test_parse_number_list_item[i].expected_number_list[0] == -1) {
            g_assert (!array);
            continue;
        }

        g_assert (array);
        for (j = 0; j < array->len; j++) {
            g_assert_cmpint (test_parse_number_list_item[i].expected_number_list[j], !=, -1);
            g_assert_cmpuint (test_parse_number_list_item[i].expected_number_list[j], ==, g_array_index (array, guint, j));
        }
        g_assert_cmpint (test_parse_number_list_item[i].expected_number_list[array->len], ==, -1);
        g_array_unref (array);
    }
}

/*****************************************************************************/

void
_mm_log (const char *loc,
         const char *func,
         guint32 level,
         const char *fmt,
         ...)
{
#if defined ENABLE_TEST_MESSAGE_TRACES
    /* Dummy log function */
    va_list args;
    gchar *msg;

    va_start (args, fmt);
    msg = g_strdup_vprintf (fmt, args);
    va_end (args);
    g_print ("%s\n", msg);
    g_free (msg);
#endif
}

#define TESTCASE(t, d) g_test_create_case (#t, 0, d, NULL, (GTestFixtureFunc) t, NULL)

int main (int argc, char **argv)
{
    GTestSuite *suite;
    RegTestData *reg_data;
    gint result;
    DevidItem *item = &devids[0];

    g_test_init (&argc, &argv, NULL);

    suite = g_test_get_root ();
    reg_data = reg_test_data_new ();

    g_test_suite_add (suite, TESTCASE (test_ifc_response_all_simple, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_all_groups, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_none_only, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_xon_xoff_only, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_rts_cts_only, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_no_xon_xoff, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_no_xon_xoff_in_ta, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_no_xon_xoff_in_te, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_no_rts_cts_simple, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_no_rts_cts_groups, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_all_simple_and_unknown, NULL));
    g_test_suite_add (suite, TESTCASE (test_ifc_response_all_groups_and_unknown, NULL));

    g_test_suite_add (suite, TESTCASE (test_ws46_response_generic_2g3g4g, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_generic_2g3g, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_generic_2g3g_v2, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_cinterion, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_telit_le866, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_range_1, NULL));
    g_test_suite_add (suite, TESTCASE (test_ws46_response_range_2, NULL));

    g_test_suite_add (suite, TESTCASE (test_cops_response_tm506, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_gt3gplus, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_ac881, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_gtmax36, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_ac860, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_gtm378, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_motoc, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_mf627a, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_mf627b, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_e160g, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_mercury, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_quicksilver, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_icon225, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_icon452, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_f3507g, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_f3607gw, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_mc8775, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_n80, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_e1550, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_mf622, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_e226, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_xu870, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_gtultraexpress, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_n2720, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_gobi, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_sek600i, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_samsung_z810, NULL));

    g_test_suite_add (suite, TESTCASE (test_cops_response_gsm_invalid, NULL));
    g_test_suite_add (suite, TESTCASE (test_cops_response_umts_invalid, NULL));

    g_test_suite_add (suite, TESTCASE (test_cops_query, NULL));

    g_test_suite_add (suite, TESTCASE (test_normalize_operator, NULL));

    g_test_suite_add (suite, TESTCASE (test_creg1_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg1_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_mercury_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_mercury_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_sek850i_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_sek850i_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_e160g_solicited_unregistered, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_e160g_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_e160g_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_tm506_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_xu870_unsolicited_unregistered, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_md400_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_s8500_wave_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_gobi_weird_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_iridium_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_no_leading_zeros_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_leading_zeros_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_no_leading_zeros_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_leading_zeros_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_ublox_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg2_ublox_unsolicited, reg_data));

    g_test_suite_add (suite, TESTCASE (test_cgreg1_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg1_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_f3607gw_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_f3607gw_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_md400_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_x220_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_unsolicited_with_rac, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_thuraya_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cgreg2_thuraya_unsolicited, reg_data));

    g_test_suite_add (suite, TESTCASE (test_cereg1_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg1_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_altair_lte_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_altair_lte_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_novatel_lte_solicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_cereg2_novatel_lte_unsolicited, reg_data));

    g_test_suite_add (suite, TESTCASE (test_creg_cgreg_multi_unsolicited, reg_data));
    g_test_suite_add (suite, TESTCASE (test_creg_cgreg_multi2_unsolicited, reg_data));

    g_test_suite_add (suite, TESTCASE (test_cscs_icon225_support_response, NULL));
    g_test_suite_add (suite, TESTCASE (test_cscs_sierra_mercury_support_response, NULL));
    g_test_suite_add (suite, TESTCASE (test_cscs_buslink_support_response, NULL));
    g_test_suite_add (suite, TESTCASE (test_cscs_blackberry_support_response, NULL));

    g_test_suite_add (suite, TESTCASE (test_cmer_response_cinterion_pls8, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmer_response_sierra_em7345, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmer_response_cinterion_ehs5, NULL));

    g_test_suite_add (suite, TESTCASE (test_cmer_request_cinterion_ehs5, NULL));

    g_test_suite_add (suite, TESTCASE (test_cind_response_linktop_lw273, NULL));
    g_test_suite_add (suite, TESTCASE (test_cind_response_moto_v3m, NULL));

    g_test_suite_add (suite, TESTCASE (test_iccid_parse_quoted_swap_19_digit, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_unquoted_swap_20_digit, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_unquoted_unswapped_19_digit, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_quoted_unswapped_20_digit, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_short, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_invalid_chars, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_quoted_invalid_mii, NULL));
    g_test_suite_add (suite, TESTCASE (test_iccid_parse_unquoted_invalid_mii, NULL));

    while (item->devid) {
        g_test_suite_add (suite, TESTCASE (test_devid_item, (gconstpointer) item));
        item++;
    }

    g_test_suite_add (suite, TESTCASE (test_cpms_response_cinterion,    NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_response_huawei_mu609, NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_response_nokia_c6,     NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_response_mixed,        NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_response_mixed_spaces, NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_response_empty_fields, NULL));
    g_test_suite_add (suite, TESTCASE (test_cpms_query_response,        NULL));

    g_test_suite_add (suite, TESTCASE (test_cmp_apn_name, NULL));

    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_single, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_multiple, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_multiple_and_ignore, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_single_context, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_thuraya, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_test_response_cinterion_phs8, NULL));

    g_test_suite_add (suite, TESTCASE (test_cgdcont_read_response_nokia, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgdcont_read_response_samsung, NULL));

    g_test_suite_add (suite, TESTCASE (test_cgact_read_response_none, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgact_read_response_single_inactive, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgact_read_response_single_active, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgact_read_response_multiple, NULL));

    g_test_suite_add (suite, TESTCASE (test_cgpaddr_exec_response_none, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgpaddr_exec_response_single_context_single_address, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgpaddr_exec_response_single_context_multiple_addresses, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgpaddr_exec_response_multiple_contexts_single_address, NULL));
    g_test_suite_add (suite, TESTCASE (test_cgpaddr_exec_response_multiple_contexts_multiple_addresses, NULL));

    g_test_suite_add (suite, TESTCASE (test_cnum_response_generic, NULL));
    g_test_suite_add (suite, TESTCASE (test_cnum_response_generic_without_detail, NULL));
    g_test_suite_add (suite, TESTCASE (test_cnum_response_generic_detail_unquoted, NULL));
    g_test_suite_add (suite, TESTCASE (test_cnum_response_generic_international_number, NULL));
    g_test_suite_add (suite, TESTCASE (test_cnum_response_generic_multiple_numbers, NULL));

    g_test_suite_add (suite, TESTCASE (test_parse_operator_id, NULL));

    g_test_suite_add (suite, TESTCASE (test_parse_cds, NULL));

    g_test_suite_add (suite, TESTCASE (test_cdma_parse_gsn, NULL));

    g_test_suite_add (suite, TESTCASE (test_cmgl_response_generic, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmgl_response_generic_multiple, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmgl_response_pantech, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmgl_response_pantech_multiple, NULL));

    g_test_suite_add (suite, TESTCASE (test_cmgr_response_generic, NULL));
    g_test_suite_add (suite, TESTCASE (test_cmgr_response_telit, NULL));

    g_test_suite_add (suite, TESTCASE (test_supported_mode_filter, NULL));

    g_test_suite_add (suite, TESTCASE (test_supported_capability_filter, NULL));

    g_test_suite_add (suite, TESTCASE (test_cclk_response, NULL));

    g_test_suite_add (suite, TESTCASE (test_crsm_response, NULL));

    g_test_suite_add (suite, TESTCASE (test_cgcontrdp_response, NULL));

    g_test_suite_add (suite, TESTCASE (test_cfun_response, NULL));
    g_test_suite_add (suite, TESTCASE (test_cfun_generic_response, NULL));

    g_test_suite_add (suite, TESTCASE (test_cesq_response, NULL));
    g_test_suite_add (suite, TESTCASE (test_cesq_response_to_signal, NULL));

    g_test_suite_add (suite, TESTCASE (test_parse_uint_list, NULL));

    result = g_test_run ();

    reg_test_data_free (reg_data);

    return result;
}
