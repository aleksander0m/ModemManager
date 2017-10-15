
include $(top_srcdir)/gtester.make

################################################################################
# common
################################################################################

AM_CFLAGS = \
	$(MM_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	$(GUDEV_CFLAGS)	\
	-I$(top_srcdir) \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src/kerneldevice \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libmm-glib \
	-I$(top_srcdir)/libmm-glib/generated \
	-I$(top_builddir)/libmm-glib/generated \
	$(NULL)

AM_LDFLAGS = \
	$(MM_LIBS)               \
	$(CODE_COVERAGE_LDFLAGS) \
	$(GUDEV_LIBS)            \
	$(NULL)

if WITH_QMI
AM_CFLAGS  += $(QMI_CFLAGS)
AM_LDFLAGS += $(QMI_LIBS)
endif

if WITH_MBIM
AM_CFLAGS  += $(MBIM_CFLAGS)
AM_LDFLAGS += $(MBIM_LIBS)
endif

# Common compiler/linker flags for plugins
PLUGIN_COMMON_COMPILER_FLAGS = \
	$(NULL)
PLUGIN_COMMON_LINKER_FLAGS = \
	-module        \
	-avoid-version \
	-export-symbols-regex '^mm_plugin_major_version$$|^mm_plugin_minor_version$$|^mm_plugin_create$$' \
	$(NULL)

# UDev rules
udevrulesdir = $(UDEV_BASE_DIR)/rules.d
dist_udevrules_DATA =

# Unit tests
noinst_PROGRAMS =

# Helper libs
noinst_LTLIBRARIES =

# Plugins
pkglib_LTLIBRARIES =

# Built sources
BUILT_SOURCES =

# Clean files
CLEANFILES =

################################################################################
# common service test support
################################################################################

noinst_LTLIBRARIES += libmm-test-common.la
libmm_test_common_la_SOURCES = \
	tests/test-fixture.h \
	tests/test-fixture.c \
	tests/test-port-context.h \
	tests/test-port-context.c \
	$(NULL)
libmm_test_common_la_CPPFLAGS = \
	-I$(top_builddir)/libmm-glib/generated/tests \
	-DTEST_SERVICES=\""$(abs_top_builddir)/data/tests"\" \
	$(NULL)
libmm_test_common_la_LIBADD = \
	${top_builddir}/libmm-glib/generated/tests/libmm-test-generated.la \
	$(top_builddir)/libmm-glib/libmm-glib.la

EXTRA_DIST += tests/gsm-port.conf

TEST_COMMON_COMPILER_FLAGS = \
	$(MM_CFLAGS) \
	-I$(top_srcdir)/plugins/tests \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_srcdir)/libmm-glib \
	-I$(top_srcdir)/libmm-glib/generated \
	-I$(top_builddir)/libmm-glib/generated \
	-I$(top_builddir)/libmm-glib/generated/tests \
	-DCOMMON_GSM_PORT_CONF=\""$(abs_top_srcdir)/plugins/tests/gsm-port.conf"\"

TEST_COMMON_LIBADD_FLAGS = \
	$(builddir)/libmm-test-common.la \
	$(top_builddir)/libmm-glib/libmm-glib.la

################################################################################
# common icera support
################################################################################

noinst_LTLIBRARIES += libhelpers-icera.la
libhelpers_icera_la_SOURCES = \
	icera/mm-modem-helpers-icera.c \
	icera/mm-modem-helpers-icera.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-icera
test_modem_helpers_icera_SOURCES = \
	icera/tests/test-modem-helpers-icera.c \
	$(NULL)
test_modem_helpers_icera_CPPFLAGS = \
	-I$(top_srcdir)/plugins/icera \
	$(NULL)
test_modem_helpers_icera_LDADD = \
	$(builddir)/libhelpers-icera.la  \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

noinst_LTLIBRARIES += libmm-utils-icera.la
libmm_utils_icera_la_SOURCES = \
	icera/mm-broadband-modem-icera.h \
	icera/mm-broadband-modem-icera.c \
	icera/mm-broadband-bearer-icera.h \
	icera/mm-broadband-bearer-icera.c \
	$(NULL)
libmm_utils_icera_la_LIBADD = \
	$(builddir)/libhelpers-icera.la \
	$(NULL)

ICERA_COMMON_COMPILER_FLAGS = -I$(top_srcdir)/plugins/icera
ICERA_COMMON_LIBADD_FLAGS   = $(builddir)/libmm-utils-icera.la

################################################################################
# common ericsson mbm support
################################################################################

noinst_LTLIBRARIES += libhelpers-mbm.la
libhelpers_mbm_la_SOURCES = \
	mbm/mm-modem-helpers-mbm.c \
	mbm/mm-modem-helpers-mbm.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-mbm
test_modem_helpers_mbm_SOURCES = \
	mbm/tests/test-modem-helpers-mbm.c \
	$(NULL)
test_modem_helpers_mbm_CPPFLAGS = \
	-I$(top_srcdir)/plugins/mbm \
	$(NULL)
test_modem_helpers_mbm_LDADD = \
	$(builddir)/libhelpers-mbm.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

noinst_LTLIBRARIES += libmm-utils-mbm.la
libmm_utils_mbm_la_SOURCES = \
	mbm/mm-broadband-modem-mbm.c \
	mbm/mm-broadband-modem-mbm.h \
	mbm/mm-broadband-bearer-mbm.c \
	mbm/mm-broadband-bearer-mbm.h \
	mbm/mm-sim-mbm.c \
	mbm/mm-sim-mbm.h \
	$(NULL)
libmm_utils_mbm_la_LIBADD = \
	$(builddir)/libhelpers-mbm.la \
	$(NULL)

MBM_COMMON_COMPILER_FLAGS = -I$(top_srcdir)/plugins/mbm
MBM_COMMON_LIBADD_FLAGS   = $(builddir)/libmm-utils-mbm.la

################################################################################
# common sierra support
################################################################################

noinst_LTLIBRARIES += libmm-utils-sierra.la
libmm_utils_sierra_la_SOURCES = \
	sierra/mm-common-sierra.c \
	sierra/mm-common-sierra.h \
	sierra/mm-sim-sierra.c \
	sierra/mm-sim-sierra.h \
	sierra/mm-broadband-bearer-sierra.c \
	sierra/mm-broadband-bearer-sierra.h \
	sierra/mm-broadband-modem-sierra.c  \
	sierra/mm-broadband-modem-sierra.h  \
	$(NULL)

SIERRA_COMMON_COMPILER_FLAGS = -I$(top_srcdir)/plugins/sierra
SIERRA_COMMON_LIBADD_FLAGS   = $(builddir)/libmm-utils-sierra.la

################################################################################
# common option support
################################################################################

noinst_LTLIBRARIES += libmm-utils-option.la
libmm_utils_option_la_SOURCES = \
	option/mm-broadband-modem-option.c \
	option/mm-broadband-modem-option.h \
	$(NULL)

OPTION_COMMON_COMPILER_FLAGS = -I$(top_srcdir)/plugins/option
OPTION_COMMON_LIBADD_FLAGS   = $(builddir)/libmm-utils-option.la

################################################################################
# common novatel support
################################################################################

# Common Novatel modem support library
noinst_LTLIBRARIES += libmm-utils-novatel.la
libmm_utils_novatel_la_SOURCES = \
	novatel/mm-common-novatel.c \
	novatel/mm-common-novatel.h \
	novatel/mm-broadband-modem-novatel.c \
	novatel/mm-broadband-modem-novatel.h \
	$(NULL)

NOVATEL_COMMON_COMPILER_FLAGS = -I$(top_srcdir)/plugins/novatel
NOVATEL_COMMON_LIBADD_FLAGS   = $(builddir)/libmm-utils-novatel.la

################################################################################
# plugin: generic
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-generic.la
libmm_plugin_generic_la_SOURCES = \
	generic/mm-plugin-generic.c \
	generic/mm-plugin-generic.h \
	$(NULL)
libmm_plugin_generic_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_generic_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

noinst_PROGRAMS += test-service-generic
test_service_generic_SOURCES  = generic/tests/test-service-generic.c
test_service_generic_CPPFLAGS = $(TEST_COMMON_COMPILER_FLAGS)
test_service_generic_LDADD    = $(TEST_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: motorola
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-motorola.la
libmm_plugin_motorola_la_SOURCES = \
	motorola/mm-plugin-motorola.c \
	motorola/mm-plugin-motorola.h \
	motorola/mm-broadband-modem-motorola.c \
	motorola/mm-broadband-modem-motorola.h \
	$(NULL)
libmm_plugin_motorola_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_motorola_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: huawei
################################################################################

noinst_LTLIBRARIES += libhelpers-huawei.la
libhelpers_huawei_la_SOURCES = \
	huawei/mm-modem-helpers-huawei.c \
	huawei/mm-modem-helpers-huawei.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-huawei
test_modem_helpers_huawei_SOURCES = \
	huawei/tests/test-modem-helpers-huawei.c \
	$(NULL)
test_modem_helpers_huawei_CPPFLAGS = \
	-I$(top_srcdir)/plugins/huawei \
	$(NULL)
test_modem_helpers_huawei_LDADD = \
	$(builddir)/libhelpers-huawei.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-huawei.la
libmm_plugin_huawei_la_SOURCES = \
	huawei/mm-plugin-huawei.c \
	huawei/mm-plugin-huawei.h \
	huawei/mm-sim-huawei.c \
	huawei/mm-sim-huawei.h \
	huawei/mm-call-huawei.c \
	huawei/mm-call-huawei.h \
	huawei/mm-broadband-modem-huawei.c \
	huawei/mm-broadband-modem-huawei.h \
	huawei/mm-broadband-bearer-huawei.c \
	huawei/mm-broadband-bearer-huawei.h \
	$(NULL)
libmm_plugin_huawei_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_huawei_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_huawei_la_LIBADD   = $(builddir)/libhelpers-huawei.la

dist_udevrules_DATA += huawei/77-mm-huawei-net-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_HUAWEI=\"${srcdir}/huawei\"

################################################################################
# plugin: ericsson mbm
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-ericsson-mbm.la
libmm_plugin_ericsson_mbm_la_SOURCES = \
	mbm/mm-plugin-mbm.c \
	mbm/mm-plugin-mbm.h \
	$(NULL)
libmm_plugin_ericsson_mbm_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(MBM_COMMON_COMPILER_FLAGS)
libmm_plugin_ericsson_mbm_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_ericsson_mbm_la_LIBADD   = $(MBM_COMMON_LIBADD_FLAGS)

dist_udevrules_DATA += mbm/77-mm-ericsson-mbm.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_MBM=\"${srcdir}/mbm\"

################################################################################
# plugin: option
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-option.la
libmm_plugin_option_la_SOURCES = \
	option/mm-plugin-option.c \
	option/mm-plugin-option.h \
	$(NULL)
libmm_plugin_option_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(OPTION_COMMON_COMPILER_FLAGS)
libmm_plugin_option_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_option_la_LIBADD   = $(OPTION_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: option hso
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-option-hso.la
libmm_plugin_option_hso_la_SOURCES = \
	option/mm-plugin-hso.c \
	option/mm-plugin-hso.h \
	option/mm-broadband-bearer-hso.c \
	option/mm-broadband-bearer-hso.h \
	option/mm-broadband-modem-hso.c \
	option/mm-broadband-modem-hso.h \
	$(NULL)
libmm_plugin_option_hso_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(OPTION_COMMON_COMPILER_FLAGS)
libmm_plugin_option_hso_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_option_hso_la_LIBADD   = $(OPTION_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: sierra (new QMI or MBIM modems)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-sierra.la
libmm_plugin_sierra_la_SOURCES = \
	sierra/mm-plugin-sierra.c \
	sierra/mm-plugin-sierra.h \
	$(NULL)
libmm_plugin_sierra_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_sierra_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: sierra (legacy)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-sierra-legacy.la
libmm_plugin_sierra_legacy_la_SOURCES = \
	sierra/mm-plugin-sierra-legacy.c \
	sierra/mm-plugin-sierra-legacy.h \
	sierra/mm-broadband-modem-sierra-icera.c \
	sierra/mm-broadband-modem-sierra-icera.h \
	$(NULL)
libmm_plugin_sierra_legacy_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(ICERA_COMMON_COMPILER_FLAGS) $(SIERRA_COMMON_COMPILER_FLAGS)
libmm_plugin_sierra_legacy_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_sierra_legacy_la_LIBADD   = $(ICERA_COMMON_LIBADD_FLAGS) $(SIERRA_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: wavecom (now sierra airlink)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-wavecom.la
libmm_plugin_wavecom_la_SOURCES = \
	wavecom/mm-plugin-wavecom.c \
	wavecom/mm-plugin-wavecom.h \
	wavecom/mm-broadband-modem-wavecom.c \
	wavecom/mm-broadband-modem-wavecom.h \
	$(NULL)
libmm_plugin_wavecom_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_wavecom_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: nokia
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-nokia.la
libmm_plugin_nokia_la_SOURCES = \
	nokia/mm-plugin-nokia.c \
	nokia/mm-plugin-nokia.h \
	nokia/mm-sim-nokia.c \
	nokia/mm-sim-nokia.h \
	nokia/mm-broadband-modem-nokia.c \
	nokia/mm-broadband-modem-nokia.h \
	$(NULL)
libmm_plugin_nokia_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_nokia_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: nokia (icera)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-nokia-icera.la
libmm_plugin_nokia_icera_la_SOURCES = \
	nokia/mm-plugin-nokia-icera.c \
	nokia/mm-plugin-nokia-icera.h \
	$(NULL)
libmm_plugin_nokia_icera_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(ICERA_COMMON_COMPILER_FLAGS)
libmm_plugin_nokia_icera_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_nokia_icera_la_LIBADD   = $(ICERA_COMMON_LIBADD_FLAGS)

dist_udevrules_DATA += nokia/77-mm-nokia-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_NOKIA=\"${srcdir}/nokia\"

################################################################################
# plugin: zte
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-zte.la
libmm_plugin_zte_la_SOURCES = \
	zte/mm-plugin-zte.c \
	zte/mm-plugin-zte.h \
	zte/mm-common-zte.h \
	zte/mm-common-zte.c \
	zte/mm-broadband-modem-zte.h \
	zte/mm-broadband-modem-zte.c \
	zte/mm-broadband-modem-zte-icera.h \
	zte/mm-broadband-modem-zte-icera.c \
	$(NULL)
libmm_plugin_zte_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(ICERA_COMMON_COMPILER_FLAGS)
libmm_plugin_zte_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_zte_la_LIBADD   = $(ICERA_COMMON_LIBADD_FLAGS)

dist_udevrules_DATA += zte/77-mm-zte-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_ZTE=\"${srcdir}/zte\"

################################################################################
# plugin: longcheer (and rebranded dongles)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-longcheer.la
libmm_plugin_longcheer_la_SOURCES = \
	longcheer/mm-plugin-longcheer.c \
	longcheer/mm-plugin-longcheer.h \
	longcheer/mm-broadband-modem-longcheer.h \
	longcheer/mm-broadband-modem-longcheer.c \
	$(NULL)
libmm_plugin_longcheer_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_longcheer_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

dist_udevrules_DATA += longcheer/77-mm-longcheer-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_LONGCHEER=\"${srcdir}/longcheer\"

################################################################################
# plugin: anydata cdma
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-anydata.la
libmm_plugin_anydata_la_SOURCES = \
	anydata/mm-plugin-anydata.c \
	anydata/mm-plugin-anydata.h \
	anydata/mm-broadband-modem-anydata.h \
	anydata/mm-broadband-modem-anydata.c \
	$(NULL)
libmm_plugin_anydata_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_anydata_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: linktop cdma
################################################################################

noinst_LTLIBRARIES += libhelpers-linktop.la
libhelpers_linktop_la_SOURCES = \
	linktop/mm-modem-helpers-linktop.c \
	linktop/mm-modem-helpers-linktop.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-linktop
test_modem_helpers_linktop_SOURCES = \
	linktop/tests/test-modem-helpers-linktop.c \
	$(NULL)
test_modem_helpers_linktop_CPPFLAGS = \
	-I$(top_srcdir)/plugins/linktop \
	$(NULL)
test_modem_helpers_linktop_LDADD = \
	$(builddir)/libhelpers-linktop.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-linktop.la
libmm_plugin_linktop_la_SOURCES = \
	linktop/mm-plugin-linktop.c \
	linktop/mm-plugin-linktop.h \
	linktop/mm-broadband-modem-linktop.h \
	linktop/mm-broadband-modem-linktop.c \
	$(NULL)
libmm_plugin_linktop_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_linktop_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_linktop_la_LIBADD   = $(builddir)/libhelpers-linktop.la

################################################################################
# plugin: simtech
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-simtech.la
libmm_plugin_simtech_la_SOURCES = \
	simtech/mm-plugin-simtech.c \
	simtech/mm-plugin-simtech.h \
	simtech/mm-broadband-modem-simtech.h \
	simtech/mm-broadband-modem-simtech.c \
	$(NULL)
libmm_plugin_simtech_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_simtech_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

dist_udevrules_DATA += simtech/77-mm-simtech-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_SIMTECH=\"${srcdir}/simtech\"

################################################################################
# plugin: alcatel/TCT/JRD x220D and possibly others
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-x22x.la
libmm_plugin_x22x_la_SOURCES = \
	x22x/mm-plugin-x22x.c \
	x22x/mm-plugin-x22x.h \
	x22x/mm-broadband-modem-x22x.h \
	x22x/mm-broadband-modem-x22x.c \
	$(NULL)
libmm_plugin_x22x_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_x22x_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

dist_udevrules_DATA += x22x/77-mm-x22x-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_X22X=\"${srcdir}/x22x\"

################################################################################
# plugin: pantech
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-pantech.la
libmm_plugin_pantech_la_SOURCES = \
	pantech/mm-plugin-pantech.c \
	pantech/mm-plugin-pantech.h \
	pantech/mm-sim-pantech.c \
	pantech/mm-sim-pantech.h \
	pantech/mm-broadband-modem-pantech.c \
	pantech/mm-broadband-modem-pantech.h \
	$(NULL)
libmm_plugin_pantech_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_pantech_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: samsung
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-samsung.la
libmm_plugin_samsung_la_SOURCES = \
	samsung/mm-plugin-samsung.c \
	samsung/mm-plugin-samsung.h \
	samsung/mm-broadband-modem-samsung.c \
	samsung/mm-broadband-modem-samsung.h \
	$(NULL)
libmm_plugin_samsung_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(ICERA_COMMON_COMPILER_FLAGS)
libmm_plugin_samsung_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_samsung_la_LIBADD   = $(ICERA_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: cinterion (previously siemens)
################################################################################

noinst_LTLIBRARIES += libhelpers-cinterion.la
libhelpers_cinterion_la_SOURCES = \
	cinterion/mm-modem-helpers-cinterion.c \
	cinterion/mm-modem-helpers-cinterion.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-cinterion
test_modem_helpers_cinterion_SOURCES = \
	cinterion/tests/test-modem-helpers-cinterion.c \
	$(NULL)
test_modem_helpers_cinterion_CPPFLAGS = \
	-I$(top_srcdir)/plugins/cinterion \
	$(NULL)
test_modem_helpers_cinterion_LDADD = \
	$(builddir)/libhelpers-cinterion.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-cinterion.la
libmm_plugin_cinterion_la_SOURCES = \
	cinterion/mm-plugin-cinterion.c \
	cinterion/mm-plugin-cinterion.h \
	cinterion/mm-common-cinterion.c \
	cinterion/mm-common-cinterion.h \
	cinterion/mm-broadband-modem-cinterion.c \
	cinterion/mm-broadband-modem-cinterion.h \
	cinterion/mm-broadband-bearer-cinterion.c \
	cinterion/mm-broadband-bearer-cinterion.h \
	$(NULL)
if WITH_QMI
libmm_plugin_cinterion_la_SOURCES += \
	cinterion/mm-broadband-modem-qmi-cinterion.c \
	cinterion/mm-broadband-modem-qmi-cinterion.h \
	$(NULL)
endif
libmm_plugin_cinterion_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_cinterion_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_cinterion_la_LIBADD   = $(builddir)/libhelpers-cinterion.la

dist_udevrules_DATA += cinterion/77-mm-cinterion-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_CINTERION=\"${srcdir}/cinterion\"

################################################################################
# plugin: iridium
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-iridium.la
libmm_plugin_iridium_la_SOURCES = \
	iridium/mm-plugin-iridium.c \
	iridium/mm-plugin-iridium.h \
	iridium/mm-broadband-modem-iridium.c \
	iridium/mm-broadband-modem-iridium.h \
	iridium/mm-bearer-iridium.c \
	iridium/mm-bearer-iridium.h \
	iridium/mm-sim-iridium.c \
	iridium/mm-sim-iridium.h \
	$(NULL)
libmm_plugin_iridium_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_iridium_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: thuraya xt
################################################################################

noinst_LTLIBRARIES += libhelpers-thuraya.la
libhelpers_thuraya_la_SOURCES = \
	thuraya/mm-modem-helpers-thuraya.c \
	thuraya/mm-modem-helpers-thuraya.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-thuraya
test_modem_helpers_thuraya_SOURCES = \
	thuraya/tests/test-mm-modem-helpers-thuraya.c \
	$(NULL)
test_modem_helpers_thuraya_CPPFLAGS = \
	-I$(top_srcdir)/plugins/thuraya \
	$(PLUGIN_COMMON_COMPILER_FLAGS) \
	$(NULL)
test_modem_helpers_thuraya_LDADD = \
	$(builddir)/libhelpers-thuraya.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-thuraya.la
libmm_plugin_thuraya_la_SOURCES = \
	thuraya/mm-plugin-thuraya.c \
	thuraya/mm-plugin-thuraya.h \
	thuraya/mm-broadband-modem-thuraya.c \
	thuraya/mm-broadband-modem-thuraya.h \
	$(NULL)
libmm_plugin_thuraya_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_thuraya_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_thuraya_la_LIBADD   = $(builddir)/libhelpers-thuraya.la

################################################################################
# plugin: novatel lte
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-novatel-lte.la
libmm_plugin_novatel_lte_la_SOURCES = \
	novatel/mm-plugin-novatel-lte.c \
	novatel/mm-plugin-novatel-lte.h \
	novatel/mm-broadband-modem-novatel-lte.c \
	novatel/mm-broadband-modem-novatel-lte.h \
	novatel/mm-broadband-bearer-novatel-lte.c \
	novatel/mm-broadband-bearer-novatel-lte.h \
	novatel/mm-sim-novatel-lte.c \
	novatel/mm-sim-novatel-lte.h \
	$(NULL)
libmm_plugin_novatel_lte_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_novatel_lte_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: novatel non-lte
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-novatel.la
libmm_plugin_novatel_la_SOURCES = \
	novatel/mm-plugin-novatel.c \
	novatel/mm-plugin-novatel.h \
	$(NULL)
libmm_plugin_novatel_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(NOVATEL_COMMON_COMPILER_FLAGS)
libmm_plugin_novatel_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_novatel_la_LIBADD   = $(NOVATEL_COMMON_LIBADD_FLAGS)

################################################################################
# plugin: altair lte
################################################################################

noinst_LTLIBRARIES += libhelpers-altair-lte.la
libhelpers_altair_lte_la_SOURCES = \
	altair/mm-modem-helpers-altair-lte.c \
	altair/mm-modem-helpers-altair-lte.h \
	$(NULL)

noinst_PROGRAMS += test-modem-helpers-altair-lte
test_modem_helpers_altair_lte_SOURCES = \
	altair/tests/test-modem-helpers-altair-lte.c \
	$(NULL)
test_modem_helpers_altair_lte_CPPFLAGS = \
	-I$(top_srcdir)/plugins/altair \
	$(NULL)
test_modem_helpers_altair_lte_LDADD   = \
	$(builddir)/libhelpers-altair-lte.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-altair-lte.la
libmm_plugin_altair_lte_la_SOURCES = \
	altair/mm-plugin-altair-lte.c \
	altair/mm-plugin-altair-lte.h \
	altair/mm-broadband-modem-altair-lte.c \
	altair/mm-broadband-modem-altair-lte.h \
	altair/mm-broadband-bearer-altair-lte.c \
	altair/mm-broadband-bearer-altair-lte.h \
	$(NULL)
libmm_plugin_altair_lte_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_altair_lte_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_altair_lte_la_LIBADD   = $(builddir)/libhelpers-altair-lte.la

################################################################################
# plugin: via
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-via.la
libmm_plugin_via_la_SOURCES = \
	via/mm-plugin-via.c \
	via/mm-plugin-via.h \
	via/mm-broadband-modem-via.c \
	via/mm-broadband-modem-via.h \
	$(NULL)
libmm_plugin_via_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_via_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

################################################################################
# plugin: telit
################################################################################

PLUGIN_TELIT_COMPILER_FLAGS = \
	-I$(top_srcdir)/plugins/telit \
	-I$(top_builddir)/plugins/telit \
	$(NULL)

noinst_LTLIBRARIES += libhelpers-telit.la

TELIT_ENUMS_INPUTS = \
	$(top_srcdir)/plugins/telit/mm-modem-helpers-telit.h \
	$(NULL)

TELIT_ENUMS_GENERATED = \
	telit/mm-telit-enums-types.h \
	telit/mm-telit-enums-types.c \
	$(NULL)

telit/mm-telit-enums-types.h: Makefile.am $(TELIT_ENUMS_INPUTS) $(top_srcdir)/build-aux/mm-enums-template.h
	$(AM_V_GEN) \
		$(MKDIR_P) telit; \
		$(GLIB_MKENUMS) \
			--fhead "#include \"mm-modem-helpers-telit.h\"\n#ifndef __MM_TELIT_ENUMS_TYPES_H__\n#define __MM_TELIT_ENUMS_TYPES_H__\n" \
			--template $(top_srcdir)/build-aux/mm-enums-template.h \
			--ftail "#endif /* __MM_TELIT_ENUMS_TYPES_H__ */\n" \
			$(TELIT_ENUMS_INPUTS) > $@

telit/mm-telit-enums-types.c: Makefile.am $(top_srcdir)/build-aux/mm-enums-template.c telit/mm-telit-enums-types.h
	$(AM_V_GEN) \
		$(MKDIR_P) telit; \
		$(GLIB_MKENUMS) \
			--fhead "#include \"mm-telit-enums-types.h\"" \
			--template $(top_srcdir)/build-aux/mm-enums-template.c \
			$(TELIT_ENUMS_INPUTS) > $@

libhelpers_telit_la_SOURCES = \
	telit/mm-modem-helpers-telit.c \
	telit/mm-modem-helpers-telit.h \
	$(NULL)

nodist_libhelpers_telit_la_SOURCES = $(TELIT_ENUMS_GENERATED)

libhelpers_telit_la_CPPFLAGS = $(PLUGIN_TELIT_COMPILER_FLAGS)

BUILT_SOURCES += $(TELIT_ENUMS_GENERATED)
CLEANFILES    += $(TELIT_ENUMS_GENERATED)

pkglib_LTLIBRARIES += libmm-plugin-telit.la
libmm_plugin_telit_la_SOURCES = \
	telit/mm-plugin-telit.c \
	telit/mm-plugin-telit.h \
	$(NULL)
libmm_plugin_telit_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(PLUGIN_TELIT_COMPILER_FLAGS)
libmm_plugin_telit_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_telit_la_LIBADD   = $(TELIT_COMMON_LIBADD_FLAGS)

dist_udevrules_DATA += telit/77-mm-telit-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_TELIT=\"${srcdir}/telit\"

noinst_PROGRAMS += test-modem-helpers-telit
test_modem_helpers_telit_SOURCES = \
	telit/tests/test-mm-modem-helpers-telit.c \
	$(NULL)
test_modem_helpers_telit_CPPFLAGS = $(PLUGIN_TELIT_COMPILER_FLAGS)
test_modem_helpers_telit_LDADD = \
	$(builddir)/libhelpers-telit.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

# Common telit modem support library
noinst_LTLIBRARIES += libmm-utils-telit.la
libmm_utils_telit_la_SOURCES = \
	telit/mm-common-telit.c \
	telit/mm-common-telit.h \
	telit/mm-broadband-modem-telit.c \
	telit/mm-broadband-modem-telit.h \
	$(NULL)
libmm_utils_telit_la_CPPFLAGS = $(PLUGIN_TELIT_COMPILER_FLAGS)

TELIT_COMMON_COMPILER_FLAGS = $(PLUGIN_TELIT_COMPILER_FLAGS)
TELIT_COMMON_LIBADD_FLAGS   = \
	$(builddir)/libhelpers-telit.la \
	$(builddir)/libmm-utils-telit.la \
	$(NULL)

################################################################################
# plugin: mtk
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-mtk.la
libmm_plugin_mtk_la_SOURCES = \
	mtk/mm-plugin-mtk.c \
	mtk/mm-plugin-mtk.h \
	mtk/mm-broadband-modem-mtk.h \
	mtk/mm-broadband-modem-mtk.c \
	$(NULL)
libmm_plugin_mtk_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_mtk_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

dist_udevrules_DATA += mtk/77-mm-mtk-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_MTK=\"${srcdir}/mtk\"

################################################################################
# plugin: haier
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-haier.la
libmm_plugin_haier_la_SOURCES = \
	haier/mm-plugin-haier.c \
	haier/mm-plugin-haier.h \
	$(NULL)
libmm_plugin_haier_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS)
libmm_plugin_haier_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)

dist_udevrules_DATA += haier/77-mm-haier-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_HAIER=\"${srcdir}/haier\"

################################################################################
# udev rules tester
################################################################################

noinst_PROGRAMS += test-udev-rules
test_udev_rules_SOURCES = \
	tests/test-udev-rules.c \
	$(NULL)
test_udev_rules_LDADD = \
	$(top_builddir)/src/libkerneldevice.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)


################################################################################
# plugin: u-blox
################################################################################

dist_udevrules_DATA += ublox/77-mm-ublox-port-types.rules

PLUGIN_UBLOX_COMPILER_FLAGS = \
	-I$(top_srcdir)/plugins/ublox \
	-I$(top_builddir)/plugins/ublox \
	$(NULL)

noinst_LTLIBRARIES += libhelpers-ublox.la

UBLOX_ENUMS_INPUTS = \
	$(top_srcdir)/plugins/ublox/mm-modem-helpers-ublox.h \
	$(NULL)

UBLOX_ENUMS_GENERATED = \
	ublox/mm-ublox-enums-types.h \
	ublox/mm-ublox-enums-types.c \
	$(NULL)

ublox/mm-ublox-enums-types.h: Makefile.am $(UBLOX_ENUMS_INPUTS) $(top_srcdir)/build-aux/mm-enums-template.h
	$(AM_V_GEN) \
		$(MKDIR_P) ublox; \
		$(GLIB_MKENUMS) \
			--fhead "#include \"mm-modem-helpers-ublox.h\"\n#ifndef __MM_UBLOX_ENUMS_TYPES_H__\n#define __MM_UBLOX_ENUMS_TYPES_H__\n" \
			--template $(top_srcdir)/build-aux/mm-enums-template.h \
			--ftail "#endif /* __MM_UBLOX_ENUMS_TYPES_H__ */\n" \
			$(UBLOX_ENUMS_INPUTS) > $@

ublox/mm-ublox-enums-types.c: Makefile.am $(top_srcdir)/build-aux/mm-enums-template.c ublox/mm-ublox-enums-types.h
	$(AM_V_GEN) \
		$(MKDIR_P) ublox; \
		$(GLIB_MKENUMS) \
			--fhead "#include \"mm-ublox-enums-types.h\"" \
			--template $(top_srcdir)/build-aux/mm-enums-template.c \
			$(UBLOX_ENUMS_INPUTS) > $@

libhelpers_ublox_la_SOURCES = \
	ublox/mm-modem-helpers-ublox.c \
	ublox/mm-modem-helpers-ublox.h \
	$(NULL)

nodist_libhelpers_ublox_la_SOURCES = $(UBLOX_ENUMS_GENERATED)

libhelpers_ublox_la_CPPFLAGS = $(PLUGIN_UBLOX_COMPILER_FLAGS)

BUILT_SOURCES += $(UBLOX_ENUMS_GENERATED)
CLEANFILES    += $(UBLOX_ENUMS_GENERATED)

noinst_PROGRAMS += test-modem-helpers-ublox
test_modem_helpers_ublox_SOURCES = \
	ublox/tests/test-modem-helpers-ublox.c \
	$(NULL)
test_modem_helpers_ublox_CPPFLAGS = \
	$(PLUGIN_UBLOX_COMPILER_FLAGS) \
	-DUBLOX_TESTS_DIR=\""$(abs_top_srcdir)/plugins/ublox/tests/"\" \
	$(NULL)
test_modem_helpers_ublox_LDADD = \
	$(builddir)/libhelpers-ublox.la \
	$(top_builddir)/src/libhelpers.la \
	$(top_builddir)/libmm-glib/libmm-glib.la \
	$(NULL)

pkglib_LTLIBRARIES += libmm-plugin-ublox.la
libmm_plugin_ublox_la_SOURCES = \
	ublox/mm-plugin-ublox.c \
	ublox/mm-plugin-ublox.h \
	ublox/mm-broadband-bearer-ublox.h \
	ublox/mm-broadband-bearer-ublox.c \
	ublox/mm-broadband-modem-ublox.h \
	ublox/mm-broadband-modem-ublox.c \
	$(NULL)
libmm_plugin_ublox_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(PLUGIN_UBLOX_COMPILER_FLAGS)
libmm_plugin_ublox_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_ublox_la_LIBADD   = $(builddir)/libhelpers-ublox.la

################################################################################
# plugin: dell (novatel, sierra or telit)
################################################################################

pkglib_LTLIBRARIES += libmm-plugin-dell.la
libmm_plugin_dell_la_SOURCES = \
	dell/mm-plugin-dell.c \
	dell/mm-plugin-dell.h \
	$(NULL)
libmm_plugin_dell_la_CPPFLAGS = $(PLUGIN_COMMON_COMPILER_FLAGS) $(NOVATEL_COMMON_COMPILER_FLAGS) $(SIERRA_COMMON_COMPILER_FLAGS) $(TELIT_COMMON_COMPILER_FLAGS) $(MBM_COMMON_COMPILER_FLAGS)
libmm_plugin_dell_la_LDFLAGS  = $(PLUGIN_COMMON_LINKER_FLAGS)
libmm_plugin_dell_la_LIBADD   = $(NOVATEL_COMMON_LIBADD_FLAGS) $(SIERRA_COMMON_LIBADD_FLAGS) $(TELIT_COMMON_LIBADD_FLAGS) $(MBM_COMMON_LIBADD_FLAGS)

dist_udevrules_DATA += dell/77-mm-dell-port-types.rules

AM_CFLAGS += -DTESTUDEVRULESDIR_DELL=\"${srcdir}/dell\"

################################################################################

TEST_PROGS += $(noinst_PROGRAMS)
