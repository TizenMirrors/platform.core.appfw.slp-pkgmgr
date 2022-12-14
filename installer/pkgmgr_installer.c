/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <glib.h>
#include <gio/gio.h>
#include <tzplatform_config.h>

#include "package-manager.h"
#include "pkgmgr_installer.h"
#include "pkgmgr_installer_config.h"
#include "pkgmgr_installer_debug.h"
#include "pkgmgr_installer_info.h"
#include "pkgmgr_installer_error.h"
#include "package-manager-types.h"

#include <pkgmgr-info.h>

/* API export macro */
#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#define MAX_STRLEN 1024
#define MAX_QUERY_LEN	4096

#define CHK_PI_RET(r) \
	do { if (NULL == pi) return (r); } while (0)

#define OPTVAL_PRELOAD 1000
#define OPTVAL_FORCE_REMOVAL 1001
#define OPTVAL_PRELOAD_RW 1002
#define OPTVAL_NO_REMOVAL 1003
#define OPTVAL_KEEP_RWDATA 1004
#define OPTVAL_PARTIAL_RW 1005
#define OPTVAL_MIGRATE_EXTIMG 1006
#define OPTVAL_SKIP_CHECK_REFERENCE 1007
#define OPTVAL_RECOVER_DB 1008
#define OPTVAL_RECOVERY_CLEANUP 1009

/* Supported options */
const char *short_opts = "k:l:i:d:c:m:t:o:r:p:s:b:e:M:y:u:w:D:A:qGS";
const struct option long_opts[] = {
	{ "session-id", 1, NULL, 'k' },
	{ "license-path", 1, NULL, 'l' },
	{ "install", 1, NULL, 'i' },
	{ "uninstall", 1, NULL, 'd' },
	{ "clear", 1, NULL, 'c' },
	{ "move", 1, NULL, 'm' },
	{ "move-type", 1, NULL, 't' },
	{ "optional-data", 0, NULL, 'o' },
	{ "reinstall", 0, NULL, 'r' },
	{ "caller-pkgid", 1, NULL, 'p' },
	{ "tep-path", 1, NULL, 'e' },
	{ "tep-move", 1, NULL, 'M' },
	{ "smack", 1, NULL, 's' },
	{ "manifest-direct-install", 1, NULL, 'y' },
	{ "mount-install", 1, NULL, 'w' },
	{ "recovery", 1, NULL, 'b' },
	{ "debug-mode", 0, NULL, 'G' },
	{ "skip-optimization", 0, NULL, 'S' },
	{ "preload", 0, NULL, OPTVAL_PRELOAD }, /* for preload RO */
	{ "force-remove", 0, NULL, OPTVAL_FORCE_REMOVAL }, /* for preload RO/RW */
	{ "preload-rw", 0, NULL, OPTVAL_PRELOAD_RW }, /* for preload RW */
	{ "no-remove", 0, NULL, OPTVAL_NO_REMOVAL }, /* for preload RW */
	{ "keep-rwdata", 0, NULL, OPTVAL_KEEP_RWDATA }, /* for preload RW */
	{ "partial-rw", 0, NULL, OPTVAL_PARTIAL_RW }, /* for preload RO */
	{ "migrate-extimg", 1, NULL, OPTVAL_MIGRATE_EXTIMG },
	{ "skip-check-reference", 0, NULL, OPTVAL_SKIP_CHECK_REFERENCE },
	{ "recover-db", 1, NULL, OPTVAL_RECOVER_DB },
	{ "recovery-cleanup", 0, NULL, OPTVAL_RECOVERY_CLEANUP },
	{ 0, 0, 0, 0 }	/* sentinel */
};

struct pkgmgr_installer {
	int request_type;
	int move_type;
	int is_upgrade;
	char *pkgmgr_info;
	char *session_id;
	char *license_path;
	char *optional_data;
	char *caller_pkgid;
	uid_t target_uid;
	char *tep_path;
	int tep_move;
	int is_tep_included;
	int is_preload;
	int force_removal;
	int is_preload_rw;
	int no_removal;
	int keep_rwdata;
	int partial_rw;
	int debug_mode;
	int skip_check_reference;
	int skip_optimization;
	int recovery_cleanup;
	GDBusConnection *conn;
	GHashTable *pkg_list;
	GList *pkgs;
};

typedef struct pkg_signal_info {
	char *pkgid;
	char *pkg_type;
} pkg_signal_info;

static uid_t g_target_uid;
static int g_debug_mode;
static int g_skip_optimization;
static pkgmgr_privilege_level g_privilege_level = PM_PRIVILEGE_UNKNOWN;

static const char *__get_signal_name(pkgmgr_installer *pi, const char *key,
		const char *pkg_type)
{
	if (strcmp(key, PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0)
		return key;
	else if (strcmp(key, PKGMGR_INSTALLER_GET_SIZE_KEY_STR) == 0)
		return key;
	else if (strcmp(key, PKGMGR_INSTALLER_APPID_KEY_STR) == 0)
		return PKGMGR_INSTALLER_UNINSTALL_EVENT_STR;
	else if (strcmp(pkg_type, PKGMGR_INSTALLER_CLEAR_CACHE_KEY_STR) == 0)
		return pkg_type;
	else if (pi->is_upgrade)
		return PKGMGR_INSTALLER_UPGRADE_EVENT_STR;


	switch (pi->request_type) {
	case PKGMGR_REQ_INSTALL:
	case PKGMGR_REQ_MANIFEST_DIRECT_INSTALL:
	case PKGMGR_REQ_MOUNT_INSTALL:
	case PKGMGR_REQ_REINSTALL:
	case PKGMGR_REQ_ENABLE_PKG:
	case PKGMGR_REQ_RECOVER:
		return PKGMGR_INSTALLER_INSTALL_EVENT_STR;
	case PKGMGR_REQ_UNINSTALL:
	case PKGMGR_REQ_DISABLE_PKG:
		return PKGMGR_INSTALLER_UNINSTALL_EVENT_STR;
	case PKGMGR_REQ_UPGRADE:
		return PKGMGR_INSTALLER_UPGRADE_EVENT_STR;
	case PKGMGR_REQ_MOVE:
		return PKGMGR_INSTALLER_MOVE_EVENT_STR;
	case PKGMGR_REQ_ENABLE_APP:
		return PKGMGR_INSTALLER_APP_ENABLE_EVENT_STR;
	case PKGMGR_REQ_DISABLE_APP:
		return PKGMGR_INSTALLER_APP_DISABLE_EVENT_STR;
	case PKGMGR_REQ_ENABLE_APP_SPLASH_SCREEN:
		return PKGMGR_INSTALLER_APP_ENABLE_SPLASH_SCREEN_EVENT_STR;
	case PKGMGR_REQ_DISABLE_APP_SPLASH_SCREEN:
		return PKGMGR_INSTALLER_APP_DISABLE_SPLASH_SCREEN_EVENT_STR;
	case PKGMGR_REQ_CLEAR:
		return PKGMGR_INSTALLER_CLEAR_EVENT_STR;
	case PKGMGR_REQ_GETSIZE:
		return PKGMGR_INSTALLER_GET_SIZE_KEY_STR;
	case PKGMGR_REQ_RES_COPY:
		return PKGMGR_INSTALLER_RES_COPY_EVENT_STR;
	case PKGMGR_REQ_RES_CREATE_DIR:
		return PKGMGR_INSTALLER_RES_CREATE_DIR_EVENT_STR;
	case PKGMGR_REQ_RES_REMOVE:
		return PKGMGR_INSTALLER_RES_REMOVE_EVENT_STR;
	case PKGMGR_REQ_RES_UNINSTALL:
		return PKGMGR_INSTALLER_RES_UNINSTALL_EVENT_STR;
	}

	ERR("cannot find type");

	return NULL;
}

static int __send_signal_for_event(pkgmgr_installer *pi, const char *pkg_type,
		const char *pkgid, const char *appid, const char *key,
		const char *val)
{
	char *sid;
	const char *tmp_appid = appid;
	const char *signal_name;
	GVariant *v;
	GVariantBuilder *builder;
	GError *err = NULL;

	if (!pi || pi->conn == NULL)
		return -1;

	sid = pi->session_id;
	if (!sid)
		sid = "";

	signal_name = __get_signal_name(pi, key, pkg_type);
	if (!signal_name) {
		ERR("unknown signal type");
		return -1;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(sss)"));
	g_variant_builder_add(builder, "(sss)", pkgid,
			(tmp_appid ? tmp_appid : ""), pkg_type);
	v = g_variant_new("(usa(sss)ss)",
			pi->target_uid, sid, builder, key, val);
	g_variant_builder_unref(builder);
	if (g_dbus_connection_emit_signal(pi->conn, NULL,
				PKGMGR_INSTALLER_DBUS_OBJECT_PATH,
				PKGMGR_INSTALLER_DBUS_INTERFACE, signal_name,
				v, &err) != TRUE) {
		ERR("failed to send dbus signal");
		if (err) {
			ERR("err: %s", err->message);
			g_error_free(err);
		}
		return -1;
	}

	return 0;
}

static int __send_signal_to_agent(uid_t uid, void *data, size_t len)
{
	int fd;
	struct sockaddr_un sa;
	int r;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (fd == -1) {
		ERR("failed to create socket: %d", errno);
		return -1;
	}

	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "/run/pkgmgr/agent/%d", uid);

	r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		ERR("failed to connect socket(%s): %d", sa.sun_path, errno);
		close(fd);
		return -1;
	}

	r = send(fd, data, len, MSG_NOSIGNAL);
	if (r < 0) {
		ERR("failed to send data: %d", errno);
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

static int __send_signal_for_event_for_uid(pkgmgr_installer *pi, uid_t uid,
		const char *pkg_type, const char *pkgid, const char *appid,
		const char *key, const char *val)
{
	char *sid;
	const char *signal_name;
	const char *tmp_appid = appid;
	size_t name_size;
	GVariantBuilder *builder;
	GVariant *gv;
	gsize gv_len;
	gpointer gv_data;
	void *data;
	void *ptr;
	size_t data_len;

	if (!pi || pi->conn == NULL)
		return -1;

	sid = pi->session_id;
	if (!sid)
		sid = "";

	data_len = sizeof(size_t) + sizeof(gsize);

	signal_name = __get_signal_name(pi, key, pkg_type);
	if (!signal_name) {
		ERR("unknown signal name");
		return -1;
	}

	/* including null byte */
	name_size = strlen(signal_name) + 1;
	data_len += name_size;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(sss)"));
	g_variant_builder_add(builder, "(sss)", pkgid,
			(tmp_appid ? tmp_appid : ""), pkg_type);
	gv = g_variant_new("(usa(sss)ss)", pi->target_uid, sid,
			builder, key, val);
	g_variant_builder_unref(builder);
	if (gv == NULL) {
		ERR("failed to create GVariant instance");
		return -1;
	}
	gv_len = g_variant_get_size(gv);
	gv_data = g_malloc(gv_len);
	g_variant_store(gv, gv_data);
	g_variant_unref(gv);
	data_len += gv_len;

	data = malloc(data_len);
	if (data == NULL) {
		ERR("out of memory");
		g_free(gv_data);
		return -1;
	}
	ptr = data;
	memcpy(ptr, &name_size, sizeof(size_t));
	ptr += sizeof(size_t);
	memcpy(ptr, &gv_len, sizeof(gsize));
	ptr += sizeof(gsize);
	memcpy(ptr, signal_name, name_size);
	ptr += name_size;
	memcpy(ptr, gv_data, gv_len);
	g_free(gv_data);

	if (__send_signal_to_agent(uid, data, data_len)) {
		ERR("failed to send signal to agent");
		free(data);
		return -1;
	}

	free(data);

	return 0;
}

static void __free_pkg_list(gpointer data)
{
	pkg_signal_info *info = (pkg_signal_info *)data;
	free(info->pkgid);
	free(info->pkg_type);
	free(info);
}

API pkgmgr_installer *pkgmgr_installer_new(void)
{
	pkgmgr_installer *pi;
	GError *err = NULL;

	pi = calloc(1, sizeof(struct pkgmgr_installer));
	if (pi == NULL)
		return NULL;

	pi->conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (pi->conn == NULL) {
		ERR("failed to get bus: %s", err->message);
		g_error_free(err);
		free(pi);
		return NULL;
	}

	pi->tep_path = NULL;
	pi->tep_move = 0;
	pi->request_type = PKGMGR_REQ_INVALID;
	pi->pkg_list = g_hash_table_new_full(
			g_str_hash, g_str_equal, NULL, __free_pkg_list);
	return pi;
}

API pkgmgr_installer *pkgmgr_installer_offline_new(void)
{
	pkgmgr_installer *pi;

	pi = calloc(1, sizeof(struct pkgmgr_installer));
	if (pi == NULL)
		return NULL;

	pi->tep_path = NULL;
	pi->tep_move = 0;
	pi->request_type = PKGMGR_REQ_INVALID;

	return pi;
}

API int pkgmgr_installer_free(pkgmgr_installer *pi)
{
	CHK_PI_RET(-EINVAL);

	/* free members */
	if (pi->pkgmgr_info)
		free(pi->pkgmgr_info);
	if (pi->session_id)
		free(pi->session_id);
	if (pi->optional_data)
		free(pi->optional_data);
	if (pi->caller_pkgid)
		free(pi->caller_pkgid);
	if (pi->tep_path)
		free(pi->tep_path);

	if (pi->conn) {
		g_dbus_connection_flush_sync(pi->conn, NULL, NULL);
		g_object_unref(pi->conn);
	}

	if (pi->pkgs)
		g_list_free_full(pi->pkgs, free);

	if (pi->pkg_list)
		g_hash_table_destroy(pi->pkg_list);

	free(pi);

	return 0;
}

static void __parse_multiple_pkgs(pkgmgr_installer *pi, int argc, char **argv)
{
	while ((optind <= argc) && (*argv[optind - 1] != '-')) {
		pi->pkgs = g_list_append(pi->pkgs, strdup(argv[optind - 1]));
		optind++;
	}
	optind--;
}

API int
pkgmgr_installer_receive_request(pkgmgr_installer *pi,
				 const int argc, char **argv)
{
	CHK_PI_RET(-EINVAL);

	int r = 0;

	/* Parse argv */
	optind = 1;		/* Initialize optind to clear prev. index */
	int opt_idx = 0;
	int c;
	int mode = 0;

	pi->target_uid = getuid();
	g_target_uid = pi->target_uid;
	g_debug_mode = 0;
	g_skip_optimization = 0;

	if (pi->pkgs) {
		g_list_free_full(pi->pkgs, free);
		pi->pkgs = NULL;
	}

	while (1) {
		c = getopt_long(argc, argv, short_opts, long_opts, &opt_idx);
		/* printf("c=%d %c\n", c, c); //debug */
		if (-1 == c)
			break;	/* Parse is end */
		switch (c) {
		case OPTVAL_PRELOAD:	/* request for preload app */
			pi->is_preload = 1;
			DBG("preload request [%d]", pi->is_preload);
			break;
		case OPTVAL_FORCE_REMOVAL:	/* request for force-remove */
			pi->force_removal = 1;
			DBG("force-remove request [%d]", pi->force_removal);
			break;
		case OPTVAL_PRELOAD_RW:	/* request for preload-rw app */
			pi->is_preload_rw = 1;
			DBG("preload-rw request [%d]", pi->is_preload_rw);
			break;
		case OPTVAL_NO_REMOVAL:	/* request for no-remove */
			pi->no_removal = 1;
			DBG("no-remove request [%d]", pi->no_removal);
			break;
		case OPTVAL_KEEP_RWDATA:	/* request for keep-rwdata */
			pi->keep_rwdata = 1;
			DBG("keep-rwdata request [%d]", pi->keep_rwdata);
			break;
		case OPTVAL_PARTIAL_RW:	/* request for partial-rw */
			pi->partial_rw = 1;
			DBG("partial-rw request [%d]", pi->partial_rw);
			break;
		case OPTVAL_MIGRATE_EXTIMG:
			/* request for legacy extimg migration */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = OPTVAL_MIGRATE_EXTIMG;
			pi->request_type = PKGMGR_REQ_MIGRATE_EXTIMG;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			DBG("legacy extimg migration requested");
			break;
		case OPTVAL_SKIP_CHECK_REFERENCE:
			pi->skip_check_reference = 1;
			break;
		case OPTVAL_RECOVER_DB:
			pi->request_type = PKGMGR_REQ_RECOVER_DB;
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;
		case OPTVAL_RECOVERY_CLEANUP:
			pi->recovery_cleanup = 1;
			break;
		case 'k':	/* session id */
			if (pi->session_id)
				free(pi->session_id);
			pi->session_id = strndup(optarg, MAX_STRLEN);
			break;

		case 'l':	/* license path */
			if (pi->license_path)
				free(pi->license_path);
			pi->license_path = strndup(optarg, MAX_STRLEN);
			break;

		case 'i':	/* install */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'i';
			pi->request_type = PKGMGR_REQ_INSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			DBG("option is [i] pkgid[%s]", pi->pkgmgr_info);
			if (pi->pkgmgr_info && strlen(pi->pkgmgr_info) == 0) {
				free(pi->pkgmgr_info);
				pi->pkgmgr_info = NULL;
			} else {
				mode = 'i';
			}
			break;

		case 'e':	/* install */
			if (pi->tep_path)
				free(pi->tep_path);
			pi->tep_path = strndup(optarg, MAX_STRLEN);
			pi->is_tep_included = 1;
			DBG("option is [e] tep_path[%s]", pi->tep_path);
			break;

		case 'M':	/* install */
			if (strcmp(optarg, "tep_move") == 0)
				pi->tep_move = 1;
			else
				pi->tep_move = 0;
			DBG("option is [M] tep_move[%d]", pi->tep_move);
			break;

		case 'd':	/* uninstall */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'd';
			pi->request_type = PKGMGR_REQ_UNINSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;


		case 'c':	/* clear */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'c';
			pi->request_type = PKGMGR_REQ_CLEAR;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'm':	/* move */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'm';
			pi->request_type = PKGMGR_REQ_MOVE;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'r':	/* reinstall */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'r';
			pi->request_type = PKGMGR_REQ_REINSTALL;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 't': /* move type*/
			pi->move_type = atoi(optarg);
			break;

		case 'p': /* caller pkgid*/
			if (pi->caller_pkgid)
				free(pi->caller_pkgid);
			pi->caller_pkgid = strndup(optarg, MAX_STRLEN);

			break;

		case 's':	/* smack */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 's';
			pi->request_type = PKGMGR_REQ_SMACK;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'o': /* optional data*/
			pi->optional_data = strndup(optarg, MAX_STRLEN);
			break;

		case 'y': /* pkgid for direct manifest installation */
			mode = 'y';
			pi->request_type = PKGMGR_REQ_MANIFEST_DIRECT_INSTALL;
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'w': /* pkgid for mount installation */
			mode = 'w';
			pi->request_type = PKGMGR_REQ_MOUNT_INSTALL;
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'b': /* recovery */
			if (mode) {
				r = -EINVAL;
				goto RET;
			}
			mode = 'b';
			pi->request_type = PKGMGR_REQ_RECOVER;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'D': /* disable pkg */
			pi->request_type = PKGMGR_REQ_DISABLE_PKG;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'A': /* enable pkg */
			pi->request_type = PKGMGR_REQ_ENABLE_PKG;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			__parse_multiple_pkgs(pi, argc, argv);
			break;

		case 'u': /* uid */
			g_target_uid = (uid_t)atoi(optarg);
			pi->target_uid = (uid_t)atoi(optarg);
			break;

		case 'G': /* debug mode */
			pi->debug_mode = 1;
			g_debug_mode = 1;
			break;

		case 'S': /* skip optimization */
			pi->skip_optimization = 1;
			g_skip_optimization = 1;
			break;

			/* Otherwise */
		case '?':	/* Not an option */
			break;

		case ':':	/* */
			break;

		}
	}

	/* if target user is not set, set as tizenglobalapp user */
	if (pi->target_uid == 0) {
		pi->target_uid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);
		g_target_uid = pi->target_uid;
	}
 RET:
	return r;
}

API int pkgmgr_installer_get_request_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->request_type;
}

API uid_t pkgmgr_installer_get_uid(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->target_uid;
}

API const char *pkgmgr_installer_get_request_info(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->pkgmgr_info;
}

API const char *pkgmgr_installer_get_request_info_at(pkgmgr_installer *pi,
		int at)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return (const char *)g_list_nth_data(pi->pkgs, at);
}

API int pkgmgr_installer_get_request_info_count(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return g_list_length(pi->pkgs);
}

API const char *pkgmgr_installer_get_tep_path(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->tep_path;
}

API int pkgmgr_installer_get_tep_move_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->tep_move;
}

API const char *pkgmgr_installer_get_session_id(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->session_id;
}

API const char *pkgmgr_installer_get_license_path(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->license_path;
}

API const char *pkgmgr_installer_get_optional_data(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->optional_data;
}

API int pkgmgr_installer_is_quiet(pkgmgr_installer *pi)
{
	return 1;
}

API int pkgmgr_installer_get_move_type(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->move_type;
}

API const char *pkgmgr_installer_get_caller_pkgid(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->caller_pkgid;
}

API int pkgmgr_installer_get_is_preload(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->is_preload;
}

API int pkgmgr_installer_get_force_removal(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->force_removal;
}

API int pkgmgr_installer_get_is_preload_rw(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->is_preload_rw;
}

API int pkgmgr_installer_get_no_removal(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->no_removal;
}

API int pkgmgr_installer_get_keep_rwdata(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->keep_rwdata;
}

API int pkgmgr_installer_get_partial_rw(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->partial_rw;
}

API int pkgmgr_installer_get_debug_mode(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->debug_mode;
}

API int pkgmgr_installer_get_skip_check_reference(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->skip_check_reference;
}

API int pkgmgr_installer_get_skip_optimization(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->skip_optimization;
}

API int pkgmgr_installer_get_recovery_cleanup(pkgmgr_installer *pi)
{
	CHK_PI_RET(PKGMGR_REQ_INVALID);
	return pi->recovery_cleanup;
}

API int pkgmgr_installer_send_app_uninstall_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *val)
{
	int ret = 0;
	ret = __send_signal_for_event(pi, pkg_type, pkgid, NULL,
			PKGMGR_INSTALLER_APPID_KEY_STR, val);
	return ret;
}

API int pkgmgr_installer_send_app_uninstall_signal_for_uid(
		pkgmgr_installer *pi, uid_t uid, const char *pkg_type,
		const char *pkgid, const char *val)
{
	int ret = 0;
	ret = __send_signal_for_event_for_uid(pi, uid, pkg_type, pkgid, NULL,
			PKGMGR_INSTALLER_APPID_KEY_STR, val);
	return ret;
}

API int pkgmgr_installer_set_uid(pkgmgr_installer *pi, uid_t uid)
{
	if (pi == NULL)
		return -1;

	pi->target_uid = uid;
	g_target_uid = pi->target_uid;

	return 0;
}

API int
pkgmgr_installer_send_app_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *appid,
			     const char *key, const char *val)
{
	int r = 0;

	if (!pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	r = __send_signal_for_event(pi, pkg_type, pkgid, appid, key, val);

	return r;
}

API int
pkgmgr_installer_send_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *key, const char *val)
{
	int r = 0;

	if (!pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	r = __send_signal_for_event(pi, pkg_type, pkgid, NULL, key, val);

	return r;
}

API int pkgmgr_installer_send_app_signal_for_uid(pkgmgr_installer *pi,
		uid_t uid, const char *pkg_type, const char *pkgid,
		const char *appid, const char *key, const char *val)
{
	int r = 0;

	if (!pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	r = __send_signal_for_event_for_uid(pi, uid, pkg_type, pkgid, appid,
			key, val);

	return r;
}

API int pkgmgr_installer_send_signal_for_uid(pkgmgr_installer *pi,
		uid_t uid, const char *pkg_type, const char *pkgid,
		const char *key, const char *val)
{
	int r = 0;

	if (!pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	r = __send_signal_for_event_for_uid(pi, uid, pkg_type, pkgid, NULL,
			key, val);

	return r;
}

API int pkgmgr_installer_set_request_type(pkgmgr_installer *pi, int request_type)
{
	if (pi == NULL)
		return -1;

	pi->request_type = request_type;
	return 0;
}

API int pkgmgr_installer_set_session_id(pkgmgr_installer *pi, const char *session_id)
{
	if (pi == NULL || session_id == NULL)
		return -1;

	pi->session_id = strndup(session_id, MAX_STRLEN);
	return 0;
}

API int pkgmgr_installer_create_certinfo_set_handle(pkgmgr_instcertinfo_h *handle)
{
	int ret = 0;
	ret = pkgmgrinfo_create_certinfo_set_handle(handle);
	return ret;
}

API int pkgmgr_installer_set_cert_value(pkgmgr_instcertinfo_h handle, pkgmgr_instcert_type cert_type, char *cert_value)
{
	int ret = 0;
	ret = pkgmgrinfo_set_cert_value(handle, cert_type, cert_value);
	return ret;
}

API int pkgmgr_installer_save_certinfo(const char *pkgid, pkgmgr_instcertinfo_h handle, uid_t uid)
{
	int ret = 0;
	ret = pkgmgrinfo_save_certinfo(pkgid, handle, uid);
	return ret;
}

API int pkgmgr_installer_destroy_certinfo_set_handle(pkgmgr_instcertinfo_h handle)
{
	int ret = 0;
	ret = pkgmgrinfo_destroy_certinfo_set_handle(handle);
	return ret;
}

API int pkgmgr_installer_delete_certinfo(const char *pkgid)
{
	int ret = 0;
	ret = pkgmgrinfo_delete_certinfo(pkgid);
	return ret;
}

API int pkgmgr_installer_set_privilege_level(pkgmgr_privilege_level level)
{
	g_privilege_level = level;

	return 0;
}

API int pkgmgr_installer_info_get_target_uid(uid_t *uid)
{
	*uid = g_target_uid;

	return 0;
}

API int pkgmgr_installer_info_get_privilege_level(pkgmgr_privilege_level *level)
{
	*level = g_privilege_level;

	return 0;
}

API int pkgmgr_installer_info_get_debug_mode(int *debug_mode)
{
	*debug_mode = g_debug_mode;
	return 0;
}

API int pkgmgr_installer_info_get_skip_optimization(int *skip_optimization)
{
	*skip_optimization = g_skip_optimization;
	return 0;
}

#define CASE_TO_STR(ERRCODE) case ERRCODE: return ERRCODE##_STR
API const char *pkgmgr_installer_error_to_string(int error_code)
{
	switch (error_code) {
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_UNDEFINED_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_GLOBALSYMLINK_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_GRANT_PERMISSION_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_IMAGE_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_UNZIP_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_SECURITY_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_REGISTER_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_PRIVILEGE_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_PARSE_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_RECOVERY_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_DELTA_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_APP_DIR_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_CONFIG_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_SIGNATURE_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_SIGNATURE_INVALID);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_CERT_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_MATCH);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_FOUND);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_ICON_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_ICON_NOT_FOUND);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_MANIFEST_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_MANIFEST_NOT_FOUND);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_PACKAGE_NOT_FOUND);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_OPERATION_NOT_ALLOWED);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_OUT_OF_SPACE);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_INVALID_VALUE);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_ERROR);
	CASE_TO_STR(PKGMGR_INSTALLER_ERRCODE_OK);
	default:
		return PKGMGR_INSTALLER_ERRCODE_UNDEFINED_ERROR_STR;
	}
}

API int pkgmgr_installer_add_pkg(pkgmgr_installer *pi,
		const char *pkgid, const char *pkg_type)
{
	pkg_signal_info *info;
	if (!pi || !pkgid || !pkg_type) {
		ERR("invalid argument");
		return -1;
	}

	info = calloc(1, sizeof(pkg_signal_info));
	if (!info) {
		ERR("out of memory");
		return -1;
	}

	info->pkgid = strdup(pkgid);
	info->pkg_type = strdup(pkg_type);
	if (!info->pkgid || !info->pkg_type) {
		ERR("out of memory");
		free(info->pkgid);
		free(info->pkg_type);
		free(info);
		return -1;
	}
	g_hash_table_insert(pi->pkg_list, (gpointer)info->pkgid, (gpointer)info);

	return 0;
}

static void __build_multi_signal(gpointer key, gpointer value,
		gpointer user_data)
{
	GVariantBuilder *builder = (GVariantBuilder *)user_data;
	pkg_signal_info *info = (pkg_signal_info *)value;

	g_variant_builder_add(builder, "(sss)", info->pkgid, "", info->pkg_type);
}

API int pkgmgr_installer_send_signals(pkgmgr_installer *pi,
		const char *key, const char *val)
{
	char *sid;
	const char *signal_name;
	GError *err = NULL;
	GVariantBuilder *builder;

	if (!pi || !key || !val) {
		ERR("invalid argument");
		return -1;
	}

	sid = pi->session_id;
	if (!sid)
		sid = "";

	signal_name = __get_signal_name(pi, key, "");
	if (!signal_name) {
		ERR("unknown signal type");
		return -1;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(sss)"));
	g_hash_table_foreach(pi->pkg_list, __build_multi_signal, builder);
	if (g_dbus_connection_emit_signal(pi->conn, NULL,
				PKGMGR_INSTALLER_DBUS_OBJECT_PATH,
				PKGMGR_INSTALLER_DBUS_INTERFACE, signal_name,
				g_variant_new("(usa(sss)ss)",
						pi->target_uid, sid, builder, key,
						val), &err) != TRUE) {
		ERR("failed to send dbus signal");
		if (err) {
			ERR("err: %s", err->message);
			g_error_free(err);
		}
		g_variant_builder_unref(builder);
		return -1;
	}
	g_variant_builder_unref(builder);

	return 0;
}

API int pkgmgr_installer_send_signals_for_uid(pkgmgr_installer *pi, uid_t uid,
		const char *key, const char *val)
{
	char *sid;
	size_t data_len;
	size_t name_size;
	GVariant *gv;
	GVariantBuilder *builder;
	gsize gv_len;
	gpointer gv_data;
	void *data;
	void *ptr;
	const char *signal_name;

	if (!pi || !pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	sid = pi->session_id;
	if (!sid)
		sid = "";

	data_len = sizeof(size_t) + sizeof(gsize);

	/* including null byte */
	signal_name = __get_signal_name(pi, key, "");
	if (!signal_name) {
		ERR("unknown signal type");
		return -1;
	}
	name_size = strlen(signal_name) + 1;
	data_len += name_size;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(sss)"));
	g_hash_table_foreach(pi->pkg_list, __build_multi_signal, builder);

	gv = g_variant_new("(usa(sss)ss)", uid, sid, builder, key, val);
	g_variant_builder_unref(builder);
	if (gv == NULL) {
		ERR("failed to create GVariant instance");
		return -1;
	}

	gv_len = g_variant_get_size(gv);
	gv_data = g_malloc(gv_len);
	g_variant_store(gv, gv_data);
	g_variant_unref(gv);
	data_len += gv_len;

	data = malloc(data_len);
	if (data == NULL) {
		ERR("out of memory");
		g_free(gv_data);
		return -1;
	}
	ptr = data;
	memcpy(ptr, &name_size, sizeof(size_t));
	ptr += sizeof(size_t);
	memcpy(ptr, &gv_len, sizeof(gsize));
	ptr += sizeof(gsize);
	memcpy(ptr, signal_name, name_size);
	ptr += name_size;
	memcpy(ptr, gv_data, gv_len);
	g_free(gv_data);

	if (__send_signal_to_agent(uid, data, data_len)) {
		ERR("failed to send signal to agent");
		free(data);
		return -1;
	}

	free(data);

	return 0;
}

API int pkgmgr_installer_set_is_upgrade(pkgmgr_installer *pi, int is_upgrade) {
	if (pi == NULL)
		return -1;

	pi->is_upgrade = is_upgrade;
	return 0;
}

static GVariant *__get_gvariant_from_event_info(pkgmgr_res_event_info *event_info)
{
	pkgmgr_res_event_info_t *info = event_info;
	GVariantBuilder *builder;
	GVariant *result;
	GList *path_states;
	res_event_path_state_t *path_state;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a(si)"));
	if (builder == NULL) {
		ERR("out of memory");
		return NULL;
	}

	for (path_states = info->path_states; path_states != NULL;
			path_states = path_states->next) {
		path_state = (res_event_path_state_t *)path_states->data;
		g_variant_builder_add(builder, "(si)",
				path_state->path, path_state->state);
	}

	result = g_variant_new("(ia(si))", info->error_code, builder);
	g_variant_builder_unref(builder);

	if (result == NULL) {
		ERR("Fail to create extra data");
		return NULL;
	}

	return result;
}

API int pkgmgr_installer_send_res_signal(pkgmgr_installer *pi,
		const char *pkgid, const char *status,
		pkgmgr_res_event_info *event_info)
{
	char *sid;
	const char *signal_name;
	GError *err = NULL;
	GVariant *extra_param;

	if (!pi || !pkgid || !status) {
		ERR("invalid argument");
		return -1;
	}

	sid = pi->session_id;
	if (!sid)
		sid = "";

	signal_name = __get_signal_name(pi, "", "");
	if (!signal_name) {
		ERR("unknown signal type");
		return -1;
	}

	extra_param = __get_gvariant_from_event_info(event_info);
	if (extra_param == NULL) {
		ERR("Fail to get extra parameter");
		return -1;
	}

	if (g_dbus_connection_emit_signal(pi->conn, NULL,
				PKGMGR_INSTALLER_DBUS_OBJECT_PATH,
				PKGMGR_INSTALLER_DBUS_INTERFACE, signal_name,
				g_variant_new("(usssv)", pi->target_uid, sid,
						pkgid, status, extra_param),
				&err) != TRUE) {
		ERR("failed to send dbus signal");
		if (err) {
			ERR("err: %s", err->message);
			g_error_free(err);
		}
		return -1;
	}

	return 0;
}

API int pkgmgr_installer_send_res_signal_for_uid(pkgmgr_installer *pi,
		uid_t uid, const char *pkgid, const char *status,
		pkgmgr_res_event_info *event_info)
{
	char *sid;
	size_t data_len;
	size_t name_size;
	GVariant *gv;
	gsize gv_len;
	gpointer gv_data;
	void *data;
	void *ptr;
	const char *signal_name;
	GVariant *extra_param;

	if (!pi || !pi->conn) {
		ERR("connection is NULL");
		return -1;
	}

	sid = pi->session_id;
	if (!sid)
		sid = "";

	data_len = sizeof(size_t) + sizeof(gsize);

	/* including null byte */
	signal_name = __get_signal_name(pi, "", "");
	if (!signal_name) {
		ERR("unknown signal type");
		return -1;
	}
	name_size = strlen(signal_name) + 1;
	data_len += name_size;

	extra_param = __get_gvariant_from_event_info(event_info);
	if (extra_param == NULL) {
		ERR("Fail to get extra parameter");
		return -1;
	}

	gv = g_variant_new("(usssv)", pi->target_uid, sid,
			pkgid, status, extra_param);
	if (gv == NULL) {
		ERR("failed to create GVariant instance");
		return -1;
	}

	gv_len = g_variant_get_size(gv);
	gv_data = g_malloc(gv_len);
	g_variant_store(gv, gv_data);
	g_variant_unref(gv);
	data_len += gv_len;

	data = malloc(data_len);
	if (data == NULL) {
		ERR("out of memory");
		g_free(gv_data);
		return -1;
	}
	ptr = data;
	memcpy(ptr, &name_size, sizeof(size_t));
	ptr += sizeof(size_t);
	memcpy(ptr, &gv_len, sizeof(gsize));
	ptr += sizeof(gsize);
	memcpy(ptr, signal_name, name_size);
	ptr += name_size;
	memcpy(ptr, gv_data, gv_len);
	g_free(gv_data);

	if (__send_signal_to_agent(uid, data, data_len)) {
		ERR("failed to send signal to agent");
		free(data);
		return -1;
	}

	free(data);

	return 0;
}
