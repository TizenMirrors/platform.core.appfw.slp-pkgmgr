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



#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#include <gio/gio.h>

#include "pkgmgr_installer.h"
#include "pkgmgr_installer_config.h"
#include "pkgmgr_installer_debug.h"
#include "pkgmgr_installer_info.h"

#include "../client/include/comm_config.h"

#include <pkgmgr-info.h>

/* API export macro */
#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#define MAX_STRLEN 1024
#define MAX_QUERY_LEN	4096

#define CHK_PI_RET(r) \
	do { if (NULL == pi) return (r); } while (0)

struct pkgmgr_installer {
	int request_type;
	int move_type;
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
	GDBusConnection *conn;
};

static uid_t g_target_uid;

static const char *__get_signal_name(pkgmgr_installer *pi, const char *key)
{
	if (strcmp(key, PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0)
		return COMM_STATUS_BROADCAST_EVENT_INSTALL_PROGRESS;
	else if (strcmp(key, PKGMGR_INSTALLER_GET_SIZE_KEY_STR) == 0)
		return COMM_STATUS_BROADCAST_EVENT_GET_SIZE;
	else if (strcmp(key, PKGMGR_INSTALLER_APPID_KEY_STR) == 0)
		return COMM_STATUS_BROADCAST_EVENT_UNINSTALL;

	switch (pi->request_type) {
	case PKGMGR_REQ_INSTALL:
	case PKGMGR_REQ_MANIFEST_DIRECT_INSTALL:
	case PKGMGR_REQ_MOUNT_INSTALL:
		return COMM_STATUS_BROADCAST_EVENT_INSTALL;
	case PKGMGR_REQ_UNINSTALL:
		return COMM_STATUS_BROADCAST_EVENT_UNINSTALL;
	case PKGMGR_REQ_UPGRADE:
		return COMM_STATUS_BROADCAST_EVENT_UPGRADE;
	case PKGMGR_REQ_MOVE:
		return COMM_STATUS_BROADCAST_EVENT_MOVE;
	case PKGMGR_REQ_ENABLE_APP:
		return COMM_STATUS_BROADCAST_EVENT_ENABLE_APP;
	case PKGMGR_REQ_DISABLE_APP:
		return COMM_STATUS_BROADCAST_EVENT_DISABLE_APP;
	case PKGMGR_REQ_ENABLE_APP_SPLASH_SCREEN:
		return COMM_STATUS_BROADCAST_EVENT_ENABLE_APP_SPLASH_SCREEN;
	case PKGMGR_REQ_DISABLE_APP_SPLASH_SCREEN:
		return COMM_STATUS_BROADCAST_EVENT_DISABLE_APP_SPLASH_SCREEN;
	}

	ERR("cannot find type, send signal with type SIGNAL_STATUS");

	return COMM_STATUS_BROADCAST_SIGNAL_STATUS;
}

static int __send_signal_for_app_event(pkgmgr_installer *pi, const char *pkg_type,
		const char *pkgid, const char *appid, const char *key, const char *val)
{
	char *sid;
	const char *name;
	GError *err = NULL;

	if (!pi || pi->conn == NULL || appid == NULL)
		return -1;

	sid = pi->session_id;
	if (!sid)
		sid = "";

	name = __get_signal_name(pi, key);
	if (name == NULL) {
		ERR("unknown signal type");
		return -1;
	}

	if (g_dbus_connection_emit_signal(pi->conn, NULL,
				COMM_STATUS_BROADCAST_OBJECT_PATH,
				COMM_STATUS_BROADCAST_INTERFACE, name,
				g_variant_new("(ussssss)", pi->target_uid, sid,
					pkg_type, pkgid, appid, key, val), &err)
			!= TRUE) {
		ERR("failed to send dbus signal: %s", err->message);
		g_error_free(err);
		return -1;
	}

	return 0;
}

static int __send_signal_for_event(pkgmgr_installer *pi, const char *pkg_type,
		const char *pkgid, const char *key, const char *val)
{
	char *sid;
	const char *name;
	GError *err = NULL;

	if (!pi || pi->conn == NULL)
		return -1;

	sid = pi->session_id;
	if (!sid)
		sid = "";

	name = __get_signal_name(pi, key);
	if (name == NULL) {
		ERR("unknown signal type");
		return -1;
	}

	if (g_dbus_connection_emit_signal(pi->conn, NULL,
				COMM_STATUS_BROADCAST_OBJECT_PATH,
				COMM_STATUS_BROADCAST_INTERFACE, name,
				g_variant_new("(ussssss)", pi->target_uid, sid,
					pkg_type, pkgid, "", key, val), &err)
			!= TRUE) {
		ERR("failed to send dbus signal: %s", err->message);
		g_error_free(err);
		return -1;
	}

	return 0;
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

	free(pi);

	return 0;
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
			DBG("option is [i] pkgid[%s]", pi->pkgmgr_info);
			if (pi->pkgmgr_info && strlen(pi->pkgmgr_info) == 0)
				free(pi->pkgmgr_info);
			else
				mode = 'i';
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
			break;

		case 'o': /* optional data*/
			pi->optional_data = strndup(optarg, MAX_STRLEN);
			break;

		case 'y': /* pkgid for direct manifest installation */
			mode = 'y';
			pi->request_type = PKGMGR_REQ_MANIFEST_DIRECT_INSTALL;
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'w': /* pkgid for mount installation */
			mode = 'w';
			pi->request_type = PKGMGR_REQ_MOUNT_INSTALL;
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
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
			break;

		case 'D': /* disable pkg */
			pi->request_type = PKGMGR_REQ_DISABLE_PKG;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'A': /* enable pkg */
			pi->request_type = PKGMGR_REQ_ENABLE_PKG;
			if (pi->pkgmgr_info)
				free(pi->pkgmgr_info);
			pi->pkgmgr_info = strndup(optarg, MAX_STRLEN);
			break;

		case 'u': /* uid */
			g_target_uid = (uid_t)atoi(optarg);
			pi->target_uid = (uid_t)atoi(optarg);
			break;

			/* Otherwise */
		case '?':	/* Not an option */
			break;

		case ':':	/* */
			break;

		}
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

API int pkgmgr_installer_send_app_uninstall_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *val)
{
	int ret = 0;
	ret = __send_signal_for_event(pi, pkg_type, pkgid,
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

	r = __send_signal_for_app_event(pi, pkg_type, pkgid, appid, key, val);

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

	if (strcmp(key, PKGMGR_INSTALLER_START_KEY_STR) == 0 &&
			strcmp(val, PKGMGR_INSTALLER_UPGRADE_EVENT_STR) == 0)
		pi->request_type = PKGMGR_REQ_UPGRADE;

	r = __send_signal_for_event(pi, pkg_type, pkgid, key, val);

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

API int pkgmgr_installer_info_get_target_uid(uid_t *uid)
{
	*uid = g_target_uid;

	return 0;
}
