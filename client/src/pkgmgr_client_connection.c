/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <gio/gio.h>

#include "package-manager.h"
#include "pkgmgr_client_debug.h"
#include "pkgmgr_client_internal.h"
#include "../../installer/pkgmgr_installer.h"
#include "../../installer/pkgmgr_installer_config.h"

#define CONNECTION_RETRY_MAX 5
#define CONNECTION_WAIT_USEC (1000000 / 2) /* 0.5 sec */
#define CONNECTION_TIMEOUT_MSEC 5000 /* 5 sec */
#define REGULAR_USER 5000

static int _is_system_user(void)
{
	uid_t uid = getuid();

	if (uid < REGULAR_USER)
		return 1;
	else
		return 0;
}

static GBusType __get_bus_type(pkgmgr_client_type type)
{
	if (type == PC_REQUEST || _is_system_user())
		return G_BUS_TYPE_SYSTEM;
	else
		return G_BUS_TYPE_SESSION;
}

int pkgmgr_client_connection_connect(struct pkgmgr_client_t *pc)
{
	GError *error = NULL;
	GBusType bus_type;

#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init();
#endif
	bus_type = __get_bus_type(pc->pc_type);
	pc->conn = g_bus_get_sync(bus_type, NULL, &error);
	if (error) {
		ERR("gdbus connection error (%s)", error->message);
		g_error_free(error);
		return PKGMGR_R_ECOMM;
	}

	return PKGMGR_R_OK;
}

void pkgmgr_client_connection_disconnect(struct pkgmgr_client_t *pc)
{
	/* flush remaining buffer: blocking mode */
	g_dbus_connection_flush_sync(pc->conn, NULL, NULL);
	g_object_unref(pc->conn);
	pc->conn = NULL;
}

struct signal_map {
	const char *signal_str;
	int signal_type;
};

struct signal_map map[] = {
	{PKGMGR_INSTALLER_INSTALL_EVENT_STR, PKGMGR_CLIENT_STATUS_INSTALL},
	{PKGMGR_INSTALLER_UNINSTALL_EVENT_STR, PKGMGR_CLIENT_STATUS_UNINSTALL},
	{PKGMGR_INSTALLER_UPGRADE_EVENT_STR, PKGMGR_CLIENT_STATUS_UPGRADE},
	{PKGMGR_INSTALLER_CLEAR_EVENT_STR, PKGMGR_CLIENT_STATUS_CLEAR_DATA},
	{PKGMGR_INSTALLER_MOVE_EVENT_STR, PKGMGR_CLIENT_STATUS_MOVE},
	{PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR,
		PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS},
	{PKGMGR_INSTALLER_GET_SIZE_KEY_STR, PKGMGR_CLIENT_STATUS_GET_SIZE},
	{PKGMGR_INSTALLER_CLEAR_CACHE_KEY_STR,
		PKGMGR_CLIENT_STATUS_CLEAR_CACHE},
	{PKGMGR_INSTALLER_APP_ENABLE_EVENT_STR,
		PKGMGR_CLIENT_STATUS_ENABLE_APP},
	{PKGMGR_INSTALLER_APP_DISABLE_EVENT_STR,
		PKGMGR_CLIENT_STATUS_DISABLE_APP},
	{PKGMGR_INSTALLER_APP_ENABLE_SPLASH_SCREEN_EVENT_STR,
		PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN},
	{PKGMGR_INSTALLER_APP_DISABLE_SPLASH_SCREEN_EVENT_STR,
		PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN},
	{NULL, -1}
};

static void __handle_size_info_callback(struct cb_info *cb_info,
		const char *pkgid, const char *val)
{
	pkg_size_info_t size_info;
	char buf[BUFMAX];
	char *saveptr;
	char *token;
	pkgmgr_total_pkg_size_info_receive_cb callback;

	snprintf(buf, sizeof(buf), "%s", val);

	DBG("%s, %s", pkgid, val);

	token = strtok_r(buf, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.data_size = atoll(token);
	token = strtok_r(NULL, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.cache_size = atoll(token);
	token = strtok_r(NULL, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.app_size = atoll(token);
	token = strtok_r(NULL, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.ext_data_size = atoll(token);
	token = strtok_r(NULL, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.ext_cache_size = atoll(token);
	token = strtok_r(NULL, ":", &saveptr);
	if (token == NULL) {
		ERR("failed to parse size info");
		return;
	}
	size_info.ext_app_size = atoll(token);

	DBG("data: %lld, cache: %lld, app: %lld, ext_data: %lld, "
			"ext_cache: %lld, ext_app: %lld",
			size_info.data_size, size_info.cache_size,
			size_info.app_size, size_info.ext_data_size,
			size_info.ext_cache_size, size_info.ext_app_size);

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0) {
		callback = (pkgmgr_total_pkg_size_info_receive_cb)
			cb_info->size_info_cb;
		callback(cb_info->client, &size_info, cb_info->data);
	} else {
		cb_info->size_info_cb(cb_info->client, pkgid, &size_info,
				cb_info->data);
	}
}

static void __convert_signal(char *event_type, char *event_status,
		char *appid, int progress, char **key, char **val)
{
	*key = event_status;
	if (strcmp(event_status, PKGMGR_INSTALLER_START_KEY_STR) == 0) {
		*val = event_type;
	} else if (strcmp(event_status, PKGMGR_INSTALLER_OK_EVENT_STR) == 0 ||
			strcmp(event_status, PKGMGR_INSTALLER_FAIL_EVENT_STR) == 0) {
		*key = PKGMGR_INSTALLER_END_KEY_STR;
		*val = event_status;
	} else if (strcmp(event_status, PKGMGR_INSTALLER_APPID_KEY_STR) == 0) {
		if (!appid) {
			ERR("appid is empty");
			return;
		}
		*val = appid;
	} else if (strcmp(event_type, PKGMGR_INSTALLER_GET_SIZE_KEY_STR) == 0) {
		*key = event_type;
		*val = event_status;
	}
	// TODO: should handle cleardata / clearacache signal
}

static void __signal_handler(GDBusConnection *conn, const gchar *sender_name,
		const gchar *object_path, const gchar *interface_name,
		const gchar *signal_name, GVariant *parameters,
		gpointer user_data)
{
	int progress = 0;
	uid_t target_uid;
	char buf[BUFMAX];
	char *req_id;
	char *pkg_type = NULL;
	char *appid = NULL;
	char *pkgid = NULL;
	char *event_type = NULL;
	char *event_status = NULL;
	char *key = NULL;
	char *val = NULL;
	struct cb_info *cb_info = (struct cb_info *)user_data;
	GVariantIter *iter = NULL;

	g_variant_get(parameters, "(u&sa(sss)&s&si)", &target_uid, &req_id, &iter,
			&event_type, &event_status, &progress);
	while (g_variant_iter_loop(iter, "(&s&s&s)", &pkgid, &appid, &pkg_type)) {
		if (cb_info->req_key) {
			if (strcmp(cb_info->req_key, req_id) != 0)
				continue;
		}

		/* convert event_type and event_status into key-val pair */
		__convert_signal(event_type, event_status, appid,
				progress, &key, &val);
		if (strcmp(event_status,
					PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0 ||
				strcmp(event_status, PKGMGR_INSTALLER_ERROR_KEY_STR) == 0) {
			snprintf(buf, BUFMAX - 1, "%d", progress);
			val = buf;
		}
		/* TODO: progress should be set properly when installation has
		 * completed or failed */

		if (cb_info->event_cb) {
			cb_info->event_cb(target_uid, cb_info->req_id,
					pkg_type, pkgid, key, val, NULL, cb_info->data);
		} else if (cb_info->app_event_cb && strcmp(appid, "") != 0) {
			cb_info->app_event_cb(target_uid, cb_info->req_id,
					pkg_type, pkgid, appid, key, val, NULL,
					cb_info->data);
		} else if (cb_info->size_info_cb)
			__handle_size_info_callback(cb_info, pkgid, val);

		/* TODO: unsubscribe request callback */
	}
}

int pkgmgr_client_connection_set_callback(struct pkgmgr_client_t *pc,
		struct cb_info *cb_info)
{
	cb_info->sid = g_dbus_connection_signal_subscribe(pc->conn, NULL,
			PKGMGR_INSTALLER_DBUS_INTERFACE, NULL,
			PKGMGR_INSTALLER_DBUS_OBJECT_PATH, NULL,
			G_DBUS_SIGNAL_FLAGS_NONE, __signal_handler,
			(gpointer)cb_info, NULL);
	if (!cb_info->sid) {
		ERR("failed to subscribe singal");
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}

void pkgmgr_client_connection_unset_callback(struct pkgmgr_client_t *pc,
		struct cb_info *cb_info)
{
	g_dbus_connection_signal_unsubscribe(pc->conn, cb_info->sid);
}

int pkgmgr_client_connection_send_request(struct pkgmgr_client_t *pc,
		const char *method, GVariant *params, GVariant **result)
{
	GError *error = NULL;
	GDBusProxy *proxy;
	GVariant *r = NULL;
	int retry_cnt = 0;
	int ret = PKGMGR_R_ECOMM;

	/* convert floating ref into normal ref */
	g_variant_ref_sink(params);

	do {
		proxy = g_dbus_proxy_new_sync(pc->conn,
				G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
				NULL, PKGMGR_DBUS_SERVICE,
				PKGMGR_DBUS_OBJECT_PATH,
				PKGMGR_DBUS_INTERFACE, NULL, &error);
		if (proxy == NULL) {
			ERR("failed to get proxy object, sleep and retry[%s]",
					error->message);
			g_error_free(error);
			error = NULL;
			usleep(CONNECTION_WAIT_USEC);
			retry_cnt++;
			continue;
		}

		r = g_dbus_proxy_call_sync(proxy, method, params,
				G_DBUS_CALL_FLAGS_NONE,
				CONNECTION_TIMEOUT_MSEC, NULL, &error);
		g_object_unref(proxy);
		if (error && error->code == G_DBUS_ERROR_ACCESS_DENIED) {
			ERR("failed to send request, privilege denied[%s]",
					error->message);
			g_error_free(error);
			ret = PKGMGR_R_EPRIV;
			break;
		}
		if (r) {
			*result = r;
			ret = PKGMGR_R_OK;
			break;
		}

		ERR("failed to send request, sleep and retry[%s]",
				error->message);
		g_error_free(error);
		error = NULL;
		usleep(CONNECTION_WAIT_USEC);
		retry_cnt++;
	} while (retry_cnt <= CONNECTION_RETRY_MAX);

	/* decrease ref count to 0 to free resource */
	g_variant_unref(params);

	return ret;
}
