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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#include "comm_client.h"
#include "pkgmgr-debug.h"
#include "package-manager.h"
#include "../../installer/pkgmgr_installer.h"
#include "../../installer/pkgmgr_installer_config.h"

#define COMM_CLIENT_RETRY_MAX 5
#define COMM_CLIENT_WAIT_USEC (1000000 / 2) /* 0.5 sec */

/*******************
 * ADT description
 */

/* Storing status_cb */
struct signal_callback_data {
	int type;
	status_cb cb;
	void *cb_data;
};

/* comm_client ADT */
struct comm_client {
	guint subscription_id;
	GDBusConnection *conn;
	struct signal_callback_data *sig_cb_data;
};

static int __get_signal_type(const char *name)
{
	if (name == NULL)
		return -1;

	if (strcmp(name, PKGMGR_INSTALLER_INSTALL_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_INSTALL;
	else if (strcmp(name, PKGMGR_INSTALLER_UNINSTALL_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_UNINSTALL;
	else if (strcmp(name, PKGMGR_INSTALLER_CLEAR_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_CLEAR_DATA;
	else if (strcmp(name, PKGMGR_INSTALLER_MOVE_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_MOVE;
	else if (strcmp(name, PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR) == 0)
		return PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS;
	else if (strcmp(name, PKGMGR_INSTALLER_UPGRADE_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_UPGRADE;
	else if (strcmp(name, PKGMGR_INSTALLER_GET_SIZE_KEY_STR) == 0)
		return PKGMGR_CLIENT_STATUS_GET_SIZE;
	else if (strcmp(name, PKGMGR_INSTALLER_APP_ENABLE_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_ENABLE_APP;
	else if (strcmp(name, PKGMGR_INSTALLER_APP_DISABLE_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_DISABLE_APP;
	else if (strcmp(name, PKGMGR_INSTALLER_APP_ENABLE_SPLASH_SCREEN_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN;
	else if (strcmp(name, PKGMGR_INSTALLER_APP_DISABLE_SPLASH_SCREEN_EVENT_STR) == 0)
		return PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN;
	else
		return -1;
}

/**
 * signal handler filter
 * Filter signal, and run user callback
 */
void _on_signal_handle_filter(GDBusConnection *conn,
		const gchar *sender_name,
		const gchar *object_path,
		const gchar *interface_name,
		const gchar *signal_name,
		GVariant *parameters,
		gpointer user_data)
{
	if (interface_name && strcmp(interface_name, PKGMGR_INSTALLER_DBUS_INTERFACE)) {
		DBG("Interface name did not match. Drop the message");
		return;
	}

	int status_type;
	/* Values to be received by signal */
	uid_t target_uid;
	char *req_id;
	char *pkg_type = NULL;
	char *pkgid = NULL;
	char *key = NULL;
	char *val = NULL;
	char *appid = NULL;

	/* User's signal handler */
	struct signal_callback_data *sig_cb_data;
	if (user_data)
		sig_cb_data = (struct signal_callback_data *)user_data;
	else
		return;

	status_type = __get_signal_type(signal_name);
	if (status_type < 0 || !(status_type & sig_cb_data->type))
		return;

	g_variant_get(parameters, "(u&s&s&s&s&s&s)",
				&target_uid, &req_id, &pkg_type, &pkgid, &appid, &key, &val);

	/* Run signal callback if exist */
	if (sig_cb_data && sig_cb_data->cb)
		sig_cb_data->cb(sig_cb_data->cb_data, target_uid, req_id,
				pkg_type, pkgid, appid, key, val);

	return;
}

/**
 * signal_callback_data free function
 * Just free it!
 */
void _free_sig_cb_data(void *data)
{
	struct signal_callback_data *sig_cb_data = NULL;
	sig_cb_data = (struct signal_callback_data *)data;
	free(sig_cb_data);
}

#define REGULAR_USER 5000
static int _is_system_user(void)
{
	uid_t uid = getuid();

	if (uid < REGULAR_USER)
		return 1;
	else
		return 0;
}

static GBusType _get_bus_type(client_type type)
{
	if (type == PC_REQUEST || _is_system_user())
		return G_BUS_TYPE_SYSTEM;
	else
		return G_BUS_TYPE_SESSION;
}

/*******************
 * API description
 */

/**
 * Create a new comm_client object
 */
comm_client *comm_client_new(client_type type)
{
	GError *error = NULL;
	comm_client *cc = NULL;

	/* Allocate memory for ADT:comm_client */
#if !GLIB_CHECK_VERSION(2, 35, 0)
	g_type_init();
#endif
	cc = calloc(1, sizeof(comm_client));
	if (NULL == cc) {
		ERR("No memory");
		return NULL;
	}

	/* Connect to gdbus. Gets shared BUS */
	cc->conn = g_bus_get_sync(_get_bus_type(type), NULL, &error);
	if (error) {
		ERR("gdbus connection error (%s)", error->message);
		g_error_free(error);
		goto ERROR_CLEANUP;
	}
	if (NULL == cc->conn) {
		ERR("gdbus connection is not set, even gdbus error isn't raised");
		goto ERROR_CLEANUP;
	}
	return cc;

 ERROR_CLEANUP:
	if (cc)
		free(cc);
	return NULL;
}

/**
 * Free comm_client object
 */
int comm_client_free(comm_client *cc)
{
	if (!cc)
		return -1;
	if (!(cc->conn) || g_dbus_connection_is_closed(cc->conn)) {
		ERR("Invalid gdbus connection");
		return -2;
	}

	if (cc->sig_cb_data) {
		g_dbus_connection_signal_unsubscribe(cc->conn, cc->subscription_id);
		/* TODO: Is it needed to free cc->sig_cb_data here? */
		/* _free_sig_cb_data(cc->sig_cb_data); */
	}

	/* Cleanup ADT */
	/* flush remaining buffer: blocking mode */
	g_dbus_connection_flush_sync(cc->conn, NULL, NULL);

	/* Free signal filter if signal callback is exist */

	/* just unref because it is shared BUS.
	If ref count is 0 it will get free'd automatically
	*/
	g_object_unref(cc->conn);
	free(cc);

	return 0;
}

/**
 * Request a message
 */
int comm_client_request(comm_client *cc, const char *method, GVariant *params,
		GVariant **result)
{
	GError *error = NULL;
	GDBusProxy *proxy;
	GVariant *r = NULL;
	int retry_cnt = 0;
	int ret = PKGMGR_R_ECOMM;

	/* convert floating ref into normal ref */
	g_variant_ref_sink(params);

	do {
		proxy = g_dbus_proxy_new_sync(cc->conn, G_DBUS_PROXY_FLAGS_NONE,
				NULL, PKGMGR_DBUS_SERVICE,
				PKGMGR_DBUS_OBJECT_PATH,
				PKGMGR_DBUS_INTERFACE, NULL, &error);
		if (proxy == NULL) {
			ERR("failed to get proxy object, sleep and retry[%s]",
					error->message);
			g_error_free(error);
			error = NULL;
			usleep(COMM_CLIENT_WAIT_USEC);
			retry_cnt++;
			continue;
		}

		r = g_dbus_proxy_call_sync(proxy, method, params,
				G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
		g_object_unref(proxy);
		if (error && error->code == G_DBUS_ERROR_ACCESS_DENIED) {
			ERR("failed to send request, privilege denied[%s]",
					error->message);
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
		usleep(COMM_CLIENT_WAIT_USEC);
		retry_cnt++;
	} while (retry_cnt <= COMM_CLIENT_RETRY_MAX);

	/* decrease ref count to 0 to free resource */
	g_variant_unref(params);

	return ret;
}

/**
 * Set a callback for status signal
 */
int
comm_client_set_status_callback(int comm_status_type, comm_client *cc, status_cb cb, void *cb_data)
{
	int r = PKGMGR_R_OK;

	if (cc == NULL)
		return PKGMGR_R_ERROR;

	/* Create new sig_cb_data */
	cc->sig_cb_data = calloc(1, sizeof(struct signal_callback_data));
	if (cc->sig_cb_data) {
		(cc->sig_cb_data)->type = comm_status_type;
		(cc->sig_cb_data)->cb = cb;
		(cc->sig_cb_data)->cb_data = cb_data;
	} else {
		r = PKGMGR_R_ERROR;
		goto ERROR_CLEANUP;
	}
	/* Add a filter for signal */
	cc->subscription_id = g_dbus_connection_signal_subscribe(cc->conn, NULL,
			PKGMGR_INSTALLER_DBUS_INTERFACE, NULL,
			PKGMGR_INSTALLER_DBUS_OBJECT_PATH, NULL,
			G_DBUS_SIGNAL_FLAGS_NONE, _on_signal_handle_filter,
			(gpointer)cc->sig_cb_data, _free_sig_cb_data);
	if (!cc->subscription_id) {
		ERR("Failed to add filter\n");
		r = PKGMGR_R_ERROR;
		goto ERROR_CLEANUP;
	}

	return PKGMGR_R_OK;

ERROR_CLEANUP:
	ERR("General error");
	return r;
}

