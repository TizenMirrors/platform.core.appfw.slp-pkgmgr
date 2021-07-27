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

#ifndef __PKGMGR_CLIENT_INTERNAL_H__
#define __PKGMGR_CLIENT_INTERNAL_H__

#include <unistd.h>
#include <ctype.h>

#include <glib.h>
#include <gio/gio.h>

#include "package-manager-plugin.h"
#include "package-manager.h"

#define BUFMAX 4096

struct cb_info {
	int req_id;
	char *req_key;
	int status_type;
	pkgmgr_handler event_cb;
	pkgmgr_app_handler app_event_cb;
	pkgmgr_pkg_size_info_receive_cb size_info_cb;
	pkgmgr_res_request_cb res_request_cb;
	void *data;
	struct pkgmgr_client_t *client;
	GList *sid_list;
};

struct pkgmgr_client_t {
	pkgmgr_client_type pc_type;
	int status_type;
	GDBusConnection *conn;
	GList *cb_info_list;
	GVariantBuilder *res_copy_builder;
	GVariantBuilder *res_remove_builder;
	char *tep_path;
	bool tep_move;
	bool debug_mode;
	bool skip_optimization;
};

struct manifest_and_type {
	const char *manifest;
	const char *type;
};

int pkgmgr_client_connection_connect(struct pkgmgr_client_t *pc);
void pkgmgr_client_connection_disconnect(struct pkgmgr_client_t *pc);
int pkgmgr_client_connection_set_callback(struct pkgmgr_client_t *pc,
		struct cb_info *cb_info);
void pkgmgr_client_connection_unset_callback(struct pkgmgr_client_t *pc,
		struct cb_info *cb_info);
int pkgmgr_client_connection_send_request(struct pkgmgr_client_t *pc,
		const char *method, GVariant *params, GVariant **result);


typedef package_manager_pkg_info_t package_manager_app_info_t;


package_manager_pkg_info_t *_pkg_malloc_appinfo(int num);

pkg_plugin_set *_pkg_plugin_load_library(const char *pkg_type,
					 const char *library_path);

int _pkg_plugin_get_library_path(const char *pkg_type, char *library_path);

pkg_plugin_set *_package_manager_load_library(const char *pkg_type);

char *_get_info_string(const char *key,
		       const package_manager_pkg_detail_info_t *
		       pkg_detail_info);

int _get_info_int(const char *key,
		  const package_manager_pkg_detail_info_t *pkg_detail_info);

time_t _get_info_time(const char *key,
		      const package_manager_pkg_detail_info_t *
		      pkg_detail_info);


#define PKG_FRONTEND	"frontend:"
#define PKG_BACKEND		"backend:"
#define PKG_BACKENDLIB	"backendlib:"
#define PKG_PARSERLIB	"parserlib:"
#define PKG_CONF_PATH	"/etc/package-manager/pkg_path.conf"

#define PKG_STATUS		"STATUS"

#define PKG_STRING_LEN_MAX 1024
#define PKG_EXT_LEN_MAX		 20
#define PKG_ARGC_MAX		 16

void _app_str_trim(char *input);

int _get_mime_from_file(const char *filename, char *mimetype, int len);
int _get_mime_extension(const char *mimetype, char *ext, int len);

#endif				/* __PKGMGR_CLIENT_INTERNAL_H__ */
