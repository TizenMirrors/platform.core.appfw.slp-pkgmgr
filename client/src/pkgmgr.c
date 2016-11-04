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
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <glib.h>

#include <pkgmgr-info.h>
#include <iniparser.h>
/* For multi-user support */
#include <tzplatform_config.h>

#include "package-manager.h"
#include "pkgmgr_client_debug.h"
#include "pkgmgr_client_internal.h"

/* API export macro */
#ifndef API
#define API __attribute__ ((visibility("default")))
#endif

#define PKG_TMP_PATH tzplatform_mkpath(TZ_USER_APP, "tmp")

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define REGULAR_USER 5000

static inline uid_t _getuid(void)
{
	uid_t uid = getuid();

	if (uid < REGULAR_USER)
		return GLOBAL_USER;
	else
		return uid;
}

static int _get_request_id()
{
	static int internal_req_id = 1;

	return internal_req_id++;
}

static struct cb_info *__create_event_cb_info(struct pkgmgr_client_t *client,
		pkgmgr_handler event_cb, void *data, const char *req_key)
{
	struct cb_info *cb_info;

	cb_info = calloc(1, sizeof(struct cb_info));
	if (cb_info == NULL) {
		ERR("out of memory");
		return NULL;
	}
	cb_info->client = client;
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->req_id = _get_request_id();
	if (req_key != NULL) {
		cb_info->req_key = strdup(req_key);
		if (cb_info->req_key == NULL) {
			ERR("out of memory");
			free(cb_info);
			return NULL;
		}
	}

	return cb_info;
}

static struct cb_info *__create_app_event_cb_info(
		struct pkgmgr_client_t *client, pkgmgr_app_handler app_event_cb,
		void *data, const char *req_key)
{
	struct cb_info *cb_info;

	cb_info = calloc(1, sizeof(struct cb_info));
	if (cb_info == NULL) {
		ERR("out of memory");
		return NULL;
	}
	cb_info->client = client;
	cb_info->app_event_cb = app_event_cb;
	cb_info->data = data;
	cb_info->req_id = _get_request_id();
	if (req_key != NULL) {
		cb_info->req_key = strdup(req_key);
		if (cb_info->req_key == NULL) {
			ERR("out of memory");
			free(cb_info);
			return NULL;
		}
	}

	return cb_info;
}

static struct cb_info *__create_size_info_cb_info(
		struct pkgmgr_client_t *client,
		pkgmgr_pkg_size_info_receive_cb size_info_cb,
		void *data, const char *req_key)
{
	struct cb_info *cb_info;

	cb_info = calloc(1, sizeof(struct cb_info));
	if (cb_info == NULL) {
		ERR("out of memory");
		return NULL;
	}
	cb_info->client = client;
	cb_info->size_info_cb = size_info_cb;
	cb_info->data = data;
	cb_info->req_id = _get_request_id();
	if (req_key != NULL) {
		cb_info->req_key = strdup(req_key);
		if (cb_info->req_key == NULL) {
			ERR("out of memory");
			free(cb_info);
			return NULL;
		}
	}

	return cb_info;
}

static void __free_cb_info(struct cb_info *cb_info)
{
	free(cb_info->req_key);
	free(cb_info);
}

static int __sync_process(const char *req_key)
{
	int ret;
	char info_file[PKG_STRING_LEN_MAX] = {'\0', };
	int result = -1;
	int check_cnt = 0;
	FILE *fp;
	char buf[PKG_STRING_LEN_MAX] = {0, };

	snprintf(info_file, PKG_STRING_LEN_MAX, "%s/%s", PKG_SIZE_INFO_PATH, req_key);
	while (1) {
		check_cnt++;

		if (access(info_file, F_OK) == 0) {
			fp = fopen(info_file, "r");
			if (fp == NULL) {
				DBG("file is not generated yet.... wait\n");
				usleep(100 * 1000);	/* 100ms sleep*/
				continue;
			}

			if (fgets(buf, PKG_STRING_LEN_MAX, fp) == NULL) {
				ERR("failed to read info file");
				fclose(fp);
				break;
			}
			fclose(fp);

			DBG("info_file file is generated, result = %s. \n", buf);
			result = atoi(buf);
			break;
		}

		DBG("file is not generated yet.... wait\n");
		usleep(100 * 1000);	/* 100ms sleep*/

		if (check_cnt > 6000) {	/* 60s * 10 time over*/
			ERR("wait time over!!\n");
			break;
		}
	}

	ret = remove(info_file);
	if (ret < 0)
		ERR("file is can not remove[%s, %d]\n", info_file, ret);

	return result;
}

static int __get_size_process(pkgmgr_client *pc, const char *pkgid, uid_t uid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "getsize",
			g_variant_new("(usi)", uid, pkgid, get_type), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	ret = __sync_process(req_key);
	if (ret < 0)
		ERR("get size failed, ret=%d\n", ret);

	g_variant_unref(result);

	return ret;
}

static int __move_pkg_process(pkgmgr_client *pc, const char *pkgid,
		const char *pkg_type, uid_t uid, pkgmgr_move_type move_type,
		pkgmgr_handler event_cb, void *data)
{
	int ret;

	ret = pkgmgr_client_usr_move(pc, pkg_type, pkgid, move_type, event_cb, data, uid);
	if (ret < 0) {
		ERR("move request failed");
		return ret;
	}

	return ret;
}

static int __check_app_process(pkgmgr_request_service_type service_type,
		pkgmgr_client *pc, const char *pkgid, uid_t uid, void *data)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgrinfo_pkginfo_h handle;
	int pid = -1;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	retvm_if(client->pc_type != PC_REQUEST, PKGMGR_R_EINVAL, "client->pc_type is not PC_REQUEST\n");

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo failed");

	if (service_type == PM_REQUEST_KILL_APP)
		ret = pkgmgr_client_connection_send_request(client, "kill",
				g_variant_new("(us)", uid, pkgid), &result);
	else if (service_type == PM_REQUEST_CHECK_APP)
		ret = pkgmgr_client_connection_send_request(client, "check",
				g_variant_new("(us)", uid, pkgid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(ii)", &ret, &pid);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed, ret=%d", ret);
		return ret;
	}

	*(int *)data = pid;

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;

}

static int __request_size_info(pkgmgr_client *pc, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
//	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "getsize",
			g_variant_new("(usi)", uid, "size_info",
				PM_GET_SIZE_INFO), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

/*
	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
*/

	g_variant_unref(result);

	return ret;
}

API pkgmgr_client *pkgmgr_client_new(pkgmgr_client_type pc_type)
{
	struct pkgmgr_client_t *client;

	if (pc_type == PC_BROADCAST) {
		ERR("broadcast type is not supported");
		return NULL;
	}

	if (pc_type != PC_REQUEST && pc_type != PC_LISTENING) {
		ERR("invalid parameter");
		return NULL;
	}

	client = calloc(1, sizeof(struct pkgmgr_client_t));
	if (client == NULL) {
		ERR("out of memory");
		return NULL;
	}

	client->pc_type = pc_type;
	client->status_type = PKGMGR_CLIENT_STATUS_ALL;

	if (pkgmgr_client_connection_connect(client))
		return NULL;

	return (pkgmgr_client *)client;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid argument");
		return PKGMGR_R_EINVAL;
	}

	pkgmgr_client_remove_listen_status(client);
	pkgmgr_client_connection_disconnect(client);
	if (client->tep_path)
		free(client->tep_path);
	free(client);

	return PKGMGR_R_OK;
}

static char *__get_type_from_path(const char *pkg_path)
{
	int ret;
	char mimetype[255] = { '\0', };
	char extlist[256] = { '\0', };
	char *pkg_type;

	ret = _get_mime_from_file(pkg_path, mimetype, sizeof(mimetype));
	if (ret) {
		ERR("_get_mime_from_file() failed - error code[%d]\n", ret);
		return NULL;
	}

	ret = _get_mime_extension(mimetype, extlist, sizeof(extlist));
	if (ret) {
		ERR("_get_mime_extension() failed - error code[%d]\n", ret);
		return NULL;
	}

	if (strlen(extlist) == 0)
		return NULL;

	if (strchr(extlist, ','))
		extlist[strlen(extlist) - strlen(strchr(extlist, ','))] = '\0';

	pkg_type = strchr(extlist, '.') + 1;
	return strdup(pkg_type);
}

API int pkgmgr_client_set_tep_path(pkgmgr_client *pc, const char *tep_path,
		bool tep_move)
{
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *) pc;

	if (pc == NULL || tep_path == NULL) {
		ERR("invalied parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->tep_path)
		free(client->tep_path);

	client->tep_path = strdup(tep_path);
	client->tep_move = tep_move;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_install(pkgmgr_client *pc, const char *pkg_type,
		const char *descriptor_path, const char *pkg_path,
		const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *args = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	char *pkgtype;
	struct cb_info *cb_info;

	if (pc == NULL || pkg_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	if (access(pkg_path, F_OK) != 0) {
		ERR("failed to access: %s", pkg_path);
		return PKGMGR_R_EINVAL;
	}

	if (client->tep_path != NULL && access(client->tep_path, F_OK) != 0) {
		ERR("failed to access: %s", client->tep_path);
		return PKGMGR_R_EINVAL;
	}

	/* TODO: check pkg's type on server-side */
	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	/* build arguments */
	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	if (client->tep_path) {
		g_variant_builder_add(builder, "s", "-e");
		g_variant_builder_add(builder, "s", client->tep_path);
		g_variant_builder_add(builder, "s", "-M");
		/* TODO: revise tep_move */
		g_variant_builder_add(builder, "s",
				client->tep_move ? "tep_move" : "tep_copy");
	}

	args = g_variant_new("as", builder);
	g_variant_builder_unref(builder);

	ret = pkgmgr_client_connection_send_request(client, "install",
			g_variant_new("(uss@as)", uid, pkgtype, pkg_path, args),
			&result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_install(pkgmgr_client *pc, const char *pkg_type,
		const char *descriptor_path, const char *pkg_path,
		const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_install(pc, pkg_type, descriptor_path,
			pkg_path, optional_data, mode, event_cb, data,
			_getuid());
}

API int pkgmgr_client_reinstall(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_reinstall(pc, pkg_type, pkgid, optional_data,
			mode, event_cb, data, _getuid());
}

API int pkgmgr_client_usr_reinstall(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	char *pkgtype;
	pkgmgrinfo_pkginfo_h handle;
	struct cb_info *cb_info;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	if (ret < 0)
		return PKGMGR_R_EINVAL;

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	if (ret < 0) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return PKGMGR_R_ERROR;
	}

	ret = pkgmgr_client_connection_send_request(client, "reinstall",
			g_variant_new("(uss)", uid, pkgtype, pkgid), &result);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_usr_mount_install(pkgmgr_client *pc, const char *pkg_type,
		const char *descriptor_path, const char *pkg_path,
		const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	GVariantBuilder *builder = NULL;
	GVariant *args = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	char *pkgtype;
	struct cb_info *cb_info;

	if (pc == NULL || pkg_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	if (access(pkg_path, F_OK) != 0) {
		ERR("failed to access: %s", pkg_path);
		return PKGMGR_R_EINVAL;
	}

	if (client->tep_path != NULL && access(client->tep_path, F_OK) != 0) {
		ERR("failed to access: %s", client->tep_path);
		return PKGMGR_R_EINVAL;
	}

	/* TODO: check pkg's type on server-side */
	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	/* build arguments */
	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	if (client->tep_path) {
		g_variant_builder_add(builder, "s", "-e");
		g_variant_builder_add(builder, "s", client->tep_path);
		g_variant_builder_add(builder, "s", "-M");
		/* TODO: revise tep_move */
		g_variant_builder_add(builder, "s",
				client->tep_move ? "tep_move" : "tep_copy");
	}

	args = g_variant_new("as", builder);
	g_variant_builder_unref(builder);

	ret = pkgmgr_client_connection_send_request(client, "mount_install",
			g_variant_new("(uss@as)", uid, pkgtype, pkg_path, args),
			&result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_mount_install(pkgmgr_client *pc, const char *pkg_type,
		const char *descriptor_path, const char *pkg_path,
		const char *optional_data, pkgmgr_mode mode,
		pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_mount_install(pc, pkg_type, descriptor_path,
			pkg_path, optional_data, mode, event_cb, data,
			_getuid());
}

API int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, pkgmgr_mode mode, pkgmgr_handler event_cb,
		void *data)
{
	return pkgmgr_client_usr_uninstall(pc, pkg_type, pkgid, mode, event_cb,
			data, _getuid());
}

API int pkgmgr_client_usr_uninstall(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, pkgmgr_mode mode, pkgmgr_handler event_cb,
		void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	char *pkgtype;
	pkgmgrinfo_pkginfo_h handle;
	struct cb_info *cb_info;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	if (ret < 0)
		return PKGMGR_R_EINVAL;

	ret = pkgmgrinfo_pkginfo_get_type(handle, &pkgtype);
	if (ret < 0) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return PKGMGR_R_ERROR;
	}

	ret = pkgmgr_client_connection_send_request(client, "uninstall",
			g_variant_new("(uss)", uid, pkgtype, pkgid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return cb_info->req_id;
}

API int pkgmgr_client_move(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, pkgmgr_move_type move_type,
		pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_move(pc, pkg_type, pkgid, move_type,
			event_cb, data, _getuid());
}
API int pkgmgr_client_usr_move(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, pkgmgr_move_type move_type,
		pkgmgr_handler event_cb, void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || pkg_type == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if ((move_type < PM_MOVE_TO_INTERNAL) ||
			(move_type > PM_MOVE_TO_SDCARD))
		return PKGMGR_R_EINVAL;

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "move",
			g_variant_new("(ussi)", uid, pkg_type, pkgid,
				move_type), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ERROR;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_usr_activate(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	GVariantBuilder *builder;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || pkg_type == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	g_variant_builder_add(builder, "s", pkgid);

	ret = pkgmgr_client_connection_send_request(client, "enable_pkgs",
			g_variant_new("(usas)", uid, pkg_type, builder),
			&result);
	g_variant_builder_unref(builder);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_activate(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid)
{
	return pkgmgr_client_usr_activate(pc, pkg_type, pkgid, _getuid());
}

API int pkgmgr_client_usr_activate_packages(pkgmgr_client *pc,
		const char *pkg_type, const char **pkgids, int n_pkgs,
		uid_t uid)
{
	GVariant *result;
	GVariantBuilder *builder;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	int i;

	if (pc == NULL || pkgids == NULL || pkg_type == NULL || n_pkgs < 1) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	for (i = 0; i < n_pkgs; i++)
		g_variant_builder_add(builder, "s", pkgids[i]);

	ret = pkgmgr_client_connection_send_request(client, "enable_pkgs",
			g_variant_new("(usas)", uid, pkg_type, builder),
			&result);
	g_variant_builder_unref(builder);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_activate_packages(pkgmgr_client *pc,
		const char *pkg_type, const char **pkgids, int n_pkgs)
{
	return pkgmgr_client_usr_activate_packages(pc, pkg_type,
			pkgids, n_pkgs, _getuid());
}

API int pkgmgr_client_usr_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid, uid_t uid)
{
	GVariant *result;
	GVariantBuilder *builder;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || pkg_type == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	g_variant_builder_add(builder, "s", pkgid);

	ret = pkgmgr_client_connection_send_request(client, "disable_pkgs",
			g_variant_new("(usas)", uid, pkg_type, builder),
			&result);
	g_variant_builder_unref(builder);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid)
{
	return pkgmgr_client_usr_deactivate(pc, pkg_type, pkgid, _getuid());
}

API int pkgmgr_client_usr_deactivate_packages(pkgmgr_client *pc,
		const char *pkg_type, const char **pkgids, int n_pkgs,
		uid_t uid)
{
	GVariant *result;
	GVariantBuilder *builder;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	int i;

	if (pc == NULL || pkgids == NULL || pkg_type == NULL || n_pkgs < 1) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	for (i = 0; i < n_pkgs; i++)
		g_variant_builder_add(builder, "s", pkgids[i]);

	ret = pkgmgr_client_connection_send_request(client, "disable_pkgs",
		g_variant_new("(us@as)", uid, pkg_type, builder), &result);
	g_variant_builder_unref(builder);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_deactivate_packages(pkgmgr_client *pc,
		const char *pkg_type, const char **pkgids, int n_pkgs)
{
	return pkgmgr_client_usr_deactivate_packages(pc, pkg_type,
			pkgids, n_pkgs, _getuid());
}

API int pkgmgr_client_usr_activate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "enable_app",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_app_event_cb_info(client, app_event_cb, NULL,
			req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_activate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb)
{
	return pkgmgr_client_usr_activate_app(pc, appid, app_event_cb,
			_getuid());
}

API int pkgmgr_client_activate_global_app_for_uid(pkgmgr_client *pc,
		const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"enable_global_app_for_uid",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_app_event_cb_info(client, app_event_cb, NULL,
			req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_deactivate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "disable_app",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_app_event_cb_info(client, app_event_cb, NULL,
			req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb)
{
	return pkgmgr_client_usr_deactivate_app(pc, appid, app_event_cb,
			_getuid());
}

API int pkgmgr_client_deactivate_global_app_for_uid(pkgmgr_client *pc,
		const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"disable_global_app_for_uid",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_app_event_cb_info(client, app_event_cb, NULL,
			req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_clear_user_data(pkgmgr_client *pc,
		const char *pkg_type, const char *appid, pkgmgr_mode mode,
		uid_t uid)
{
	GVariant *result;
	int ret;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkg_type == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "cleardata",
			g_variant_new("(uss)", uid, pkg_type, appid), &result);
	if (ret == PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
		const char *appid, pkgmgr_mode mode)
{
	return pkgmgr_client_usr_clear_user_data(pc, pkg_type, appid, mode,
			_getuid());
}

API int pkgmgr_client_set_status_type(pkgmgr_client *pc, int status_type)
{
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	client->status_type = status_type;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
		void *data)
{
	int ret;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_LISTENING) {
		ERR("client->pc_type is not PC_LISTENING");
		return PKGMGR_R_EINVAL;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, NULL);
	if (cb_info == NULL)
		return PKGMGR_R_ENOMEM;
	cb_info->status_type = client->status_type;
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_listen_app_status(pkgmgr_client *pc,
		pkgmgr_app_handler app_event_cb, void *data)
{
	int ret;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || app_event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_LISTENING) {
		ERR("client->pc_type is not PC_LISTENING");
		return PKGMGR_R_EINVAL;
	}

	cb_info = __create_app_event_cb_info(client, app_event_cb, data, NULL);
	if (cb_info == NULL)
		return PKGMGR_R_ENOMEM;
	cb_info->status_type = client->status_type;
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return cb_info->req_id;
}

API int pkgmgr_client_remove_listen_status(pkgmgr_client *pc)
{
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	GList *tmp;
	GList *next;
	struct cb_info *cb_info;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	/* unset all callback */
	tmp = client->cb_info_list;
	while (tmp != NULL) {
		next = tmp->next;
		cb_info = (struct cb_info *)tmp->data;
		pkgmgr_client_connection_unset_callback(pc, cb_info);
		client->cb_info_list = g_list_delete_link(client->cb_info_list,
				tmp);
		__free_cb_info(cb_info);
		tmp = next;
	}

	return PKGMGR_R_OK;
}

API int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, const char *key, const char *val)
{
	/* client cannot broadcast signal */
	return PKGMGR_R_OK;
}

/* TODO: deprecate(or remove) */
API int pkgmgr_client_request_service(pkgmgr_request_service_type service_type,
		int service_mode, pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, const char *custom_info,
		pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_request_service(service_type, service_mode,
			pc, pkg_type, pkgid, _getuid(), custom_info, event_cb,
			data);
}

API int pkgmgr_client_usr_request_service(
		pkgmgr_request_service_type service_type, int service_mode,
		pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
		uid_t uid, const char *custom_info, pkgmgr_handler event_cb,
		void *data)
{
	int ret = 0;

	/* Check for NULL value of service type */
	retvm_if(service_type > PM_REQUEST_MAX, PKGMGR_R_EINVAL, "service type is not defined\n");
	retvm_if(service_type < 0, PKGMGR_R_EINVAL, "service type is error\n");

	switch (service_type) {
	case PM_REQUEST_MOVE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_MOVE_TO_INTERNAL) || (service_mode > PM_MOVE_TO_SDCARD), ret = PKGMGR_R_EINVAL, "service_mode is wrong\n");

		ret = __move_pkg_process(pc, pkgid, pkg_type, uid, (pkgmgr_move_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_GET_SIZE:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");
		tryvm_if((service_mode < PM_GET_TOTAL_SIZE) || (service_mode >= PM_GET_MAX), ret = PKGMGR_R_EINVAL, "service_mode is wrong\n");

		ret = __get_size_process(pc, pkgid, uid, (pkgmgr_getsize_type)service_mode, event_cb, data);
		break;

	case PM_REQUEST_KILL_APP:
	case PM_REQUEST_CHECK_APP:
		tryvm_if(pkgid == NULL, ret = PKGMGR_R_EINVAL, "pkgid is NULL\n");
		tryvm_if(pc == NULL, ret = PKGMGR_R_EINVAL, "pc is NULL\n");

		ret = __check_app_process(service_type, pc, pkgid, uid, data);
		if (ret < 0)
			ERR("__check_app_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

	default:
		ERR("Wrong Request\n");
		ret = -1;
		break;
	}

catch:

	return ret;
}


API int pkgmgr_client_usr_request_size_info(uid_t uid)
{
	int ret;
	struct pkgmgr_client *client;

	client = pkgmgr_client_new(PC_REQUEST);
	if (client == NULL) {
		ERR("out of memory");
		return PKGMGR_R_ENOMEM;
	}

	ret = __request_size_info(client, uid);
	if (ret < 0)
		ERR("__request_size_info fail");

	pkgmgr_client_free(client);
	return ret;
}

API int pkgmgr_client_request_size_info(void)
{
	/* get all package size (data, total) */
	return pkgmgr_client_usr_request_size_info(_getuid());
}

API int pkgmgr_client_usr_clear_cache_dir(const char *pkgid, uid_t uid)
{
	GVariant *result;
	int ret;
	struct pkgmgr_client_t *client;

	if (pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	client = pkgmgr_client_new(PC_REQUEST);
	if (client == NULL) {
		ERR("out of memory");
		return PKGMGR_R_ENOMEM;
	}

	ret = pkgmgr_client_connection_send_request(client, "clearcache",
			g_variant_new("(us)", uid, pkgid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_clear_cache_dir(const char *pkgid)
{
	return pkgmgr_client_usr_clear_cache_dir(pkgid, _getuid());
}

API int pkgmgr_client_clear_usr_all_cache_dir(uid_t uid)
{
	return pkgmgr_client_usr_clear_cache_dir(PKG_CLEAR_ALL_CACHE, uid);
}

API int pkgmgr_client_clear_all_cache_dir(void)
{
	return pkgmgr_client_usr_clear_cache_dir(
			PKG_CLEAR_ALL_CACHE, getuid());
}

API int pkgmgr_client_get_size(pkgmgr_client *pc, const char *pkgid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data)
{
	return pkgmgr_client_usr_get_size(pc, pkgid, get_type, event_cb, data,
			_getuid());
}

/* TODO: deprecate(or remove) */
API int pkgmgr_client_usr_get_size(pkgmgr_client *pc, const char *pkgid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || pkgid == NULL || event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	/* FIXME */
	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
		get_type = PM_GET_TOTAL_PKG_SIZE_INFO;
	else
		get_type = PM_GET_PKG_SIZE_INFO;

	ret = pkgmgr_client_connection_send_request(client, "getsize",
			g_variant_new("(usi)", uid, pkgid, get_type), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_event_cb_info(client, event_cb, data, req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_get_package_size_info(pkgmgr_client *pc,
		const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb,
		void *user_data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	int get_type;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;
	struct cb_info *cb_info;

	if (pc == NULL || pkgid == NULL || event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
		get_type = PM_GET_TOTAL_PKG_SIZE_INFO;
	else
		get_type = PM_GET_PKG_SIZE_INFO;

	ret = pkgmgr_client_connection_send_request(client, "getsize",
			g_variant_new("(usi)", uid, pkgid, get_type), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s)", &ret, &req_key);
	if (req_key == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ECOMM;
	}
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	cb_info = __create_size_info_cb_info(client, event_cb, user_data,
			req_key);
	if (cb_info == NULL) {
		g_variant_unref(result);
		return PKGMGR_R_ENOMEM;
	}
	g_variant_unref(result);
	ret = pkgmgr_client_connection_set_callback(client, cb_info);
	if (ret != PKGMGR_R_OK) {
		__free_cb_info(cb_info);
		return ret;
	}
	client->cb_info_list = g_list_append(client->cb_info_list, cb_info);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_get_package_size_info(pkgmgr_client *pc,
		const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb,
		void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, pkgid, event_cb,
			user_data, _getuid());
}

API int pkgmgr_client_usr_get_total_package_size_info(pkgmgr_client *pc,
		pkgmgr_total_pkg_size_info_receive_cb event_cb,
		void *user_data, uid_t uid)
{	/* total package size info */
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL,
			(pkgmgr_pkg_size_info_receive_cb)event_cb,
			user_data, uid);
}

API int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc,
		pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL,
			(pkgmgr_pkg_size_info_receive_cb)event_cb,
			user_data, _getuid());
}

API int pkgmgr_client_generate_license_request(pkgmgr_client *pc,
		const char *resp_data, char **req_data, char **license_url)
{
	GVariant *result;
	int ret;
	char *data;
	char *url;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || resp_data == NULL || req_data == NULL ||
			license_url == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"generate_license_request",
			g_variant_new("(s)", resp_data), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i&s&s)", &ret, &data, &url);
	if (ret != PKGMGR_R_OK) {
		ERR("generate_license_request failed: %d", ret);
		g_variant_unref(result);
		return ret;
	}

	*req_data = strdup(data);
	*license_url = strdup(url);

	g_variant_unref(result);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_register_license(pkgmgr_client *pc, const char *resp_data)
{
	GVariant *result;
	int ret;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || resp_data == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "register_license",
			g_variant_new("(s)", resp_data), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		ERR("register license failed: %d", ret);

	return ret;
}

API int pkgmgr_client_decrypt_package(pkgmgr_client *pc,
		const char *drm_file_path, const char *decrypted_file_path)
{
	GVariant *result;
	int ret;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || drm_file_path == NULL ||
			decrypted_file_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (client->pc_type != PC_REQUEST) {
		ERR("client->pc_type is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client, "decrypt_package",
			g_variant_new("(ss)", drm_file_path,
				decrypted_file_path), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		ERR("decrypt_package failed: %d", ret);

	return ret;
}

API int pkgmgr_client_enable_splash_screen(pkgmgr_client *pc, const char *appid)
{
	return pkgmgr_client_usr_enable_splash_screen(pc, appid, _getuid());
}

API int pkgmgr_client_usr_enable_splash_screen(pkgmgr_client *pc,
		const char *appid, uid_t uid)
{
	int ret;
	GVariant *result;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("Invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"enable_app_splash_screen",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		ERR("enable splash screen failed: %d", ret);

	return ret;
}

API int pkgmgr_client_disable_splash_screen(pkgmgr_client *pc,
		const char *appid)
{
	return pkgmgr_client_usr_disable_splash_screen(pc, appid,
			_getuid());
}

API int pkgmgr_client_usr_disable_splash_screen(pkgmgr_client *pc,
		const char *appid, uid_t uid)
{
	int ret;
	GVariant *result;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("Invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"disable_app_splash_screen",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		ERR("disable splash screen failed: %d", ret);

	return ret;
}

static int __set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid,
		int mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0 || mode <= 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"set_restriction_mode",
			g_variant_new("(usi)", uid, pkgid, mode), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_usr_set_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int mode, uid_t uid)
{
	return __set_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_set_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int mode)
{
	return pkgmgr_client_usr_set_pkg_restriction_mode(pc, pkgid, mode,
			_getuid());
}

static int __unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid,
		int mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0 || mode <= 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"unset_restriction_mode",
			g_variant_new("(usi)", uid, pkgid, mode), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;

}

API int pkgmgr_client_usr_unset_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int mode, uid_t uid)
{
	return __unset_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_unset_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int mode)
{
	return pkgmgr_client_usr_unset_pkg_restriction_mode(pc, pkgid, mode,
			_getuid());
}

static int __get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid,
		int *mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	gint m;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"get_restriction_mode",
			g_variant_new("(us)", uid, pkgid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(ii)", &m, &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		return ret;

	*mode = m;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_get_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int *mode, uid_t uid)
{
	return __get_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_get_pkg_restriction_mode(pkgmgr_client *pc,
		const char *pkgid, int *mode)
{
	return pkgmgr_client_usr_get_pkg_restriction_mode(pc, pkgid, mode,
			_getuid());
}

API int pkgmgr_client_usr_set_restriction_mode(pkgmgr_client *pc, int mode,
		uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"set_restriction_mode",
			g_variant_new("(usi)", uid, "", mode), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_set_restriction_mode(pkgmgr_client *pc, int mode)
{
	return pkgmgr_client_usr_set_restriction_mode(pc, mode, _getuid());
}

API int pkgmgr_client_usr_unset_restriction_mode(pkgmgr_client *pc, int mode,
		uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"unset_restriction_mode",
			g_variant_new("(usi)", uid, "", mode), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_unset_restriction_mode(pkgmgr_client *pc, int mode)
{
	return pkgmgr_client_usr_unset_restriction_mode(pc, mode, _getuid());
}

API int pkgmgr_client_usr_get_restriction_mode(pkgmgr_client *pc,
		int *mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	gint m;
	struct pkgmgr_client_t *client = (struct pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = pkgmgr_client_connection_send_request(client,
			"get_restriction_mode",
			g_variant_new("(us)", uid, ""), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(ii)", &m, &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK)
		return ret;

	*mode = m;

	return PKGMGR_R_OK;
}

API int pkgmgr_client_get_restriction_mode(pkgmgr_client *pc, int *mode)
{
	return pkgmgr_client_usr_get_restriction_mode(pc, mode, _getuid());
}
