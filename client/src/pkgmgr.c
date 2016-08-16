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
#include "pkgmgr-internal.h"
#include "pkgmgr-debug.h"
#include "comm_client.h"
#include "comm_config.h"

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

typedef struct _req_cb_info {
	int request_id;
	char *req_key;
	pkgmgr_handler event_cb;
	pkgmgr_app_handler app_event_cb;
	void *data;
	struct _req_cb_info *next;
} req_cb_info;

typedef struct _listen_cb_info {
	int request_id;
	pkgmgr_handler event_cb;
	pkgmgr_app_handler app_event_cb;
	void *data;
	struct _listen_cb_info *next;
} listen_cb_info;

typedef struct _pkgmgr_client_t {
	client_type ctype;
	int status_type;
	union {
		struct _request {
			comm_client *cc;
			req_cb_info *rhead;
		} request;
		struct _listening {
			comm_client *cc;
			listen_cb_info *lhead;
		} listening;
	} info;
	void *new_event_cb;
	char *tep_path;
	bool tep_move;
} pkgmgr_client_t;

typedef struct _iter_data {
	pkgmgr_iter_fn iter_fn;
	void *data;
} iter_data;

static int __xsystem(const char *argv[])
{
	int status = 0;
	pid_t pid;
	pid = fork();
	switch (pid) {
	case -1:
		perror("fork failed");
		return -1;
	case 0:
		/* child */
		execvp(argv[0], (char *const *)argv);
		_exit(-1);
	default:
		/* parent */
		break;
	}
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid failed");
		return -1;
	}
	if (WIFSIGNALED(status)) {
		perror("signal");
		return -1;
	}
	if (!WIFEXITED(status)) {
		/* shouldn't happen */
		perror("should not happen");
		return -1;
	}
	return WEXITSTATUS(status);
}

static void __error_to_string(int errnumber, char **errstr)
{
	if (errstr == NULL)
		return;
	switch (errnumber) {
	case PKGCMD_ERR_PACKAGE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_PACKAGE_INVALID:
		*errstr = PKGCMD_ERR_PACKAGE_INVALID_STR;
		break;
	case PKGCMD_ERR_PACKAGE_LOWER_VERSION:
		*errstr = PKGCMD_ERR_PACKAGE_LOWER_VERSION_STR;
		break;
	case PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND:
		*errstr = PKGCMD_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_MANIFEST_INVALID:
		*errstr = PKGCMD_ERR_MANIFEST_INVALID_STR;
		break;
	case PKGCMD_ERR_CONFIG_NOT_FOUND:
		*errstr = PKGCMD_ERR_CONFIG_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CONFIG_INVALID:
		*errstr = PKGCMD_ERR_CONFIG_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_NOT_FOUND:
		*errstr = PKGCMD_ERR_SIGNATURE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_INVALID:
		*errstr = PKGCMD_ERR_SIGNATURE_INVALID_STR;
		break;
	case PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_SIGNATURE_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND:
		*errstr = PKGCMD_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_INVALID:
		*errstr = PKGCMD_ERR_CERTIFICATE_INVALID_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED:
		*errstr = PKGCMD_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR;
		break;
	case PKGCMD_ERR_CERTIFICATE_EXPIRED:
		*errstr = PKGCMD_ERR_CERTIFICATE_EXPIRED_STR;
		break;
	case PKGCMD_ERR_INVALID_PRIVILEGE:
		*errstr = PKGCMD_ERR_INVALID_PRIVILEGE_STR;
		break;
	case PKGCMD_ERR_MENU_ICON_NOT_FOUND:
		*errstr = PKGCMD_ERR_MENU_ICON_NOT_FOUND_STR;
		break;
	case PKGCMD_ERR_FATAL_ERROR:
		*errstr = PKGCMD_ERR_FATAL_ERROR_STR;
		break;
	case PKGCMD_ERR_OUT_OF_STORAGE:
		*errstr = PKGCMD_ERR_OUT_OF_STORAGE_STR;
		break;
	case PKGCMD_ERR_OUT_OF_MEMORY:
		*errstr = PKGCMD_ERR_OUT_OF_MEMORY_STR;
		break;
	case PKGCMD_ERR_ARGUMENT_INVALID:
		*errstr = PKGCMD_ERR_ARGUMENT_INVALID_STR;
		break;
	default:
		*errstr = PKGCMD_ERR_UNKNOWN_STR;
		break;
	}
}

static void __add_op_cbinfo(pkgmgr_client_t *pc, int request_id,
			    const char *req_key, pkgmgr_handler event_cb, void *new_event_cb,
			    void *data)
{
	req_cb_info *cb_info;
	req_cb_info *current;
	req_cb_info *prev;

	cb_info = (req_cb_info *) calloc(1, sizeof(req_cb_info));
	if (cb_info == NULL) {
		DBG("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->req_key = strdup(req_key);
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;
	cb_info->app_event_cb = NULL;
	pc->new_event_cb = new_event_cb;

	if (pc->info.request.rhead == NULL)
		pc->info.request.rhead = cb_info;
	else {
		current = prev = pc->info.request.rhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __add_op_app_cbinfo(pkgmgr_client_t *pc, int request_id,
			    const char *req_key, pkgmgr_app_handler app_event_cb, void *data)
{
	req_cb_info *cb_info;
	req_cb_info *current;
	req_cb_info *prev;

	cb_info = (req_cb_info *) calloc(1, sizeof(req_cb_info));
	if (cb_info == NULL) {
		DBG("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->req_key = strdup(req_key);
	cb_info->event_cb = NULL;
	cb_info->app_event_cb = app_event_cb;
	cb_info->data = data;
	cb_info->next = NULL;
	pc->new_event_cb = NULL;

	if (pc->info.request.rhead == NULL)
		pc->info.request.rhead = cb_info;
	else {
		current = prev = pc->info.request.rhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static req_cb_info *__find_op_cbinfo(pkgmgr_client_t *pc, const char *req_key)
{
	req_cb_info *tmp;

	tmp = pc->info.request.rhead;

	if (tmp == NULL) {
		ERR("tmp is NULL");
		return NULL;
	}

	DBG("tmp->req_key %s, req_key %s", tmp->req_key, req_key);

	while (tmp) {
		if (strncmp(tmp->req_key, req_key, strlen(tmp->req_key)) == 0)
			return tmp;
		tmp = tmp->next;
	}
	return NULL;
}

static int __remove_stat_cbinfo(pkgmgr_client_t *pc)
{
	listen_cb_info *info = pc->info.listening.lhead;
	listen_cb_info *next = NULL;

	while (info != NULL) {
		next = info->next;
		free(info);
		info = next;
	}

	pc->info.listening.lhead = NULL;
	return 0;
}

static void __add_app_stat_cbinfo(pkgmgr_client_t *pc, int request_id,
			      pkgmgr_app_handler event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		DBG("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->app_event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __add_stat_cbinfo(pkgmgr_client_t *pc, int request_id,
			      pkgmgr_handler event_cb, void *data)
{
	listen_cb_info *cb_info;
	listen_cb_info *current;
	listen_cb_info *prev;

	cb_info = (listen_cb_info *) calloc(1, sizeof(listen_cb_info));
	if (cb_info == NULL) {
		DBG("calloc failed");
		return;
	}
	cb_info->request_id = request_id;
	cb_info->event_cb = event_cb;
	cb_info->data = data;
	cb_info->next = NULL;

	/* TODO - check the order of callback - FIFO or LIFO => Should be changed to LIFO */
	if (pc->info.listening.lhead == NULL)
		pc->info.listening.lhead = cb_info;
	else {
		current = prev = pc->info.listening.lhead;
		while (current) {
			prev = current;
			current = current->next;
		}

		prev->next = cb_info;
	}
}

static void __operation_callback(void *cb_data, uid_t target_uid,
				 const char *req_id, const char *pkg_type,
				 const char *pkgid,  const char *appid,
				 const char *key,    const char *val)
{
	pkgmgr_client_t *pc;
	req_cb_info *cb_info;

	pc = (pkgmgr_client_t *) cb_data;

	/* find callback info */
	cb_info = __find_op_cbinfo(pc, req_id);
	if (cb_info == NULL) {
		ERR("cannot find cb_info for req_id:%s", req_id);
		return;
	}

	/* call callback */
	if (appid != NULL && strlen(appid) != 0 && cb_info->app_event_cb) {
		/* run app callback */
		if (pc->new_event_cb)
			cb_info->app_event_cb(target_uid, cb_info->request_id,
					pkg_type, pkgid, appid, key, val, pc,
					cb_info->data);
		else
			cb_info->app_event_cb(target_uid, cb_info->request_id,
					pkg_type, pkgid, appid, key, val, NULL,
					cb_info->data);
	} else if (cb_info->event_cb) {
		/* run pkg callback */
		if (pc->new_event_cb)
			cb_info->event_cb(target_uid, cb_info->request_id,
					pkg_type, pkgid, key, val, pc,
					cb_info->data);
		else
			cb_info->event_cb(target_uid, cb_info->request_id,
					pkg_type, pkgid, key, val, NULL,
					cb_info->data);
	}

	return;
}

static void __status_callback(void *cb_data, uid_t target_uid,
			      const char *req_id, const char *pkg_type,
			      const char *pkgid,  const char *appid,
			      const char *key,    const char *val)
{
	pkgmgr_client_t *pc;
	listen_cb_info *tmp;

	pc = (pkgmgr_client_t *) cb_data;

	tmp = pc->info.listening.lhead;
	while (tmp) {
		if (appid != NULL && strlen(appid) != 0) {
			/* run app callback */
			if (tmp->app_event_cb && tmp->app_event_cb(
					target_uid, tmp->request_id, pkg_type, pkgid,
					appid, key, val, NULL, tmp->data) != 0)
				break;
		} else {
			/* run pkg callback */
			if (tmp->event_cb && tmp->event_cb(
				target_uid, tmp->request_id, pkg_type, pkgid,
				key, val, NULL, tmp->data) != 0)
				break;
		}
		tmp = tmp->next;
	}

	return;
}

static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd = 0;
	int ret = 0;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

char *__proc_get_cmdline_bypid(int pid)
{
	char buf[PKG_STRING_LEN_MAX] = {'\0', };
	int ret = 0;

	snprintf(buf, sizeof(buf), "/proc/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* support app launched by shell script*/
	if (strncmp(buf, BINSH_NAME, BINSH_SIZE) == 0)
		return strdup(&buf[BINSH_SIZE + 1]);
	else
		return strdup(buf);
}

static inline int __pkgmgr_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
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

static int __csc_process(const char *csc_path, char *result_path)
{
	int ret = 0;
	int cnt = 0;
	int count = 0;
	int csc_fail = 0;
	int fd = 0;
	char *pkgtype = NULL;
	char *des = NULL;
	char buf[PKG_STRING_LEN_MAX] = {0,};
	char type_buf[1024] = { 0 };
	char des_buf[1024] = { 0 };
	dictionary *csc = NULL;
	FILE *file = NULL;

	csc = iniparser_load(csc_path);
	retvm_if(csc == NULL, PKGMGR_R_EINVAL, "cannot open parse file [%s]", csc_path);

	file = fopen(result_path, "w");
	tryvm_if(file == NULL, ret = PKGMGR_R_EINVAL, "cannot open result file [%s]", result_path);

	count = iniparser_getint(csc, "csc packages:count", -1);
	tryvm_if(count == 0, ret = PKGMGR_R_ERROR, "csc [%s] dont have packages", csc_path);

	snprintf(buf, PKG_STRING_LEN_MAX, "[result]\n");
	fwrite(buf, 1, strlen(buf), file);
	snprintf(buf, PKG_STRING_LEN_MAX, "count = %d\n", count);
	fwrite(buf, 1, strlen(buf), file);

	for (cnt = 1 ; cnt <= count ; cnt++) {
		snprintf(type_buf, PKG_STRING_LEN_MAX - 1, "csc packages:type_%03d", cnt);
		snprintf(des_buf, PKG_STRING_LEN_MAX - 1, "csc packages:description_%03d", cnt);

		pkgtype = iniparser_getstring(csc, type_buf, NULL);
		des = iniparser_getstring(csc, des_buf, NULL);
		ret = 0;

		if (pkgtype == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get pkgtype\n", type_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		} else if (des == NULL) {
			csc_fail++;
			snprintf(buf, PKG_STRING_LEN_MAX, "%s = Fail to get description\n", des_buf);
			fwrite(buf, 1, strlen(buf), file);
			continue;
		}

		snprintf(buf, PKG_STRING_LEN_MAX, "type_%03d = %s\n", cnt, pkgtype);
		fwrite(buf, 1, strlen(buf), file);
		snprintf(buf, PKG_STRING_LEN_MAX, "description_%03d = %s\n", cnt, des);
		fwrite(buf, 1, strlen(buf), file);

		if (strcmp(pkgtype, "tpk") == 0) {
			const char *ospinstaller_argv[] = { "/usr/bin/osp-installer", "-c", des, NULL };
			ret = __xsystem(ospinstaller_argv);
		} else if (strcmp(pkgtype, "wgt") == 0) {
			const char *wrtinstaller_argv[] = { "/usr/bin/wrt-installer", "-c", des, NULL };
			ret = __xsystem(wrtinstaller_argv);
		} else {
			csc_fail++;
			ret = -1;
		}

		if (ret != 0) {
			char *errstr = NULL;
			__error_to_string(ret, &errstr);
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = fail[%s]\n", cnt, errstr);
		} else {
			snprintf(buf, PKG_STRING_LEN_MAX, "result_%03d = success\n", cnt);
		}

		fwrite(buf, 1, strlen(buf), file);
	}

catch:
	iniparser_freedict(csc);
	if (file != NULL) {
		fflush(file);
		fd = fileno(file);
		fsync(fd);
		fclose(file);
	}
	return ret;
}

static int __get_size_process(pkgmgr_client *pc, const char *pkgid, uid_t uid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "getsize",
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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	retvm_if(mpc->ctype != PC_REQUEST, PKGMGR_R_EINVAL, "mpc->ctype is not PC_REQUEST\n");

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
	else
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "pkgmgrinfo_pkginfo_get_pkginfo failed");

	if (service_type == PM_REQUEST_KILL_APP)
		ret = comm_client_request(mpc->info.request.cc, "kill",
				g_variant_new("(us)", uid, pkgid), &result);
	else if (service_type == PM_REQUEST_CHECK_APP)
		ret = comm_client_request(mpc->info.request.cc, "check",
				g_variant_new("(us)", uid, pkgid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed, ret=%d", ret);
		return ret;
	}

	/* FIXME */
	pid  = __sync_process(pkgid);
	*(int *)data = pid;

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return ret;

}

static int __request_size_info(pkgmgr_client *pc, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "getsize",
			g_variant_new("(usi)", uid, "size_info",
				PM_GET_SIZE_INFO),
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

	g_variant_unref(result);

	return ret;
}

static int __change_op_cb_for_getsize(pkgmgr_client *pc)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	req_cb_info *tmp = NULL;
	req_cb_info *prev = NULL;
	for (tmp = mpc->info.request.rhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.request.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_REQUEST;
	mpc->status_type = PKGMGR_CLIENT_STATUS_GET_SIZE;


	mpc->info.request.cc = comm_client_new(PC_REQUEST);
	retvm_if(mpc->info.request.cc == NULL, PKGMGR_R_ERROR, "client creation failed");

	ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_GET_SIZE, mpc->info.request.cc, __operation_callback, pc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "set_status_callback() failed - %d", ret);

	return PKGMGR_R_OK;
}

static int __change_op_cb_for_enable_disable(pkgmgr_client *pc, bool is_disable)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/*  free listening head */
	req_cb_info *tmp = NULL;
	req_cb_info *prev = NULL;
	for (tmp = mpc->info.request.rhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.request.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_REQUEST;
	if (is_disable)
		mpc->status_type = PKGMGR_CLIENT_STATUS_DISABLE_APP;
	else
		mpc->status_type = PKGMGR_CLIENT_STATUS_ENABLE_APP;


	mpc->info.request.cc = comm_client_new(PC_REQUEST);
	retvm_if(mpc->info.request.cc == NULL, PKGMGR_R_ERROR, "client creation failed");

	if (is_disable)
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_DISABLE_APP, mpc->info.request.cc, __operation_callback, pc);
	else
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ENABLE_APP, mpc->info.request.cc, __operation_callback, pc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "set_status_callback() failed - %d", ret);

	return PKGMGR_R_OK;
}

static int __get_pkg_size_info_cb(uid_t target_uid, int req_id, const char *req_type,
		const char *pkgid, const char *key,
		const char *value, const void *pc, void *user_data)
{
	int ret = 0;
	DBG("target_uid: %u, reqid: %d, req type: %s, pkgid: %s, unused key: %s, size info: %s",
			target_uid, req_id, req_type, pkgid, key, value);

	pkg_size_info_t *size_info = (pkg_size_info_t *)malloc(sizeof(pkg_size_info_t));
	retvm_if(size_info == NULL, -1, "The memory is insufficient.");

	char *save_ptr = NULL;
	char *token = strtok_r((char *)value, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->app_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->ext_data_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->ext_cache_size = atoll(token);
	token = strtok_r(NULL, ":", &save_ptr);
	tryvm_if(token == NULL, ret = -1, "failed to parse sizeinfo");
	size_info->ext_app_size = atoll(token);

	DBG("data: %lld, cache: %lld, app: %lld, ext_data: %lld, ext_cache: %lld, ext_app: %lld",
			size_info->data_size, size_info->cache_size, size_info->app_size,
			size_info->ext_data_size, size_info->ext_cache_size, size_info->ext_app_size);

	pkgmgr_client_t *pmc = (pkgmgr_client_t *)pc;
	tryvm_if(pmc == NULL, ret = -1, "pkgmgr_client instance is null.");

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0) {	/* total package size info */
		pkgmgr_total_pkg_size_info_receive_cb callback = (pkgmgr_total_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, size_info, user_data);
	} else {
		pkgmgr_pkg_size_info_receive_cb callback = (pkgmgr_pkg_size_info_receive_cb)(pmc->new_event_cb);
		callback((pkgmgr_client *)pc, pkgid, size_info, user_data);
	}

catch:

	if (size_info) {
		free(size_info);
		size_info = NULL;
	}
	return ret;
}

API pkgmgr_client *pkgmgr_client_new(client_type ctype)
{
	pkgmgr_client_t *pc = NULL;
	int ret = -1;

	retvm_if(ctype == PC_BROADCAST, NULL, "broadcast type is not supported");
	retvm_if(ctype != PC_REQUEST && ctype != PC_LISTENING, NULL, "ctype is not client_type");

	/* Allocate memory for ADT:pkgmgr_client */
	pc = calloc(1, sizeof(pkgmgr_client_t));
	retvm_if(pc == NULL, NULL, "No memory");

	/* Manage pc */
	pc->ctype = ctype;
	pc->status_type = PKGMGR_CLIENT_STATUS_ALL;
	pc->tep_path = NULL;

	if (pc->ctype == PC_REQUEST) {
		pc->info.request.cc = comm_client_new(PC_REQUEST);
		trym_if(pc->info.request.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.request.cc, __operation_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	} else if (pc->ctype == PC_LISTENING) {
		pc->info.listening.cc = comm_client_new(PC_LISTENING);
		trym_if(pc->info.listening.cc == NULL, "client creation failed");

		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ALL, pc->info.listening.cc, __status_callback, pc);
		trym_if(ret < 0L, "comm_client_set_status_callback() failed - %d", ret);
	}

	return (pkgmgr_client *)pc;

 catch:
	if (pc)
		free(pc);
	return NULL;
}

API int pkgmgr_client_free(pkgmgr_client *pc)
{
	int ret = -1;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;
	retvm_if(mpc == NULL, PKGMGR_R_EINVAL, "Invalid argument");

	if (mpc->ctype == PC_REQUEST) {
		req_cb_info *tmp;
		req_cb_info *prev;
		for (tmp = mpc->info.request.rhead; tmp;) {
			prev = tmp;
			tmp = tmp->next;
			free(prev);
		}

		ret = comm_client_free(mpc->info.request.cc);
		tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_LISTENING) {
			listen_cb_info *tmp;
			listen_cb_info *prev;
			for (tmp = mpc->info.listening.lhead; tmp;) {
				prev = tmp;
				tmp = tmp->next;
				free(prev);
			}

			ret = comm_client_free(mpc->info.listening.cc);
			tryvm_if(ret < 0, ret = PKGMGR_R_ERROR, "comm_client_free() failed");
	} else if (mpc->ctype == PC_BROADCAST) {
		ret = 0;
	} else {
		ERR("Invalid client type\n");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->tep_path) {
		free(mpc->tep_path);
		mpc->tep_path = NULL;
	}

	free(mpc);
	mpc = NULL;
	return PKGMGR_R_OK;

 catch:
	if (mpc) {
		free(mpc);
		mpc = NULL;
	}
	return PKGMGR_R_ERROR;
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

static int __change_op_cb_for_enable_disable_splash_screen(pkgmgr_client *pc,
		bool is_enable)
{
	int ret;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	req_cb_info *tmp;
	req_cb_info *prev;

	if (mpc == NULL) {
		ERR("package mananger client pc is NULL");
		return PKGMGR_R_EINVAL;
	}

	for (tmp = mpc->info.request.rhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	ret = comm_client_free(mpc->info.request.cc);
	if (ret < 0) {
		ERR("comm_client_free() failed - %d", ret);
		return PKGMGR_R_ERROR;
	}

	mpc->ctype = PC_REQUEST;
	if (is_enable)
		mpc->status_type = PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN;
	else
		mpc->status_type = PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN;

	mpc->info.request.cc = comm_client_new(PC_REQUEST);
	if (mpc->info.request.cc == NULL) {
		ERR("client creation failed");
		return PKGMGR_R_ENOMEM;
	}

	if (is_enable)
		ret = comm_client_set_status_callback(
				COMM_STATUS_BROADCAST_ENABLE_APP_SPLASH_SCREEN,
				mpc->info.request.cc, __operation_callback, pc);
	else
		ret = comm_client_set_status_callback(
				COMM_STATUS_BROADCAST_DISABLE_APP_SPLASH_SCREEN,
				mpc->info.request.cc, __operation_callback, pc);

	if (ret < 0) {
		ERR("set_status_callback() failed - %d", ret);
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}

API int pkgmgr_client_set_tep_path(pkgmgr_client *pc, char *tep_path, bool tep_move)
{
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	retvm_if(tep_path == NULL, PKGMGR_R_EINVAL, "tep path is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	if (mpc->tep_path)
		free(mpc->tep_path);

	mpc->tep_path = strdup(tep_path);
	mpc->tep_move = tep_move;

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
	int req_id;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	char *pkgtype;

	if (pc == NULL || pkg_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	if (access(pkg_path, F_OK) != 0) {
		ERR("failed to access: %s", pkg_path);
		return PKGMGR_R_EINVAL;
	}

	if (mpc->tep_path != NULL && access(mpc->tep_path, F_OK) != 0) {
		ERR("failed to access: %s", mpc->tep_path);
		return PKGMGR_R_EINVAL;
	}

	/* TODO: check pkg's type on server-side */
	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	/* build arguments */
	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	if (mpc->tep_path) {
		g_variant_builder_add(builder, "s", "-e");
		g_variant_builder_add(builder, "s", mpc->tep_path);
		g_variant_builder_add(builder, "s", "-M");
		/* TODO: revise tep_move */
		g_variant_builder_add(builder, "s",
				mpc->tep_move ? "tep_move" : "tep_copy");
	}

	args = g_variant_new("as", builder);
	g_variant_builder_unref(builder);

	ret = comm_client_request(mpc->info.request.cc, "install",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	g_variant_unref(result);

	return req_id;
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
	int req_id;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	char *pkgtype;
	pkgmgrinfo_pkginfo_h handle;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
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

	ret = comm_client_request(mpc->info.request.cc, "reinstall",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	g_variant_unref(result);

	return req_id;
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
	int req_id;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	char *pkgtype;

	if (pc == NULL || pkg_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	if (access(pkg_path, F_OK) != 0) {
		ERR("failed to access: %s", pkg_path);
		return PKGMGR_R_EINVAL;
	}

	if (mpc->tep_path != NULL && access(mpc->tep_path, F_OK) != 0) {
		ERR("failed to access: %s", mpc->tep_path);
		return PKGMGR_R_EINVAL;
	}

	/* TODO: check pkg's type on server-side */
	if (pkg_type == NULL)
		pkgtype = __get_type_from_path(pkg_path);
	else
		pkgtype = strdup(pkg_type);

	/* build arguments */
	builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
	if (mpc->tep_path) {
		g_variant_builder_add(builder, "s", "-e");
		g_variant_builder_add(builder, "s", mpc->tep_path);
		g_variant_builder_add(builder, "s", "-M");
		/* TODO: revise tep_move */
		g_variant_builder_add(builder, "s",
				mpc->tep_move ? "tep_move" : "tep_copy");
	}

	args = g_variant_new("as", builder);
	g_variant_builder_unref(builder);

	ret = comm_client_request(mpc->info.request.cc, "mount_install",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	g_variant_unref(result);

	return req_id;
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
	int req_id;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	char *pkgtype;
	pkgmgrinfo_pkginfo_h handle;

	if (pc == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
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

	ret = comm_client_request(mpc->info.request.cc, "uninstall",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	g_variant_unref(result);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return req_id;
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
	int req_id;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkg_type == NULL || pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if ((move_type < PM_MOVE_TO_INTERNAL) || (move_type > PM_MOVE_TO_SDCARD))
		return PKGMGR_R_EINVAL;

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "move",
			g_variant_new("(ussi)", uid, pkg_type, pkgid, move_type), &result);
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_usr_activate(pkgmgr_client *pc, const char *pkg_type,
		const char *pkgid, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || pkg_type == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "enable_pkg",
			g_variant_new("(uss)", uid, pkg_type, pkgid), &result);
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

API int pkgmgr_client_usr_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || pkg_type == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "disable_pkg",
			g_variant_new("(uss)", uid, pkg_type, pkgid), &result);
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

/* TODO: deprecate? */
API int pkgmgr_client_usr_activate_appv(pkgmgr_client *pc, const char *appid,
		char *const argv[], uid_t uid)
{
	return pkgmgr_client_usr_activate_app(pc, appid, NULL, uid);
}

API int pkgmgr_client_activate_appv(pkgmgr_client *pc, const char *appid,
		char *const argv[])
{
	return pkgmgr_client_usr_activate_app(pc, appid, NULL, _getuid());
}

API int pkgmgr_client_usr_activate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	int req_id;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (__change_op_cb_for_enable_disable(mpc, false) < 0) {
		ERR("__change_op_cb_for_enable_disable failed");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(mpc->info.request.cc, "enable_app",
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

	req_id = _get_request_id();
	__add_op_app_cbinfo(pc, req_id, req_key, app_event_cb, NULL);
	g_variant_unref(result);
	return ret;
}

API int pkgmgr_client_activate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb)
{
	return pkgmgr_client_usr_activate_app(pc, appid, app_event_cb, _getuid());
}

API int pkgmgr_client_activate_global_app_for_uid(pkgmgr_client *pc,
				 const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	int req_id;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (__change_op_cb_for_enable_disable(mpc, false) < 0) {
		ERR("__change_op_cb_for_enable_disable failed");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(mpc->info.request.cc, "enable_global_app_for_uid",
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

	req_id = _get_request_id();
	__add_op_app_cbinfo(pc, req_id, req_key, app_event_cb, NULL);

	return ret;
}

API int pkgmgr_client_usr_deactivate_app(pkgmgr_client *pc, const char *appid,
		pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;
	int req_id;
	char *req_key = NULL;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	/* FIXME */
	if (__change_op_cb_for_enable_disable(mpc, true) < 0) {
		ERR("__change_op_cb_for_enable_disable failed");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(mpc->info.request.cc, "disable_app",
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

	req_id = _get_request_id();
	__add_op_app_cbinfo(pc, req_id, req_key, app_event_cb, NULL);

	g_variant_unref(result);
	return ret;
}

API int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb)
{
	return pkgmgr_client_usr_deactivate_app(pc, appid, app_event_cb, _getuid());
}

API int pkgmgr_client_deactivate_global_app_for_uid(pkgmgr_client *pc,
				 const char *appid, pkgmgr_app_handler app_event_cb, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	int req_id;
	char *req_key = NULL;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (__change_op_cb_for_enable_disable(mpc, true) < 0) {
		ERR("__change_op_cb_for_enable_disable failed");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(mpc->info.request.cc, "disable_global_app_for_uid",
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

	req_id = _get_request_id();
	__add_op_app_cbinfo(pc, req_id, req_key, app_event_cb, NULL);
	return ret;
}

API int pkgmgr_client_usr_clear_user_data(pkgmgr_client *pc,
		const char *pkg_type, const char *appid, pkgmgr_mode mode,
		uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkg_type == NULL || appid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "cleardata",
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
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	retvm_if(status_type == PKGMGR_CLIENT_STATUS_ALL, PKGMGR_R_OK, "status_type is PKGMGR_CLIENT_STATUS_ALL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	/*  free listening head */
	listen_cb_info *tmp = NULL;
	listen_cb_info *prev = NULL;
	for (tmp = mpc->info.listening.lhead; tmp;) {
		prev = tmp;
		tmp = tmp->next;
		free(prev);
	}

	/* free dbus connection */
	ret = comm_client_free(mpc->info.listening.cc);
	retvm_if(ret < 0, PKGMGR_R_ERROR, "comm_client_free() failed - %d", ret);

	/* Manage pc for seperated event */
	mpc->ctype = PC_LISTENING;
	mpc->status_type = status_type;

	mpc->info.listening.cc = comm_client_new(PC_LISTENING);
	retvm_if(mpc->info.listening.cc == NULL, PKGMGR_R_EINVAL, "client creation failed");

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL) == PKGMGR_CLIENT_STATUS_INSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "PKGMGR_CLIENT_STATUS_INSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UNINSTALL) == PKGMGR_CLIENT_STATUS_UNINSTALL) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UNINSTALL, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UNINSTALL failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_MOVE) == PKGMGR_CLIENT_STATUS_MOVE) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_MOVE, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_MOVE failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) == PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_INSTALL_PROGRESS, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_INSTALL_PROGRESS failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_UPGRADE) == PKGMGR_CLIENT_STATUS_UPGRADE) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_UPGRADE, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_UPGRADE failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_ENABLE_APP) == PKGMGR_CLIENT_STATUS_ENABLE_APP) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ENABLE_APP, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_ENABLE_APP failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_DISABLE_APP) == PKGMGR_CLIENT_STATUS_DISABLE_APP) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_DISABLE_APP, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_DISABLE_APP failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN) == PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_ENABLE_APP_SPLASH_SCREEN, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_ENABLE_APP_SPLASH_SCREEN failed - %d", ret);
	}

	if ((mpc->status_type & PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN) == PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN) {
		ret = comm_client_set_status_callback(COMM_STATUS_BROADCAST_DISABLE_APP_SPLASH_SCREEN, mpc->info.listening.cc, __status_callback, pc);
		retvm_if(ret < 0, PKGMGR_R_ECOMM, "COMM_STATUS_BROADCAST_DISABLE_APP_SPLASH_SCREEN failed - %d", ret);
	}

	return PKGMGR_R_OK;
}

API int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check input */
	retvm_if(mpc->ctype != PC_LISTENING, PKGMGR_R_EINVAL, "ctype is not PC_LISTENING");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL");

	/* 1. get id */
	req_id = _get_request_id();

	/* 2. add callback info to pkgmgr_client */
	__add_stat_cbinfo(mpc, req_id, event_cb, data);
	return req_id;
}

API int pkgmgr_client_listen_app_status(pkgmgr_client *pc, pkgmgr_app_handler event_cb,
				    void *data)
{
	int req_id;
	/* Check for NULL value of pc */
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	/* 0. check input */
	retvm_if(mpc->ctype != PC_LISTENING, PKGMGR_R_EINVAL, "ctype is not PC_LISTENING");
	retvm_if(event_cb == NULL, PKGMGR_R_EINVAL, "event_cb is NULL");

	/* 1. get id */
	req_id = _get_request_id();

	/* 2. add app callback info to pkgmgr_client */
	__add_app_stat_cbinfo(mpc, req_id, event_cb, data);
	return req_id;
}

API int pkgmgr_client_remove_listen_status(pkgmgr_client *pc)
{
	int ret = -1;

	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "package manager client pc is NULL");
	pkgmgr_client_t *mpc = (pkgmgr_client_t *) pc;

	ret = __remove_stat_cbinfo(mpc);
	if (ret != 0) {
		ERR("failed to remove status callback");
		return PKGMGR_R_ERROR;
	}

	return PKGMGR_R_OK;
}

API int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
				       const char *pkgid, const char *key,
				       const char *val)
{
	/* client cannot broadcast signal */
	return PKGMGR_R_OK;
}

API int pkgmgr_client_request_service(pkgmgr_request_service_type service_type, int service_mode,
				  pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
			      const char *custom_info, pkgmgr_handler event_cb, void *data)
{
	return pkgmgr_client_usr_request_service(service_type, service_mode, pc, pkg_type, pkgid, _getuid(), custom_info, event_cb, data);
}

API int pkgmgr_client_usr_request_service(pkgmgr_request_service_type service_type, int service_mode,
				  pkgmgr_client *pc, const char *pkg_type, const char *pkgid, uid_t uid,
			      const char *custom_info, pkgmgr_handler event_cb, void *data)
{
	int ret = 0;

	/* Check for NULL value of service type */
	retvm_if(service_type > PM_REQUEST_MAX, PKGMGR_R_EINVAL, "service type is not defined\n");
	retvm_if(service_type < 0, PKGMGR_R_EINVAL, "service type is error\n");

	switch (service_type) {
	case PM_REQUEST_CSC:
		tryvm_if(custom_info == NULL, ret = PKGMGR_R_EINVAL, "custom_info is NULL\n");
		tryvm_if(strlen(custom_info) >= PKG_STRING_LEN_MAX, ret = PKGMGR_R_EINVAL, "custom_info over PKG_STRING_LEN_MAX");
		tryvm_if(data == NULL, ret = PKGMGR_R_EINVAL, "data is NULL\n");

		ret = __csc_process(custom_info, (char *)data);
		if (ret < 0)
			ERR("__csc_process fail \n");
		else
			ret = PKGMGR_R_OK;

		break;

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
	int ret = 0;
	pkgmgr_client *pc = NULL;

	pc = pkgmgr_client_new(PC_REQUEST);
	retvm_if(pc == NULL, PKGMGR_R_EINVAL, "request pc is null\n");

	ret = __request_size_info(pc, uid);
	if (ret < 0)
		ERR("__request_size_info fail \n");

	pkgmgr_client_free(pc);
	return ret;
}

API int pkgmgr_client_request_size_info(void) /* get all package size (data, total) */
{
	return pkgmgr_client_usr_request_size_info(_getuid());
}

API int pkgmgr_client_usr_clear_cache_dir(const char *pkgid, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *pc;

	if (pkgid == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	pc = pkgmgr_client_new(PC_REQUEST);
	if (pc == NULL) {
		ERR("out of memory");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(pc->info.request.cc, "clearcache",
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
	return pkgmgr_client_usr_clear_cache_dir(PKG_CLEAR_ALL_CACHE, _getuid());
}

API int pkgmgr_client_get_size(pkgmgr_client *pc, const char *pkgid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data)
{
	return pkgmgr_client_usr_get_size(pc, pkgid, get_type, event_cb, data,
			_getuid());
}

API int pkgmgr_client_usr_get_size(pkgmgr_client *pc, const char *pkgid,
		pkgmgr_getsize_type get_type, pkgmgr_handler event_cb,
		void *data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	int req_id;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	/* FIXME */
	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
		get_type = PM_GET_TOTAL_PKG_SIZE_INFO;
	else
		get_type = PM_GET_PKG_SIZE_INFO;

	ret = comm_client_request(mpc->info.request.cc, "getsize",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, event_cb, NULL, data);

	g_variant_unref(result);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_usr_get_package_size_info(pkgmgr_client *pc,
		const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb,
		void *user_data, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	char *req_key = NULL;
	int req_id;
	int get_type;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || event_cb == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	/* FIXME */
	if (__change_op_cb_for_getsize(mpc) < 0) {
		ERR("__change_op_cb_for_getsize failed");
		return PKGMGR_R_ESYSTEM;
	}

	if (strcmp(pkgid, PKG_SIZE_INFO_TOTAL) == 0)
		get_type = PM_GET_TOTAL_PKG_SIZE_INFO;
	else
		get_type = PM_GET_PKG_SIZE_INFO;

	ret = comm_client_request(mpc->info.request.cc, "getsize",
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

	req_id = _get_request_id();
	__add_op_cbinfo(mpc, req_id, req_key, __get_pkg_size_info_cb, event_cb,
			user_data);

	g_variant_unref(result);

	return PKGMGR_R_OK;
}

API int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb event_cb, void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, pkgid, event_cb, user_data, _getuid());
}

API int pkgmgr_client_usr_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data, uid_t uid)
{	/* total package size info */
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, (pkgmgr_pkg_size_info_receive_cb)event_cb, user_data, uid);
}

API int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb event_cb, void *user_data)
{
	return pkgmgr_client_usr_get_package_size_info(pc, PKG_SIZE_INFO_TOTAL, (pkgmgr_pkg_size_info_receive_cb)event_cb, user_data, _getuid());
}

API int pkgmgr_client_generate_license_request(pkgmgr_client *pc,
		const char *resp_data, char **req_data, char **license_url)
{
	GVariant *result;
	int ret;
	char *data;
	char *url;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || resp_data == NULL || req_data == NULL ||
			license_url == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || resp_data == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
			"register_license", g_variant_new("(s)", resp_data),
			&result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK) {
		ERR("register license failed: %d", ret);
		return ret;
	}

	return PKGMGR_R_OK;
}

API int pkgmgr_client_decrypt_package(pkgmgr_client *pc,
		const char *drm_file_path, const char *decrypted_file_path)
{
	GVariant *result;
	int ret;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || drm_file_path == NULL ||
			decrypted_file_path == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	if (mpc->ctype != PC_REQUEST) {
		ERR("mpc->ctype is not PC_REQUEST");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
			"decrypt_package",
			g_variant_new("(ss)", drm_file_path,
				decrypted_file_path),
			&result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);
	if (ret != PKGMGR_R_OK) {
		ERR("decrypt_package failed: %d", ret);
		return ret;
	}

	return PKGMGR_R_OK;
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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("Invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = __change_op_cb_for_enable_disable_splash_screen(mpc, true);
	if (ret < 0) {
		ERR("__change_op_cb_for_enable_disable_splash_screen failed");
		return PKGMGR_R_ESYSTEM;
	}

	ret = comm_client_request(mpc->info.request.cc,
			"enable_app_splash_screen",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	g_variant_unref(result);

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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || appid == NULL) {
		ERR("Invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = __change_op_cb_for_enable_disable_splash_screen(mpc, false);
	if (ret < 0) {
		ERR("__change_op_cb_for_enable_disable_splash_screen failed");
		return ret;
	}

	ret = comm_client_request(mpc->info.request.cc,
			"disable_app_splash_screen",
			g_variant_new("(us)", uid, appid), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	if (ret != PKGMGR_R_OK) {
		g_variant_unref(result);
		return ret;
	}

	g_variant_unref(result);

	return ret;
}

static int __set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0 || mode <= 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "set_restriction_mode",
			g_variant_new("(usi)", uid, pkgid, mode), &result);
	if (ret != PKGMGR_R_OK) {
		ERR("request failed: %d", ret);
		return ret;
	}

	g_variant_get(result, "(i)", &ret);
	g_variant_unref(result);

	return ret;
}

API int pkgmgr_client_usr_set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid)
{
	return __set_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode)
{
	return pkgmgr_client_usr_set_pkg_restriction_mode(pc, pkgid, mode, _getuid());
}

static int __unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0 || mode <= 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
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

API int pkgmgr_client_usr_unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid)
{
	return __unset_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode)
{
	return pkgmgr_client_usr_unset_pkg_restriction_mode(pc, pkgid, mode, _getuid());
}

static int __get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int *mode, uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	gint m;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL || pkgid == NULL || strlen(pkgid) == 0) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
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

API int pkgmgr_client_usr_get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int *mode, uid_t uid)
{
	return __get_pkg_restriction_mode(pc, pkgid, mode, uid);
}

API int pkgmgr_client_get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int *mode)
{
	return pkgmgr_client_usr_get_pkg_restriction_mode(pc, pkgid, mode, _getuid());
}

API int pkgmgr_client_usr_set_restriction_mode(pkgmgr_client *pc, int mode,
		uid_t uid)
{
	GVariant *result;
	int ret = PKGMGR_R_ECOMM;
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc, "set_restriction_mode",
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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
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
	pkgmgr_client_t *mpc = (pkgmgr_client_t *)pc;

	if (pc == NULL) {
		ERR("invalid parameter");
		return PKGMGR_R_EINVAL;
	}

	ret = comm_client_request(mpc->info.request.cc,
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

API int pkgmgr_client_get_restriction_mode(pkgmgr_client *pc,
		int *mode)
{
	return pkgmgr_client_usr_get_restriction_mode(pc, mode, _getuid());
}
