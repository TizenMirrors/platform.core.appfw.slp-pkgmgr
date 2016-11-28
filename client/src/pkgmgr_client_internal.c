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
#include <stdbool.h>
#include <ctype.h>
#include <xdgmime.h>

#include <unistd.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <tzplatform_config.h>
#include <pkgmgr-info.h>

#include "package-manager.h"
#include "pkgmgr_client_debug.h"
#include "pkgmgr_client_internal.h"

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#define IS_WHITESPACE(CHAR) \
	((CHAR == ' ' || CHAR == '\t' || CHAR == '\r' || CHAR == '\n') ? \
	true : false)

void _app_str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!IS_WHITESPACE(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

char *_get_backend_path(const char *input_path)
{
	FILE *fp = NULL;
	char buffer[1024] = { '\0', };
	char *type = NULL;
	char installer_path[PKG_STRING_LEN_MAX] = { '\0', };
	char pkg_path[PKG_STRING_LEN_MAX] = { '\0', };
	char backend_path[PKG_STRING_LEN_MAX] = { '\0', };

	if (strrchr(input_path, '/')) {
		strncpy(pkg_path, strrchr(input_path, '/') + 1,
			PKG_STRING_LEN_MAX - 1);
	} else {
		strncpy(pkg_path, input_path, PKG_STRING_LEN_MAX - 1);
	}

	DBG("pkg_path[%s]\n", pkg_path);

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL)
		return NULL;

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			DBG("[%s]\n", buffer);
			DBG("[%s]\n", path);
			path = path + strlen(PKG_BACKEND);
			DBG("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL)
		return NULL;

/*	if(path[strlen(path)] == '/') */
	snprintf(backend_path, PKG_STRING_LEN_MAX - 1, "%s", path);
/*	else
		sprintf(backend_path, "%s/", path); */

	type = strrchr(pkg_path, '.');
	if (type == NULL)
		type = pkg_path;
	else
		type++;

	snprintf(installer_path, PKG_STRING_LEN_MAX - 1,
					"%s%s", backend_path, type);

	DBG("installer_path[%s]\n", installer_path);

	if (access(installer_path, F_OK) != 0)
		return NULL;

	return strdup(installer_path);
}

char *_get_backend_path_with_type(const char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { '\0', };
	char installer_path[PKG_STRING_LEN_MAX] = { '\0', };
	char backend_path[PKG_STRING_LEN_MAX] = { '\0', };

	DBG("type[%s]\n", type);

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL)
		return NULL;

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			DBG("[%s]\n", buffer);
			DBG("[%s]\n", path);
			path = path + strlen(PKG_BACKEND);
			DBG("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL)
		return NULL;

/*	if(path[strlen(path)] == '/') */
	snprintf(backend_path, PKG_STRING_LEN_MAX - 1, "%s", path);
/*	else
       sprintf(backend_path, "%s/", path); */

	snprintf(installer_path, PKG_STRING_LEN_MAX - 1,
					"%s%s", backend_path, type);
	DBG("installer_path[%s]\n", installer_path);

	if (access(installer_path, F_OK) != 0) {
		char extlist[256] = { '\0', };
		_get_mime_extension(type, extlist, sizeof(extlist));
		DBG("extlist[%s]\n", extlist);

		if (strlen(extlist) == 0)
			return NULL;

		if (strchr(extlist, ',')) {
			extlist[strlen(extlist) -
				strlen(strchr(extlist, ','))] = '\0';
		}
		type = strchr(extlist, '.') + 1;

		snprintf(installer_path, PKG_STRING_LEN_MAX - 1,
						"%s%s", backend_path, type);
	}

	return strdup(installer_path);
}

int _get_mime_from_file(const char *filename, char *mimetype, int len)
{
	const char *mime;
	if (filename == NULL)
		return -1;

	if (access(filename, F_OK) != 0)
		return -1;

	mime = xdg_mime_get_mime_type_for_file(filename, 0);
	if (strcmp(mime, "application/octet-stream") == 0)
		mime = xdg_mime_get_mime_type_from_file_name(filename);

	snprintf(mimetype, len, "%s", mime);
	return 0;
}

int _get_mime_extension(const char *mimetype, char *ext, int len)
{
	const char **extlist;
	int totlen = 0;
	const char *unaliased_mimetype;

	if (mimetype == NULL || ext == NULL || len <= 0)
		return -1;

	unaliased_mimetype = xdg_mime_unalias_mime_type(mimetype);
	if (unaliased_mimetype == NULL)
		return -1;

	extlist = xdg_mime_get_file_names_from_mime_type(unaliased_mimetype);
	if (extlist == NULL)
		return -1;

	if (extlist[0] == NULL)
		return -1;

	ext[0] = 0;
	while (*extlist != NULL) {
		if (*(extlist + 1) == NULL) {
			snprintf(&ext[totlen], len - totlen, "%s", *extlist);
			break;
		} else {
			snprintf(&ext[totlen], len - totlen, "%s,", *extlist);
			if (strlen(*extlist) > len - totlen - 1)
				break;
			totlen += strlen(*extlist) + 1;
			extlist++;
		}
	}

	return 0;
}

const char *_get_pkg_type(const char *pkgid, uid_t uid)
{
	int ret;
	pkgmgrinfo_pkginfo_h pkginfo;
	char *val;
	static char pkg_type[PKG_EXT_LEN_MAX];

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &pkginfo);
	if (ret != PMINFO_R_OK)
		return NULL;

	ret = pkgmgrinfo_pkginfo_get_type(pkginfo, &val);
	if (ret != PMINFO_R_OK)
		return NULL;

	snprintf(pkg_type, sizeof(pkg_type), "%s", val);

	pkgmgrinfo_pkginfo_destroy_pkginfo(pkginfo);

	return pkg_type;
}

package_manager_pkg_info_t *_pkg_malloc_appinfo(int num)
{
	package_manager_app_info_t *app_info = NULL;
	package_manager_app_info_t *first = NULL;
	package_manager_app_info_t *last = NULL;
	int i = 0;

	for (i = 0; i < num; i++) {
		app_info = (package_manager_app_info_t *)
		    malloc(sizeof(package_manager_app_info_t));
		if (app_info == NULL) {
			package_manager_app_info_t *temp_info;
			package_manager_app_info_t *next;

			for (temp_info = first; temp_info != NULL;
			     temp_info = next) {
				next = temp_info->next;
				free(temp_info);
				temp_info = NULL;
			}

			return NULL;
		}

		memset(app_info, 0x00, sizeof(package_manager_app_info_t));

		if (first == NULL)
			first = app_info;

		if (last == NULL)
			last = app_info;
		else {
			last->next = app_info;
			last = app_info;
		}
	}

	return first;

}

static pkg_plugin_set *plugin_set_list[24] = { 0, };

pkg_plugin_set *_pkg_plugin_load_library(const char *pkg_type,
		const char *library_path)
{
	void *library_handle;
	int i;
	bool (*on_load)(pkg_plugin_set *plugin);

	if (library_path == NULL || pkg_type == NULL) {
		ERR("invalid parameter");
		return NULL;
	}

	for (i = 0; plugin_set_list[i]; i++) {
		if (strcmp(plugin_set_list[i]->pkg_type, pkg_type) == 0) {
			DBG("already loaded [%s]", library_path);
			return plugin_set_list[i];
		}
	}

	if ((library_handle = dlopen(library_path, RTLD_LAZY)) == NULL) {
		ERR("dlopen is failed library_path[%s]", library_path);
		return NULL;
	}

	if ((on_load = dlsym(library_handle, "pkg_plugin_on_load")) == NULL ||
			dlerror() != NULL) {
		ERR("can not find symbol");
		dlclose(library_handle);
		return NULL;
	}

	plugin_set_list[i] = (pkg_plugin_set *)calloc(1, sizeof(pkg_plugin_set));
	if (plugin_set_list[i] == NULL) {
		ERR("malloc of the plugin_set_list element is failed");
		dlclose(library_handle);
		return NULL;
	}

	if (on_load(plugin_set_list[i]) != 0) {
		ERR("pkg_plugin_on_load failed");
		free(plugin_set_list[i]);
		dlclose(library_handle);
		plugin_set_list[i] = NULL;
		return NULL;
	}

	plugin_set_list[i]->plugin_handle = library_handle;
	snprintf(plugin_set_list[i]->pkg_type,
			sizeof(plugin_set_list[i]->pkg_type), "%s", pkg_type);

	DBG("library [%s] is loaded", library_path);

	return plugin_set_list[i];
}

int _pkg_plugin_get_library_path(const char *pkg_type, char *library_path)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };

	if (pkg_type == NULL || library_path == NULL) {
		ERR("invalid argument\n");
		return -1;
	}

	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		ERR("no matching backendlib\n");
		return PKGMGR_R_ERROR;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKENDLIB)) != NULL) {
			DBG("[%s]\n", buffer);
			DBG("[%s]\n", path);
			path = path + strlen(PKG_BACKENDLIB);
			DBG("[%s]\n", path);

			break;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	if (path == NULL) {
		ERR("no matching backendlib\n");
		return PKGMGR_R_ERROR;
	}

	snprintf(library_path, 1024, "%slib%s.so", path, pkg_type);

	return PKGMGR_R_OK;

}

pkg_plugin_set *_package_manager_load_library(const char *pkg_type)
{
	char package_path[1024] = { 0, };
	pkg_plugin_set *plugin_set;

	if (pkg_type == NULL) {
		ERR("cannot load library - pkg_type is null");
		return NULL;
	}

	if (_pkg_plugin_get_library_path(pkg_type, package_path) !=
			PKGMGR_R_OK) {
		ERR("cannot find path");
		return NULL;
	}

	plugin_set = _pkg_plugin_load_library(pkg_type, package_path);
	if (plugin_set == NULL) {
		ERR("cannot load library");
		return NULL;
	}

	return plugin_set;
}

typedef struct _detail_info_map_t {
	char *name;
	void *field;
	char *type;
} detail_info_map_t;

/*
	typedef struct _package_manager_pkg_detail_info_t {
		char pkg_type[PKG_TYPE_STRING_LEN_MAX];
		char pkgid[PKG_NAME_STRING_LEN_MAX];
		char version[PKG_VERSION_STRING_LEN_MAX];
		char pkg_description[PKG_VALUE_STRING_LEN_MAX];
		char min_platform_version[PKG_VERSION_STRING_LEN_MAX];
		time_t installed_time;
		int installed_size;
		int app_size;
		int data_size;
		char optional_id[PKG_NAME_STRING_LEN_MAX];
		void *pkg_optional_info;
	} package_manager_pkg_detail_info_t;
*/

static package_manager_pkg_detail_info_t tmp_pkg_detail_info;

static detail_info_map_t info_map[] = {
	{"pkg_type", tmp_pkg_detail_info.pkg_type, "string"},
	{"pkgid", tmp_pkg_detail_info.pkgid, "string"},
	{"version", tmp_pkg_detail_info.version, "string"},
	{"pkg_description", tmp_pkg_detail_info.pkg_description, "string"},
	{"min_platform_version", tmp_pkg_detail_info.min_platform_version,
	 "string"},
	{"installed_time", &tmp_pkg_detail_info.installed_time, "time_t"},
	{"installed_size", &tmp_pkg_detail_info.installed_size, "int"},
	{"app_size", &tmp_pkg_detail_info.app_size, "int"},
	{"data_size", &tmp_pkg_detail_info.data_size, "int"},
	{"optional_id", tmp_pkg_detail_info.optional_id, "string"}
};

char *_get_info_string(const char *key,
		       const package_manager_pkg_detail_info_t *
		       pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return NULL;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));

	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "string") == 0) {
				return strdup((char *)(tmp->field));
			} else if (strcmp(tmp->type, "bool") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1,
					"%d", (int)*(bool *) (tmp->field));
				return strdup(temp);
			} else if (strcmp(tmp->type, "int") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1,
					"%d", (int)*(int *)(tmp->field));
				return strdup(temp);
			} else if (strcmp(tmp->type, "time_t") == 0) {
				char temp[PKG_VALUE_STRING_LEN_MAX];
				snprintf(temp, PKG_VALUE_STRING_LEN_MAX - 1,
					"%d", (int)*(time_t *) (tmp->field));
				return strdup(temp);
			} else
				return NULL;
		}
	}
	return NULL;
}

int _get_info_int(const char *key,
		  const package_manager_pkg_detail_info_t *pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return -1;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));
	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "int") == 0)
				return (int)*(int *)(tmp->field);
			else
				return -1;
		}
	}
	return -1;
}

time_t _get_info_time(const char *key,
		      const package_manager_pkg_detail_info_t *pkg_detail_info)
{
	detail_info_map_t *tmp;
	int i = 0;

	if (pkg_detail_info == NULL)
		return -1;

	memcpy(&tmp_pkg_detail_info, pkg_detail_info,
	       sizeof(package_manager_pkg_detail_info_t));
	for (i = 0; i < sizeof(info_map) / sizeof(detail_info_map_t); i++) {
		tmp = &info_map[i];
		if (strcmp(key, tmp->name) == 0) {
			if (strcmp(tmp->type, "time_t") == 0)
				return (time_t) *(time_t *) (tmp->field);
			else
				return (time_t) -1;
		}
	}
	return (time_t) -1;
}


