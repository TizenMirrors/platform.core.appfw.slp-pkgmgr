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









/**
 * @file		package-manager.h
 * @author		Sewook Park <sewook7.park@samsung.com>
 * @version		0.1
 * @brief		This file declares API of slp-pkgmgr library
 *
 * @addtogroup APPLICATION_FRAMEWORK
 * @{
 *
  * @defgroup	PackageManager
 * @section		Header to use them:
 * @code
 * #include "package-manager.h"
 * @endcode
 *
 * @addtogroup PackageManager
 * @{
 */

#ifndef __PKG_MANAGER_H__
#define __PKG_MANAGER_H__

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEPRECATED
#define DEPRECATED	__attribute__ ((__deprecated__))
#endif

/**
 * @mainpage
 *
 * This is package manager
 *
 * Packaeg manager is used to install/uninstall the packages.\n
 * package includes dpkg, java, widget, etc. and it can be added\n
 * Security is considered on current package manager\n
 *
 */

/**
 * @file	package-manager.h
 * @brief Package Manager header
 *
 * Generated by    Sewook Park <sewook7.park@samsung.com>
 */



/**
 * @addtogroup PackageManager
 * @{
 */

/**
 * @brief pkgmgr info types.
 */
#define PKGMGR_INFO_STR_PKGTYPE		"pkg_type"
#define PKGMGR_INFO_STR_PKGNAME		"pkg_name"
#define PKGMGR_INFO_STR_VERSION		"version"
#define PKGMGR_INFO_STR_INSTALLED_SIZE	"installed_size"
#define PKGMGR_INFO_STR_DATA_SIZE	"data_size"
#define PKGMGR_INFO_STR_APP_SIZE	"app_size"
#define PKGMGR_INFO_STR_INSTALLED_TIME	"installed_time"

/**
 * @brief listening status type in pkgmgr.
 */
#define PKGMGR_CLIENT_STATUS_ALL				0x0FFF
#define PKGMGR_CLIENT_STATUS_INSTALL				0x0001
#define PKGMGR_CLIENT_STATUS_UNINSTALL				0x0002
#define PKGMGR_CLIENT_STATUS_UPGRADE				0x0004
#define PKGMGR_CLIENT_STATUS_MOVE				0x0008
#define PKGMGR_CLIENT_STATUS_CLEAR_DATA				0x0010
#define PKGMGR_CLIENT_STATUS_INSTALL_PROGRESS			0x0020
#define PKGMGR_CLIENT_STATUS_GET_SIZE				0x0040
#define PKGMGR_CLIENT_STATUS_ENABLE_APP				0x0080
#define PKGMGR_CLIENT_STATUS_DISABLE_APP			0x0100
#define PKGMGR_CLIENT_STATUS_ENABLE_APP_SPLASH_SCREEN		0x0200
#define PKGMGR_CLIENT_STATUS_DISABLE_APP_SPLASH_SCREEN		0x0400
#define PKGMGR_CLIENT_STATUS_CLEAR_CACHE			0x0800

/** @} */

#define PKG_SIZE_INFO_TOTAL "__TOTAL__"
#define PKG_CLEAR_ALL_CACHE "__ALL__"
/**
 * @brief Return values in pkgmgr.
 */
typedef enum _pkgmgr_return_val {
	PKGMGR_R_ESYSTEM = -9,		/**< Severe system error */
	PKGMGR_R_EIO = -8,		/**< IO error */
	PKGMGR_R_ENOMEM = -7,		/**< Out of memory */
	PKGMGR_R_ENOPKG = -6,		/**< No such package */
	PKGMGR_R_EPRIV = -5,		/**< Privilege denied */
	PKGMGR_R_ETIMEOUT = -4,		/**< Timeout */
	PKGMGR_R_EINVAL = -3,		/**< Invalid argument */
	PKGMGR_R_ECOMM = -2,		/**< Comunication Error */
	PKGMGR_R_ERROR = -1,		/**< General error */
	PKGMGR_R_OK = 0			/**< General success */
} pkgmgr_return_val;
/** @} */

/**
 * @defgroup pkg_operate	APIs to install /uninstall / activate application
 * @ingroup pkgmgr
 * @brief
 *	APIs to install /uninstall / activate application
 *	- Install application using application package filepath
 *	- Uninstall application using application package name
 *	- Activate application using application package name
 *
 */


/**
 * @addtogroup pkg_operate
 * @{
 */

typedef void pkgmgr_client;
typedef void pkgmgr_info;

typedef struct {
	long long data_size;
	long long cache_size;
	long long app_size;
	long long ext_data_size;
	long long ext_cache_size;
	long long ext_app_size;
} pkg_size_info_t;

typedef enum {
	PM_UPDATEINFO_TYPE_NONE = 0,
	PM_UPDATEINFO_TYPE_FORCE,
	PM_UPDATEINFO_TYPE_OPTIONAL
} pkgmgr_updateinfo_type;

typedef struct {
	char *pkgid;
	char *version;
	pkgmgr_updateinfo_type type;
} pkg_update_info_t;

typedef int (*pkgmgr_iter_fn)(const char *pkg_type, const char *pkgid,
				const char *version, void *data);

typedef int (*pkgmgr_handler)(uid_t target_uid, int req_id, const char *pkg_type,
				const char *pkgid, const char *key,
				const char *val, const void *pmsg, void *data);

typedef int (*pkgmgr_app_handler)(uid_t target_uid, int req_id, const char *pkg_type,
				const char *pkgid, const char *appid, const char *key,
				const char *val, const void *pmsg, void *data);

typedef void (*pkgmgr_pkg_size_info_receive_cb)(pkgmgr_client *pc, const char *pkgid,
		const pkg_size_info_t *size_info, void *user_data);

typedef void (*pkgmgr_total_pkg_size_info_receive_cb)(pkgmgr_client *pc,
		const pkg_size_info_t *size_info, void *user_data);

typedef enum {
	PC_REQUEST = 0,
	PC_LISTENING,
	PC_BROADCAST,
} pkgmgr_client_type;

typedef enum {
	PM_DEFAULT,
	PM_QUIET
} pkgmgr_mode;

typedef enum {
	PM_MOVE_TO_INTERNAL = 0,
	PM_MOVE_TO_SDCARD = 1,
} pkgmgr_move_type;

typedef enum {
	PM_REQUEST_MOVE = 0,
	PM_REQUEST_GET_SIZE = 1,
	PM_REQUEST_KILL_APP = 2,
	PM_REQUEST_CHECK_APP = 3,
	PM_REQUEST_MAX
} pkgmgr_request_service_type;

typedef enum {
	/* sync, get data, total size for one requested pkgid */
	PM_GET_TOTAL_SIZE = 0,
	PM_GET_DATA_SIZE = 1,

	/* async, get total used storage size */
	PM_GET_ALL_PKGS = 2,

	/* async, get a pkgid's data, total size for all installed pkg */
	PM_GET_SIZE_INFO = 3,

	/* deprecated */
	PM_GET_TOTAL_AND_DATA = 4,
	PM_GET_SIZE_FILE = 5,

	/* async, get data, cache, app size based on "pkg_size_info_t" */
	PM_GET_PKG_SIZE_INFO = 6,
	PM_GET_TOTAL_PKG_SIZE_INFO = 7,
	PM_GET_MAX
} pkgmgr_getsize_type;

typedef enum {
	PM_RESTRICTION_MODE_ALL = 0x07,
	PM_RESTRICTION_MODE_INSTALL = 0x01,
	PM_RESTRICTION_MODE_UNINSTALL = 0x02,
	PM_RESTRICTION_MODE_MOVE = 0x04,
} pkgmgr_restriction_mode;

/**
 * @brief	This API creates pkgmgr client.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	ctype	client type - PC_REQUEST, PC_LISTENING, PC_BROADCAST
 * @return	pkgmgr_client object
 * @retval	NULL	on failure creating an object
*/
pkgmgr_client *pkgmgr_client_new(pkgmgr_client_type ctype);

/**
 * @brief	This API deletes pkgmgr client.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @return	Operation result;
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_free(pkgmgr_client *pc);

/**
 * @brief	This API set information to install tep package.
 * @details	Use this API before calling installation API.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	tep_path	full path that tep file is located at
 * @param[in]	tep_move	if TRUE, source file will be moved, else it will be copied
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_set_tep_path(pkgmgr_client *pc, const char *tep_path, bool tep_move);

/**
 * @brief	This API installs package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	descriptor_path	full path that descriptor is located
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_data	optional data which is used for installation
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data, uid_t uid);
/**
 * @brief	This API reinstalls package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_data	optional data which is used for installation
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_reinstall(pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_reinstall(pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
				  const char *optional_data, pkgmgr_mode mode,
			      pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API mount-installs package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	descriptor_path	full path that descriptor is located
 * @param[in]	pkg_path		full path that package file is located
 * @param[in]	optional_data	optional data which is used for installation
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_mount_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_mount_install(pkgmgr_client *pc, const char *pkg_type,
			    const char *descriptor_path, const char *pkg_path,
			    const char *optional_data, pkgmgr_mode mode,
			    pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API uninstalls package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @param[in]	uid	the addressee user id of the instruction
 * @return	request_id (>0), error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_uninstall(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_mode mode,
				pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API moves installed package to SD card or vice versa.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	application package id
 * @param[in]	move_type		PM_MOVE_TO_INTERNAL or PM_MOVE_TO_SDCARD
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @param[in]	event_cb	user callback
 * @param[in]	data	user data
 * @param[in]	uid	the addressee user id of the instruction
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type,
				pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_move(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, pkgmgr_move_type move_type,
				pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API registers the update information of given packages
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	update_info	update information
 * @param[in]	uid	the addressee user id of the instruction
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_register_pkg_update_info(pkgmgr_client *pc,
				pkg_update_info_t *update_info);
int pkgmgr_client_usr_register_pkg_update_info(pkgmgr_client *pc,
				pkg_update_info_t *update_info, uid_t uid);

/**
 * @brief	This API unregisters update information of certain package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkgid	package id
 * @param[in]	uid	the addressee user id of the instruction
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_unregister_pkg_update_info(pkgmgr_client *pc, const char *pkgid);
int pkgmgr_client_usr_unregister_pkg_update_info(pkgmgr_client *pc,
				const char *pkgid, uid_t uid);

/**
 * @brief	This API unregister update information of all packages.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	uid	the addressee user id of the instruction
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR	general error
*/
int pkgmgr_client_unregister_all_pkg_update_info(pkgmgr_client *pc);
int pkgmgr_client_usr_unregister_all_pkg_update_info(pkgmgr_client *pc,
				uid_t uid);

/**
 * @brief	This API activates package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid);
int pkgmgr_client_usr_activate(pkgmgr_client *pc, const char *pkg_type,
				const char *pkgid, uid_t uid);

/**
 * @brief	This API activates multiple packages.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgids	array of package ids
 * @param[in]	n_pkgs	size of array
 * @param[in]	event_cb	user callback
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_packages(pkgmgr_client *pc, const char *pkg_type,
				const char **pkgids, int n_pkgs,
				pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_activate_packages(pkgmgr_client *pc, const char *pkg_type,
				const char **pkgids, int n_pkgs,
				pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API deactivates package.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid);
int pkgmgr_client_usr_deactivate(pkgmgr_client *pc, const char *pkg_type,
				 const char *pkgid, uid_t uid);

/**
 * @brief	This API deactivates multiple packages.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgids	array of package ids
 * @param[in]	n_pkgs	size of array
 * @param[in]	event_cb	user callback
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_packages(pkgmgr_client *pc, const char *pkg_type,
				 const char **pkgids, int n_pkgs,
				 pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_deactivate_packages(pkgmgr_client *pc, const char *pkg_type,
				 const char **pkgids, int n_pkgs,
				 pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief	This API deactivates app.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data);
int pkgmgr_client_usr_deactivate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API activates multiple apps.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appids	array of application ids
 * @param[in]	n_apps	size of array
 * @param[in]	app_event_cb	user callback
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_apps(pkgmgr_client *pc, const char **appids, int n_apps, pkgmgr_app_handler app_event_cb, void *data);
int pkgmgr_client_usr_activate_apps(pkgmgr_client *pc, const char **appids, int n_apps, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API deactivates multiple apps.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appids	array of application ids
 * @param[in]	n_apps	size of array
 * @param[in]	app_event_cb	user callback
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_apps(pkgmgr_client *pc, const char **appids, int n_apps, pkgmgr_app_handler app_event_cb, void *data);
int pkgmgr_client_usr_deactivate_apps(pkgmgr_client *pc, const char **appids, int n_apps, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API deactivates global app for user specified by uid.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_deactivate_global_app_for_uid(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API activates app.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data);
int pkgmgr_client_usr_activate_app(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API activates global app for user specified by uid.
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @param[in]	app_event_cb	user callback
 * @param[in]	uid	user id
 * @param[in]	data	user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_activate_global_app_for_uid(pkgmgr_client *pc, const char *appid, pkgmgr_app_handler app_event_cb, void *data, uid_t uid);

/**
 * @brief	This API deletes application's private data.
 *
 * This API is for package-manager client application.\n
 *
 * @remarks	You should call this function with regular uid
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	mode		installation mode  - PM_DEFAULT, PM_QUIET
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				const char *appid, pkgmgr_mode mode);
int pkgmgr_client_usr_clear_user_data(pkgmgr_client *pc, const char *pkg_type,
				const char *appid, pkgmgr_mode mode, uid_t uid);
/**
 * @brief	This API set status type to listen for the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	status_type	status type to listen
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_set_status_type(pkgmgr_client *pc, int status_type);

/**
 * @brief	This API request to listen the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_listen_status(pkgmgr_client *pc, pkgmgr_handler event_cb,
				    void *data);

/**
 * @brief	This API request to listen the pkgmgr's broadcasting about apps
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	event_cb	user callback
 * @param[in]	data		user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_listen_app_status(pkgmgr_client *pc, pkgmgr_app_handler event_cb,
				    void *data);

/**
 * @brief	This API request to stop listen the pkgmgr's broadcasting
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ERROR		internal error
*/
int pkgmgr_client_remove_listen_status(pkgmgr_client *pc);

/**
 * @brief	This API broadcasts pkgmgr's status
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid	package id
 * @param[in]	key		key to broadcast
 * @param[in]	val		value to broadcast
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
*/
int pkgmgr_client_broadcast_status(pkgmgr_client *pc, const char *pkg_type,
					 const char *pkgid,  const char *key,
					 const char *val);

/**
 * @brief	This API  gets the package's information.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkg_path		package file path to get infomation
 * @return	package entry pointer if success, NULL if fail\n
*/
pkgmgr_info *pkgmgr_client_check_pkginfo_from_file(const char *pkg_path);

/**
 * @brief	This API  get package information value
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkg_info			pointer for package info entry
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_client_free_pkginfo(pkgmgr_info *pkg_info);

/**
 * @brief	This API requests service
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	service_type		pkgmgr_request_service_type
 * @param[in]	service_mode		mode which is used for addtional mode selection
 * @param[in]	pc			pkgmgr_client
 * @param[in]	pkg_type		package type
 * @param[in]	pkgid			package id
 * @param[in]	custom_info		custom information which is used for addtional information
 * @param[in]	event_cb		user callback
 * @param[in]	data			user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_request_service(pkgmgr_request_service_type service_type, int service_mode,
					pkgmgr_client *pc, const char *pkg_type, const char *pkgid,
					const char *custom_info, pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_request_service(pkgmgr_request_service_type service_type, int service_mode,
					pkgmgr_client *pc, const char *pkg_type, const char *pkgid, uid_t uid,
					const char *custom_info, pkgmgr_handler event_cb, void *data);
/**
 * @brief	This API get package size
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc				pkgmgr_client
 * @param[in]	pkgid			package id
 * @param[in]	get_type		type for pkgmgr client request to get package size
 * @param[in]	event_cb		user callback
 * @param[in]	data			user data
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
*/
int pkgmgr_client_get_size(pkgmgr_client *pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data);
int pkgmgr_client_usr_get_size(pkgmgr_client *pc, const char *pkgid, pkgmgr_getsize_type get_type, pkgmgr_handler event_cb, void *data, uid_t uid);

/**
 * @brief		Gets the package size information.
 * @details		The package size info is asynchronously obtained by the specified callback function.
 *
 * @param[in] pc		The pointer to pkgmgr_client instance
 * @param[in] pkgid		The package ID
 * @param[in] result_cb	The asynchronous callback function to get the package size information
 * @param[in] user_data	User data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #PKGMGR_R_OK			Successful
 * @retval #PKGMGR_R_EINVAL		Invalid parameter
 * @retval #PKGMGR_R_ERROR		Internal error
 */
int pkgmgr_client_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb result_cb, void *user_data);
int pkgmgr_client_usr_get_package_size_info(pkgmgr_client *pc, const char *pkgid, pkgmgr_pkg_size_info_receive_cb result_cb, void *user_data, uid_t uid);

/**
 * @brief		Gets the sum of the entire package size information.
 * @details		The package size info is asynchronously obtained by the specified callback function.
 *
 * @param[in] pc		The pointer to pkgmgr_client instance
 * @param[in] result_cb	The asynchronous callback function to get the total package size information
 * @param[in] user_data	User data to be passed to the callback function
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #PKGMGR_R_OK			Successful
 * @retval #PKGMGR_R_EINVAL		Invalid parameter
 * @retval #PKGMGR_R_ERROR		Internal error
 */
int pkgmgr_client_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb result_cb, void *user_data);
int pkgmgr_client_usr_get_total_package_size_info(pkgmgr_client *pc, pkgmgr_total_pkg_size_info_receive_cb result_cb, void *user_data, uid_t uid);

/**
 * @brief		Gets size information of each installed packages.
 * @details		The package size info is asynchronously obtained by callback function added by pkgmgr_client_listen_status.
 *
 * @return 0 on success, otherwise a negative error value
 * @retval #PKGMGR_R_OK			Successful
 * @retval #PKGMGR_R_EINVAL		Invalid parameter
 * @retval #PKGMGR_R_ECOMM		communication error
 * @retval #PKGMGR_R_ERROR		Internal error
 */
int pkgmgr_client_request_size_info(void);
int pkgmgr_client_usr_request_size_info(uid_t uid);

/**
 * @brief	This API removes cache directories
 *
 * This API is for package-manager client application.\n
 *
 * @remarks	You should call this function with regular uid
 * @param[in]	pkgid			package id
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_clear_cache_dir(const char *pkgid);
int pkgmgr_client_usr_clear_cache_dir(const char *pkgid, uid_t uid);

/**
 * @brief	This API removes all cache directories
 *
 * This API is for package-manager client application.\n
 *
 * @remarks	You should call this function with regular uid
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ERROR	internal error
*/
int pkgmgr_client_clear_all_cache_dir(void);
int pkgmgr_client_usr_clear_all_cache_dir(uid_t uid);

/**
 * @brief	Generates request for getting license
 *
 * This API generates request for getting license.\n
 *
 * @remarks	You must release @a req_data and @a license_url by yourself.
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	resp_data	The response data string of the purchase request
 * @param[out]	req_data	License request data
 * @param[out]	license_url	License acquisition url data
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV	privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_generate_license_request(pkgmgr_client *pc, const char *resp_data, char **req_data, char **license_url);

/**
 * @brief	Registers encrypted license
 *
 * This API registers encrypted license.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	resp_data	The response data string of the purchase request
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_register_license(pkgmgr_client *pc, const char *resp_data);

/**
 * @brief	Decrypts contents which is encrypted
 *
 * This API decrypts contents which is encrypted.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	drm_file_path	The pointer to pkgmgr_client instance
 * @param[in]	decrypted_file_path	The pointer to pkgmgr_client instance
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @retval	PKGMGR_R_ESYSTEM	severe system error
 */
int pkgmgr_client_decrypt_package(pkgmgr_client *pc, const char *drm_file_path, const char *decrypted_file_path);

/**
 * @brief	This API is enabled the splash screen
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK		success
 * @retval	PKGMGR_R_EINVAL		invalid argument
 * @retval	PKGMGR_R_ECOMM		communication error
 * @retval	PKGMGR_R_ENOMEM		out of memory
 */
int pkgmgr_client_enable_splash_screen(pkgmgr_client *pc, const char *appid);
int pkgmgr_client_usr_enable_splash_screen(pkgmgr_client *pc, const char *appid, uid_t uid);

/**
 * @brief	This API is disabled the splash screen
 *
 * This API is for package-manager client application.\n
 *
 * @param[in]	pc	pkgmgr_client
 * @param[in]	appid	applicaiton id
 * @return	request_id (>0) if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK		success
 * @retval	PKGMGR_R_EINVAL		invalid argument
 * @retval	PKGMGR_R_ECOMM		communication error
 * @retval	PKGMGR_R_ENOMEM		out of memory
 */
int pkgmgr_client_disable_splash_screen(pkgmgr_client *pc, const char *appid);
int pkgmgr_client_usr_disable_splash_screen(pkgmgr_client *pc, const char *appid, uid_t uid);

/**
 * @brief	Set restriction mode
 *
 * This API set restriction mode bit.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	mode	restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_set_restriction_mode(pkgmgr_client *pc, int mode);
int pkgmgr_client_usr_set_restriction_mode(pkgmgr_client *pc, int mode, uid_t uid);

/**
 * @brief	Unset restriction mode
 *
 * This API unset restriction mode bit.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	mode	restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_unset_restriction_mode(pkgmgr_client *pc, int mode);
int pkgmgr_client_usr_unset_restriction_mode(pkgmgr_client *pc, int mode, uid_t uid);

/**
 * @brief	Get restriction mode
 *
 * This API gets restriction mode bit.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[out]	mode	restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_get_restriction_mode(pkgmgr_client *pc, int *mode);
int pkgmgr_client_usr_get_restriction_mode(pkgmgr_client *pc, int *mode, uid_t uid);

/**
 * @brief	Set restriction mode bit for package specified.
 * @details	You can combine multiple status using OR operation which you want to restrict.
 *
 * This API sets restriction bit for pkg operation to not allow user to do it.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	pkgid  to be restricted
 * @param[in]  mode restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode);
int pkgmgr_client_usr_set_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid);

/**
 * @brief	Unset restriction mode bit for package specified
 * @details	You can combine multiple status using OR operation which you want to unset
 *
 * This API unsets restriction bit to remove restriction of pkg operation.
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	pkg id to be remove in restriction.
 * @param[in]  mode restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode);
int pkgmgr_client_usr_unset_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int mode, uid_t uid);

/**
 * @brief	Get restriction bit of package operation
 *
 * This API gets restriction bit for restricted package operation.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	pkg id to be remove in restriction.
 * @param[out]	mode	restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 * @retval	PKGMGR_R_EPRIV privilege denied
 * @see pkgmgr_restriction_mode
 */
int pkgmgr_client_get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int *mode);
int pkgmgr_client_usr_get_pkg_restriction_mode(pkgmgr_client *pc, const char *pkgid, int *mode, uid_t uid);

/**
 * @brief	Change application's label
 *
 * This API sets label of application specified.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	appid	app id to be changed.
 * @param[in]	label	application's label to change.
 * @param[out]	mode	restriction mode bit
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 * @retval	PKGMGR_R_ECOMM	communication error
 */
int pkgmgr_client_set_app_label(pkgmgr_client *pc, char *appid, char *label);
int pkgmgr_client_usr_set_app_label(pkgmgr_client *pc, char *appid, char *label, uid_t uid);

/**
 * @brief	Set debug mode
 *
 * This API sets debug mode value for request.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	debug_mode	indicates the request is debug mode or not
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 */
int pkgmgr_client_set_debug_mode(pkgmgr_client *pc, bool debug_mode);

/**
 * @brief	Migrate legacy external image which is generated under 3.0
 *
 * This API request the migration of external image.\n
 *
 * @param[in]	pc	The pointer to pkgmgr_client instance
 * @param[in]	pkgid	pkg id which have legacy image
 * @return	0 if success, error code(<0) if fail\n
 * @retval	PKGMGR_R_OK	success
 * @retval	PKGMGR_R_EINVAL	invalid argument
 */
int pkgmgr_client_usr_migrate_external_image(pkgmgr_client *pc, const char *pkgid, uid_t uid);

/** @} */


#ifdef __cplusplus
}
#endif
#endif				/* __PKG_MANAGER_H__ */
/**
 * @}
 * @}
 */

