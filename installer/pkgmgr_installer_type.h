/*
 * slp-pkgmgr
 *
 * Copyright (c) 2017 Samsung Electronics Co., Ltd. All rights reserved.
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


#ifndef __PKGMGR_INSTALLER_TYPE_H__
#define __PKGMGR_INSTALLER_TYPE_H__

/**
 * @file	pkgmgr_installer_type.h
 * @brief	This file declares some types for pkgmgr_installer
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief listening event type in pkgmgr.
 */
#define PKGMGR_INSTALLER_START_KEY_STR           "start"
#define PKGMGR_INSTALLER_END_KEY_STR             "end"
#define PKGMGR_INSTALLER_ERROR_KEY_STR           "error"
#define PKGMGR_INSTALLER_APPID_KEY_STR           "appid"
#define PKGMGR_INSTALLER_INSTALL_PERCENT_KEY_STR "install_percent"
#define PKGMGR_INSTALLER_GET_SIZE_KEY_STR        "get_size"
#define PKGMGR_INSTALLER_CLEAR_CACHE_KEY_STR     "clear_cache"

#define PKGMGR_INSTALLER_INSTALL_EVENT_STR       "install"
#define PKGMGR_INSTALLER_UNINSTALL_EVENT_STR     "uninstall"
#define PKGMGR_INSTALLER_CLEAR_EVENT_STR         "clear"
#define PKGMGR_INSTALLER_MOVE_EVENT_STR          "move"
#define PKGMGR_INSTALLER_UPGRADE_EVENT_STR       "update"
#define PKGMGR_INSTALLER_OK_EVENT_STR            "ok"
#define PKGMGR_INSTALLER_FAIL_EVENT_STR          "fail"
#define PKGMGR_INSTALLER_UNKNOWN_EVENT_STR       ""

#define PKGMGR_INSTALLER_APP_DISABLE_EVENT_STR         "disable_app"
#define PKGMGR_INSTALLER_APP_ENABLE_EVENT_STR          "enable_app"

#define PKGMGR_INSTALLER_APP_DISABLE_SPLASH_SCREEN_EVENT_STR         "disable_app_splash_screen"
#define PKGMGR_INSTALLER_APP_ENABLE_SPLASH_SCREEN_EVENT_STR          "enable_app_splash_screen"

/**
 * Request type.
 */
enum {
	PKGMGR_REQ_PERM = -1,
	PKGMGR_REQ_INVALID = 0,
	PKGMGR_REQ_INSTALL = 1,
	PKGMGR_REQ_UNINSTALL = 2,
	PKGMGR_REQ_CLEAR = 3,
	PKGMGR_REQ_MOVE = 4,
	PKGMGR_REQ_RECOVER = 5,
	PKGMGR_REQ_REINSTALL = 6,
	PKGMGR_REQ_GETSIZE = 7,
	PKGMGR_REQ_UPGRADE = 8,
	PKGMGR_REQ_SMACK = 9,
	PKGMGR_REQ_MANIFEST_DIRECT_INSTALL = 10,
	PKGMGR_REQ_ENABLE_APP = 11,
	PKGMGR_REQ_DISABLE_APP = 12,
	PKGMGR_REQ_ENABLE_APP_SPLASH_SCREEN = 13,
	PKGMGR_REQ_DISABLE_APP_SPLASH_SCREEN = 14,
	PKGMGR_REQ_MOUNT_INSTALL = 15,
	PKGMGR_REQ_DISABLE_PKG = 16,
	PKGMGR_REQ_ENABLE_PKG = 17,
	PKGMGR_REQ_MIGRATE_EXTIMG = 18,
	PKGMGR_REQ_RECOVER_DB = 19
};

enum {
	PKGMGR_INSTALLER_EINVAL = -2,		/**< Invalid argument */
	PKGMGR_INSTALLER_ERROR = -1,		/**< General error */
	PKGMGR_INSTALLER_EOK = 0		/**< General success */
};

typedef enum {
	PM_SET_AUTHOR_ROOT_CERT = 0,
	PM_SET_AUTHOR_INTERMEDIATE_CERT = 1,
	PM_SET_AUTHOR_SIGNER_CERT = 2,
	PM_SET_DISTRIBUTOR_ROOT_CERT = 3,
	PM_SET_DISTRIBUTOR_INTERMEDIATE_CERT = 4,
	PM_SET_DISTRIBUTOR_SIGNER_CERT = 5,
	PM_SET_DISTRIBUTOR2_ROOT_CERT = 6,
	PM_SET_DISTRIBUTOR2_INTERMEDIATE_CERT = 7,
	PM_SET_DISTRIBUTOR2_SIGNER_CERT = 8,
} pkgmgr_instcert_type;

typedef enum {
	PM_PRIVILEGE_UNKNOWN = -1,
	PM_PRIVILEGE_UNTRUSTED = 0,
	PM_PRIVILEGE_PUBLIC = 1,
	PM_PRIVILEGE_PARTNER = 2,
	PM_PRIVILEGE_PLATFORM = 3
} pkgmgr_privilege_level;

#ifdef __cplusplus
}
#endif

#endif	/* __PKGMGR_INSTALLER_TYPE_H__ */

