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


#ifndef __PKGMGR_INSTALLER_H__
#define __PKGMGR_INSTALLER_H__

#include <sys/types.h>

#include "package-manager.h"
#include "pkgmgr_installer_type.h"

/**
 * @file pkgmgr_installer.h
 * @author Youmin Ha <youmin.ha@samsung.com>
 * @version 0.1
 * @brief    This file declares API of pkgmgr_installer
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * pkgmgr_installer is an opaque type for an object
 */
typedef struct pkgmgr_installer pkgmgr_installer;
typedef void *pkgmgr_instcertinfo_h;

/**
 * @brief	Create a pkgmgr_installer object.
 * @pre		None
 * @post	pkgmgr_installer object must be freed.
 * @see		pkgmgr_installer_free
 * @return	pkgmgr_installer object
 * @retval	NULL	on failure creating an object
 * @remark	None
@code
#include <pkgmgr_installer.h>
pkgmgr_installer *pi = pkgmgr_installer_new();
pkgmgr_installer_free(pi);
@endcode
 */
pkgmgr_installer *pkgmgr_installer_new(void);

/**
 * @brief	Create a pkgmgr_installer object in offline mode
 * @pre		None
 * @post	pkgmgr_installer object must be freed.
 * @see		pkgmgr_installer_free
 * @return	pkgmgr_installer object
 * @retval	NULL	on failure creating an object
 * @remark	None
@code
#include <pkgmgr_installer.h>
pkgmgr_installer *pi = pkgmgr_installer_offline_new();
pkgmgr_installer_free(pi);
@endcode
 */
pkgmgr_installer *pkgmgr_installer_offline_new(void);

/**
	@brief		Free a pkgmgr_installer object
	@pre		pi must be a valid object.
	@post		None
	@see		pkgmgr_installer_new
	@param[in]	pi	A pkgmgr_installer object
	@return		Operation result
	@retval		0	on success
	@retval		-errno	on error
	@remark		None
	@code
#include <pkgmgr_installer.h>
pkgmgr_installer *pi = pkgmgr_installer_new();
pkgmgr_installer_free(pi);
	@endcode
 */
int pkgmgr_installer_free(pkgmgr_installer *pi);

/**
	@brief		Receive a request from argv
	@pre		None
	@post		pkgmgr_installer_get_*(), pkgmgr_installer_is_quiet() can be called.
	@see		pkgmgr_installer_get_request_type, pkgmgr_installer_get_request_info, pkgmgr_installer_get_session_id, pkgmgr_installer_is_quiet
	@param[in]	pi	a pkgmgr_installer object
	@param[in]	argc	argc from system
	@param[in]	argv	argv from system
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r;

	pi = pkgmgr_installer_new();
	int r = pkgmgr_installer_receive_request(pi, argc, argv);
	pkgmgr_installer_free(pi);

	return 0;
}
	@endcode
 */
int pkgmgr_installer_receive_request(pkgmgr_installer *pi,
				     const int argc, char **argv);

/**
	@brief		Get request type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Request type (One of PKGMGR_REQ_* enum values)
	@remark		None
	@code
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	switch(pkgmgr_installer_get_request_type(pi)) {
		case PKGMGR_REQ_PERM:
			// Do error processing
			break;
		case PKGMGR_REQ_INVALID:
			// Do error processing
			r = -1;
			break;
		case PKGMGR_REQ_INSTALL:
			// Do install processing
			break;
		case PKGMGR_REQ_UNINSTALL:
			// Do uninstall processing
			break;
		case PKGMGR_REQ_RECOVER:
			// Do recovere processing
			break;
		case PKGMGR_REQ_REINSTALL:
			// Do reinstall processing
			break;
		default:
			goto CLEANUP_END;
	}
CLEANUP_END:
	pkgmgr_installer_free(pi);

	return r;
}
	@endcode
 */
int pkgmgr_installer_get_request_type(pkgmgr_installer *pi);

/**
	@brief		Get uid
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Uid info.
	@retval		NULL	on function failure
	@remark		Returned uid must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	uid_t uid;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	uid = pkgmgr_installer_get_uid(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
uid_t pkgmgr_installer_get_uid(pkgmgr_installer *pi);

/**
	@brief		Get request info
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Request info. When PKGMGR_REQ_INSTALL, this is a package file path to be installed. When PKGMGR_REQ_UNINSTALL, this is a package name to be uninstalled.
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *req_info = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	req_info = (char *) pkgmgr_installer_get_request_info(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
const char *pkgmgr_installer_get_request_info(pkgmgr_installer *pi);

/**
	@brief		Get request info at specific position
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@see		pkgmgr_installer_get_request_info_count
	@param[in]	pi	pkgmgr_installer object
	@return		Request info. When PKGMGR_REQ_INSTALL, this is a package file path to be installed. When PKGMGR_REQ_UNINSTALL, this is a package name to be uninstalled.
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *req_info = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	req_info = (char *) pkgmgr_installer_get_request_info_at(pi, 1);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
const char *pkgmgr_installer_get_request_info_at(pkgmgr_installer *pi,
		int at);

/**
	@brief		Get the number of request info
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		The number of request info.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int n;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	n = pkgmgr_installer_get_request_info_count(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_request_info_count(pkgmgr_installer *pi);

/**
	@brief		Get TEP path
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		TEP path if exists
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *tep_path = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	tep_path = (char *) pkgmgr_installer_get_tep_path(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_tep_path(pkgmgr_installer *pi);

/**
	@brief		Get TEP move type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		integer value indicates tep move type(0: copy TEP file / 1: move TEP file)
	@retval		0	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int tep_move_type = -1;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	tep_move_type = pkgmgr_installer_get_tep_move_type(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
int pkgmgr_installer_get_tep_move_type(pkgmgr_installer *pi);

/**
	@brief		Get session ID for a certain session
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		A session ID
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	session_id = (char *) pkgmgr_installer_get_session_id(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_session_id(pkgmgr_installer *pi);

/**
	@brief		Get a license path
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		license path
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *license_path = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	session_id = (char *) pkgmgr_installer_get_license_path(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_license_path(pkgmgr_installer *pi);

/**
	@brief		Get a optional data
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		optional data
	@retval		NULL	on function failure
	@remark		Returned string must not be modified.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *optional_data = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	optional_data = (char *) pkgmgr_installer_get_optional_data(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
@endcode
 */
const char *pkgmgr_installer_get_optional_data(pkgmgr_installer *pi);

/**
	@brief		Get if a request is with quite mode or not
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not quiet mode
	@retval		1 if a request is quiet mode
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	if(pkgmgr_installer_is_quiet(pi)) {
		// Do quiet mode work...
	} else {
		// Do normal mode work...
	}

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_is_quiet(pkgmgr_installer *pi);

/**
	@brief		Get move type
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		enum value of move type
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	move_type = pkgmgr_installer_get_move_type(pi);

	//Do Something

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_move_type(pkgmgr_installer *pi);

/**
	@brief		Get caller package id
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		enum value of move type
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *pkgid = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	pkgid = (char *) pkgmgr_installer_get_caller_pkgid(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
const char *pkgmgr_installer_get_caller_pkgid(pkgmgr_installer *pi);

/**
	@brief		Get if the request is for preload app or not
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not for preload
	@retval		1 if a request is for preload
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int is_preload = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	is_preload = pkgmgr_installer_get_is_preload(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_is_preload(pkgmgr_installer *pi);
int pkgmgr_installer_get_is_preload_rw(pkgmgr_installer *pi);

/**
	@brief		Get if the request is for force-removal
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not for force-removal
	@retval		1 if a request is for force-removal
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int force_remove = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	force_remove = pkgmgr_installer_get_force_removal(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_force_removal(pkgmgr_installer *pi);
int pkgmgr_installer_get_no_removal(pkgmgr_installer *pi);

/**
	@brief		Get if the request is for keep-rwdata
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not for keep-rwdata
	@retval		1 if a request is for keep-rwdata
	@remark		Keep RW-data of updated RO pkg.
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int force_remove = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	force_remove = pkgmgr_installer_get_keep_rwdata(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_keep_rwdata(pkgmgr_installer *pi);

/**
	@brief		Get if the request is for partial-rw
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not for partial-rw
	@retval		1 if a request is for partial-rw
	@remark		For install/update/uninstall of stubs of RO pkg
			on RW partitions
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int force_remove = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	force_remove = pkgmgr_installer_get_partial_rw(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_get_partial_rw(pkgmgr_installer *pi);

/**
	@brief		Get debug mode value
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not debug mode
	@retval		1 if a request is debug mode
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int force_remove = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	force_remove = pkgmgr_installer_get_debug_mode(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
*/
int pkgmgr_installer_get_debug_mode(pkgmgr_installer *pi);

/**
	@brief		Get skip_check_reference value
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request does not skip checking reference
	@retval		1 if a request skip checking reference
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int check_reference = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	check_reference = pkgmgr_installer_get_skip_check_reference(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
*/
int pkgmgr_installer_get_skip_check_reference(pkgmgr_installer *pi);

/**
	@brief		Get skip optimization value
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a request is not debug mode
	@retval		1 if a request is debug mode
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int skip_optimization = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	skip_optimization = pkgmgr_installer_get_skip_optimization(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
*/
int pkgmgr_installer_get_skip_optimization(pkgmgr_installer *pi);

/**
	@brief		Get recovery cleanup mode
	@pre		pkgmgr_installer_receive_request() must be called.
	@post		None
	@see		pkgmgr_installer_receive_request
	@param[in]	pi	pkgmgr_installer object
	@return		Operation result
	@retval		0 if a recovery cleanup flag has not set
	@retval		1 if a recovery cleanup flag has set
	@remark		None
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	int recovery_cleanup = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}
	recovery_cleanup = pkgmgr_installer_get_recovery_cleanup(pi);

	// Do something...

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
*/
int pkgmgr_installer_get_recovery_cleanup(pkgmgr_installer *pi);

/**
	@brief		Send a app status signal
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	appid	application id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@code
#include <pkgmgr_installer.h>
void send_app_singal(uid_t uid, int request_type, int req_id,
		const char *pkg_type, const char *pkgid, const char *appid,
		const char *key, const char *val)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;

	if (pkgmgr_installer_set_uid(pi, uid))
		goto CLEANUP_RET;
	if (pkgmgr_installer_set_request_type(pi, request_type))
		goto CLEANUP_RET;
	if ((pkgmgr_installer_set_session_id(pi, req_id))
		goto CLEANUP_RET;
	pkgmgr_installer_send_app_signal(pi, pkg_type, pkgid, appid, key, val);

}
	@endcode
 */
int pkgmgr_installer_send_app_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *appid,
			     const char *key, const char *val);

/**
	@brief		Send a process status signal
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@remark		If pkgmgr_installer_receive_request() is not called, the session ID will be null string (=="/0").
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	// Do something...
	pkgmgr_installer_send_signal(pi,
	 "deb", "org.tizen.foo", "install_percent", "100");
	// A sample signal

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_send_signal(pkgmgr_installer *pi,
				 const char *pkg_type,
				 const char *pkgid, const char *key,
				 const char *val);

/**
	@brief		Send a app status signal
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	uid	user id
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	appid	application id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success, otherwise -1
	@remark		If pkgmgr_installer_receive_request() is not called, the session ID will be null string (=="/0").
 */
int pkgmgr_installer_send_app_signal_for_uid(pkgmgr_installer *pi,
				 uid_t uid,
				 const char *pkg_type,
				 const char *pkgid,
				 const char *appid,
				 const char *key, const char *val);

/**
	@brief		Send a process status signal
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	uid	user id
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success, otherwise -1
	@remark		If pkgmgr_installer_receive_request() is not called, the session ID will be null string (=="/0").
 */
int pkgmgr_installer_send_signal_for_uid(pkgmgr_installer *pi,
				 uid_t uid,
				 const char *pkg_type,
				 const char *pkgid, const char *key,
				 const char *val);

/**
	@brief		Send a signal which indicates application is being uninstalled
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
	@code
#include <pkgmgr_installer.h>
int main(int argc, char **argv)
{
	pkgmgr_installer *pi;
	int r = 0;
	char *session_id = NULL;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;
	if(pkgmgr_installer_receive_request(pi, argc, argv)) {
		r = -1;
		goto CLEANUP_RET;
	}

	// Do something...
	pkgmgr_installer_send_app_uninstall_signal(pi,
	 "tpk", "org.tizen.foo");
	// A sample signal

	pkgmgr_installer_free(pi);
	return r;
}
	@endcode
 */
int pkgmgr_installer_send_app_uninstall_signal(pkgmgr_installer *pi,
			     const char *pkg_type,
			     const char *pkgid,
			     const char *val);

/**
	@brief		Send a signal which indicates application is being uninstalled
	@pre		None
	@post		None
	@see		None
	@param[in]	pi	pkgmgr_installer object
	@param[in]	uid	user id
	@param[in]	pkg_type	package type: "deb", "jar", "wgt", ...
	@param[in]	pkgid	package id
	@param[in]	key			Signal key
	@param[in]	val			Signal value
	@return		Operation result
	@retval		0 on success
	@retval		-errno on failure
 */
int pkgmgr_installer_send_app_uninstall_signal_for_uid(
		pkgmgr_installer *pi, uid_t uid, const char *pkg_type,
		const char *pkgid, const char *val);

/**
 * @brief	This API sets the uid of given pkgmgr_installer.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]pi				pointer to pkgmgr_installer
 * @param[in]uid				uid
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_uid(pkgmgr_installer *pi, uid_t uid);

/**
 * @brief	This API sets the requst info of given pkgmgr_installer.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]pi				pointer to pkgmgr_installer
 * @param[in]	request_type				request type
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_request_type(pkgmgr_installer *pi, int request_type);

/**
 * @brief	This API sets the session ID.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pi				pointer to pkgmgr_installer
 * @param[in]	session_id				session ID to be set
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_session_id(pkgmgr_installer *pi, const char *session_id);

/**
 * @brief	This API creates the certinfo handle.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[out]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_create_certinfo_set_handle(pkgmgr_instcertinfo_h *handle);

/**
 * @brief	This API sets cert value for corresponding cert type.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to cert info handle
 * @param[in]	cert_type			enum value for certificate type
 * @param[in]	cert_value			certificate value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_cert_value(pkgmgr_instcertinfo_h handle, pkgmgr_instcert_type cert_type, char *cert_value);

/**
 * @brief	This API saves cert info in DB.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkgid				package ID
 * @param[in]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_save_certinfo(const char *pkgid, pkgmgr_instcertinfo_h handle, uid_t uid);

/**
 * @brief	This API destroys cert info handle freeing all resources.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	handle				pointer to cert info handle
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_destroy_certinfo_set_handle(pkgmgr_instcertinfo_h handle);

/**
 * @brief	This API deletes cert info from DB. To be used to cleanup info upon pkg uninstallation
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]	pkgid				package ID
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_delete_certinfo(const char *pkgid);

/**
 * @brief	This API sets privilege level for pkgmgr_installer_info
 *
 *              This API is for installer backend.\n
 *
 * @param[in]	level				pkgmgr_privilege_level
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_privilege_level(pkgmgr_privilege_level level);

/**
 * @brief	This API converts error code to string
 *
 *              This API is for installer backend.\n
 *
 * @param[in]	error_code			pkgmgr installer error code
 * @return	error string\n
*/
const char *pkgmgr_installer_error_to_string(int error_code);

/**
 * @brief	This API adds pkg to be send at once
 *
 *              This API is for installer backend.\n
 *
 * @param[in]	pi				pointer to pkgmgr_installer
 * @param[in]	pkgid				package ID
 * @param[in]	pkg_type			type of package
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_add_pkg(pkgmgr_installer *pi,
		const char *pkgid, const char *pkg_type);

/**
 * @brief	This API sends signals with packages already added
 *
 *              This API is for installer backend.\n
 *
 * @param[in]	pi			pointer to pkgmgr_installer
 * @param[in]	key			Signal key
 * @param[in]	val			Signal value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_send_signals(pkgmgr_installer *pi,
		const char *key, const char *val);

/**
 * @brief	This API sends signals to certain uid with packages already added
 *
 *              This API is for installer backend.\n
 *
 * @param[in]	pi			pointer to pkgmgr_installer
 * @param[in]	uid			user id
 * @param[in]	key			Signal key
 * @param[in]	val			Signal value
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_send_signals_for_uid(pkgmgr_installer *pi, uid_t uid,
		const char *key, const char *val);

/**
 * @brief	This API sets is_upgrade_flag of given pkgmgr_installer.
 *
 *              This API is for package-manager client application.\n
 *
 * @param[in]pi				pointer to pkgmgr_installer
 * @param[in]is_upgrade			is_upgrade flag
 * @return	0 if success, error code(<0) if fail\n
*/
int pkgmgr_installer_set_is_upgrade(pkgmgr_installer *pi, int is_upgrade);

/**
	@brief		Send a signal of the resource copy event status
	@pre		None
	@post		None
	@see		None
	@param[in]	pi		pkgmgr_installer object
	@param[in]	pkgid		package id
	@param[in]	status		event status
	@param[in]	event_info	event info handle
	@return		Operation result
	@retval		0 on success, otherwise -1
	@code
#include <pkgmgr_installer.h>
void send_res_singal(uid_t uid, int request_type, const char *session_id,
		const char *pkgid, const char *status,
		pkgmgr_res_event_info *event_info)
{
	pkgmgr_installer *pi;
	int r = 0;

	pi = pkgmgr_installer_new();
	if(!pi) return -1;

	if (pkgmgr_installer_set_uid(pi, uid))
		goto CLEANUP_RET;
	if (pkgmgr_installer_set_request_type(pi, request_type))
		goto CLEANUP_RET;
	if ((pkgmgr_installer_set_session_id(pi, session_id))
		goto CLEANUP_RET;
	pkgmgr_installer_send_res_signal(pi, pkgid, status, event_info);

}
	@endcode
 */
int pkgmgr_installer_send_res_signal(pkgmgr_installer *pi,
		const char *pkgid, const char *status,
		pkgmgr_res_event_info *event_info);

/**
	@brief		Send a signal of the resource copy event status
	@pre		None
	@post		None
	@see		None
	@param[in]	pi		pkgmgr_installer object
	@param[in]	uid		user id
	@param[in]	pkgid		package id
	@param[in]	status		event status
	@param[in]	event_info	event info handle
	@return		Operation result
	@retval		0 on success, otherwise -1
 */
int pkgmgr_installer_send_res_signal_for_uid(pkgmgr_installer *pi,
		uid_t uid, const char *pkgid, const char *status,
		pkgmgr_res_event_info *event_info);

#ifdef __cplusplus
}
#endif

#endif				/* __PKGMGR_INSTALLER_H__ */

