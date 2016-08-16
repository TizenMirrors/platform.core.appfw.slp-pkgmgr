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


#ifndef __COMM_CLIENT_H__
#define __COMM_CLIENT_H__

#include <glib.h>

#include "package-manager.h"

typedef struct comm_client comm_client;
typedef void (*status_cb) (void *cb_data, uid_t target_uid, const char *req_id,
			   const char *pkg_type, const char *pkgid,
			   const char *appid,    const char *key,
			   const char *val);

comm_client *comm_client_new(client_type type);
int comm_client_free(comm_client *cc);

int comm_client_request(comm_client *cc, const char *method, GVariant *params, GVariant **result);

int comm_client_set_status_callback(int comm_status_type, comm_client *cc, status_cb cb, void *cb_data);

#endif				/* __COMM_CLIENT_H__ */
