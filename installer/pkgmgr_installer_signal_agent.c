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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <pwd.h>

#include <glib.h>
#include <glib-unix.h>
#include <gio/gio.h>
#include <systemd/sd-daemon.h>

#include <dlog.h>

#include "pkgmgr_installer_config.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "PKGMGR_INSTALLER_SIGNAL_AGENT"

#define BUFMAX 4096
#define PWBUFSIZE sysconf(_SC_GETPW_R_SIZE_MAX)
#define APPFW_USERNAME "app_fw"

static int server_fd;
static GMainLoop *loop;
static guint sid;
static guint tid;
static GDBusConnection *conn;

static int __create_server_socket(const char *path)
{
	int r;
	int fd;
	struct sockaddr_un sa;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		LOGE("socket create failed: %d", errno);
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);

	r = unlink(sa.sun_path);
	if (r == -1 && errno != ENOENT) {
		LOGE("unlink(%s) failed: %d", sa.sun_path, errno);
		close(fd);
		return -1;
	}

	r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	if (r == -1) {
		LOGE("bind(%s) failed: %d", sa.sun_path, errno);
		close(fd);
		return -1;
	}

	r = chmod(sa.sun_path, 0660);
	if (r == -1)
		LOGW("chmod(%s) failed: %d", sa.sun_path, errno);

	r = listen(fd, SOMAXCONN);
	if (r == -1) {
		LOGE("listen(%s) failed: %d", sa.sun_path, errno);
		close(fd);
		return -1;
	}

	return fd;
}

static int __get_server_socket(const char *path)
{
	int i;
	int n;
	int r;
	int fd = -1;

	n = sd_listen_fds(0);
	if (n < 0) {
		LOGE("sd_listen_fds: %d", n);
		return -1;
	} else if (n == 0) {
		return __create_server_socket(path);
	}

	for (i = SD_LISTEN_FDS_START; i < SD_LISTEN_FDS_START + n; i++) {
		r = sd_is_socket_unix(i, SOCK_STREAM, -1, path, 0);
		if (r > 0) {
			fd = i;
			break;
		}
	}

	if (fd == -1) {
		LOGE("socket is not passed, create server socket");
		return __create_server_socket(path);
	}

	return fd;
}

static void __emit_signal(const char *name, GVariant *gv)
{
	GError *err = NULL;

	if (g_dbus_connection_emit_signal(conn, NULL,
				PKGMGR_INSTALLER_DBUS_OBJECT_PATH,
				PKGMGR_INSTALLER_DBUS_INTERFACE,
				name, gv, &err) != TRUE) {
		LOGE("g_dbus_connection_emit_signal failed: %s", err->message);
		g_error_free(err);
	}
}

static gboolean __quit(gpointer user_data)
{
	g_main_loop_quit(loop);
	return FALSE;
}

static int __check_authority(int fd)
{
	int r;
	struct ucred cr;
	socklen_t len;
	struct passwd pwd;
	struct passwd *pwd_r;
	char buf[PWBUFSIZE];

	len = sizeof(struct ucred);
	r = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
	if (r != 0) {
		LOGE("getsockopt failed: %d", errno);
		return -1;
	}

	/* allow root user */
	if (cr.uid == 0)
		return 0;

	r = getpwuid_r(cr.uid, &pwd, buf, sizeof(buf), &pwd_r);
	if (r != 0 || pwd_r == NULL) {
		LOGE("getpwuid failed: %d", r);
		return -1;
	}

	/* only app_fw user can send signal to agent */
	if (strcmp(pwd_r->pw_name, APPFW_USERNAME) != 0) {
		LOGE("unauthorized client");
		return -1;
	}

	return 0;
}

/**
 * packet format:
 * +----------------+-------------+-----------+-------------------+
 * |signal name size|GVariant size|signal name|serialized GVariant|
 * +----------------+-------------+-----------+-------------------+
 */
static gboolean __handle_signal(gint fd, GIOCondition cond, gpointer user_data)
{
	int r;
	unsigned char buf[BUFMAX];
	int clifd;
	struct sockaddr_un sa;
	socklen_t s = sizeof(sa);
	size_t type_len;
	char *type_name;
	gsize data_len;
	gpointer data;
	GVariant *gv;

	clifd = accept(fd, (struct sockaddr *)&sa, &s);
	if (clifd == -1) {
		LOGE("accept failed: %d", errno);
		return FALSE;
	}

	if (__check_authority(clifd)) {
		close(clifd);
		return TRUE;
	}

	r = recv(clifd, buf, sizeof(size_t) + sizeof(gsize), 0);
	if (r < 0) {
		LOGE("recv failed: %d", errno);
		close(clifd);
		return FALSE;
	} else if (r == 0) {
		LOGE("client fd already closed");
		close(clifd);
		return FALSE;
	}

	memcpy(&type_len, buf, sizeof(size_t));
	memcpy(&data_len, buf + sizeof(size_t), sizeof(gsize));

	if ((type_len + data_len) > BUFMAX) {
		LOGE("received size is too large: %zu %zu", type_len, data_len);
		close(clifd);
		return FALSE;
	}

	r = recv(clifd, buf, type_len + data_len, 0);
	if (r < 0) {
		LOGE("recv failed: %d", errno);
		close(clifd);
		return FALSE;
	} else if (r == 0) {
		LOGE("client fd already closed");
		close(clifd);
		return FALSE;
	}

	if (type_len == 0) {
		LOGE("invalid type_len");
		close(clifd);
		return FALSE;
	}

	/* get signal name (including terminating null byte) */
	type_name = malloc(type_len);
	memcpy(type_name, buf, type_len);

	/* get data */
	data = malloc(data_len);
	memcpy(data, buf + type_len, data_len);

	/* floating type GVariant instance */
	gv = g_variant_new_from_data(G_VARIANT_TYPE("(usa(sss)ss)"), data,
			data_len, TRUE, NULL, NULL);
	__emit_signal(type_name, gv);

	free(data);
	free(type_name);
	close(clifd);

	/* renew timeout */
	g_source_remove(tid);
	tid = g_timeout_add_seconds(10, __quit, NULL);

	return TRUE;
}

static int __init(void)
{
	char path[PATH_MAX];
	GError *err = NULL;

	snprintf(path, sizeof(path), "/run/pkgmgr/agent/%d", getuid());
	server_fd = __get_server_socket(path);
	if (server_fd < 0) {
		LOGE("server init failed");
		return -1;
	}

	conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
	if (conn == NULL) {
		LOGE("g_bus_get_sync failed: %s", err->message);
		g_error_free(err);
		close(server_fd);
		return -1;
	}

	loop = g_main_loop_new(NULL, FALSE);
	sid = g_unix_fd_add(server_fd, G_IO_IN, __handle_signal, NULL);
	tid = g_timeout_add_seconds(10, __quit, NULL);

	return 0;
}

static void __fini(void)
{
	g_source_remove(sid);
	g_main_loop_unref(loop);
	g_object_unref(conn);
	close(server_fd);
}

int main(int argc, char *argv[])
{
	int r;

	r = __init();
	if (r < 0)
		return -1;

	g_main_loop_run(loop);

	__fini();

	return 0;
}
