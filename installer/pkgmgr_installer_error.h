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

#ifndef __PKGMGR_INSTALLER_ERROR__
#define __PKGMGR_INSTALLER_ERROR__

/* new common error codes
 * since 3.0
 */
#define PKGMGR_INSTALLER_ERRCODE_UNDEFINED_ERROR        (-999)
#define PKGMGR_INSTALLER_ERRCODE_RECOVERY_DONE           (-27)  /* Recovery process done */
#define PKGMGR_INSTALLER_ERRCODE_GLOBALSYMLINK_ERROR     (-26)  /* Global symlink error */
#define PKGMGR_INSTALLER_ERRCODE_GRANT_PERMISSION_ERROR  (-25)  /* Grant permission error */
#define PKGMGR_INSTALLER_ERRCODE_IMAGE_ERROR             (-24)  /* Image error */
#define PKGMGR_INSTALLER_ERRCODE_UNZIP_ERROR             (-23)  /* Unzip error */
#define PKGMGR_INSTALLER_ERRCODE_SECURITY_ERROR          (-22)  /* Security error */
#define PKGMGR_INSTALLER_ERRCODE_REGISTER_ERROR          (-21)  /* Register application error */
#define PKGMGR_INSTALLER_ERRCODE_PRIVILEGE_ERROR         (-20)  /* Privilege error */
#define PKGMGR_INSTALLER_ERRCODE_PARSE_ERROR             (-19)  /* Parsing error */
#define PKGMGR_INSTALLER_ERRCODE_RECOVERY_ERROR          (-18)  /* Recovery error */
#define PKGMGR_INSTALLER_ERRCODE_DELTA_ERROR             (-17)  /* Delta patch error */
#define PKGMGR_INSTALLER_ERRCODE_APP_DIR_ERROR           (-16)  /* Application directory error */
#define PKGMGR_INSTALLER_ERRCODE_CONFIG_ERROR            (-15)  /* Configuration error */
#define PKGMGR_INSTALLER_ERRCODE_SIGNATURE_ERROR         (-14)  /* Signature error */
#define PKGMGR_INSTALLER_ERRCODE_SIGNATURE_INVALID       (-13)  /* Signature invalid */
#define PKGMGR_INSTALLER_ERRCODE_CERT_ERROR              (-12)  /* Check certificate error */
#define PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_MATCH   (-11)  /* Author certificate not match */
#define PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_FOUND   (-10)  /* Author certificate not found */
#define PKGMGR_INSTALLER_ERRCODE_ICON_ERROR               (-9)  /* Icon error */
#define PKGMGR_INSTALLER_ERRCODE_ICON_NOT_FOUND           (-8)  /* Icon not found */
#define PKGMGR_INSTALLER_ERRCODE_MANIFEST_ERROR           (-7)  /* Manifest error */
#define PKGMGR_INSTALLER_ERRCODE_MANIFEST_NOT_FOUND       (-6)  /* Manifest not found */
#define PKGMGR_INSTALLER_ERRCODE_PACKAGE_NOT_FOUND        (-5)  /* Package not found */
#define PKGMGR_INSTALLER_ERRCODE_OPERATION_NOT_ALLOWED    (-4)  /* Operation not allowed */
#define PKGMGR_INSTALLER_ERRCODE_OUT_OF_SPACE             (-3)  /* Out of disc space */
#define PKGMGR_INSTALLER_ERRCODE_INVALID_VALUE            (-2)  /* Invalid argument */
#define PKGMGR_INSTALLER_ERRCODE_ERROR                    (-1)  /* General error */
#define PKGMGR_INSTALLER_ERRCODE_OK                        (0)  /* Success */

#define PKGMGR_INSTALLER_ERRCODE_RECOVERY_DONE_STR           "Recovery process done"
#define PKGMGR_INSTALLER_ERRCODE_GLOBALSYMLINK_ERROR_STR     "Global symlink error"
#define PKGMGR_INSTALLER_ERRCODE_GRANT_PERMISSION_ERROR_STR  "Grant permission error"
#define PKGMGR_INSTALLER_ERRCODE_IMAGE_ERROR_STR             "Image error"
#define PKGMGR_INSTALLER_ERRCODE_UNZIP_ERROR_STR             "Unzip error"
#define PKGMGR_INSTALLER_ERRCODE_SECURITY_ERROR_STR          "Security error"
#define PKGMGR_INSTALLER_ERRCODE_REGISTER_ERROR_STR          "Register application error"
#define PKGMGR_INSTALLER_ERRCODE_PRIVILEGE_ERROR_STR         "Privilege error"
#define PKGMGR_INSTALLER_ERRCODE_PARSE_ERROR_STR             "Parsing error"
#define PKGMGR_INSTALLER_ERRCODE_RECOVERY_ERROR_STR          "Recovery error"
#define PKGMGR_INSTALLER_ERRCODE_DELTA_ERROR_STR             "Delta patch error"
#define PKGMGR_INSTALLER_ERRCODE_APP_DIR_ERROR_STR           "Application directory error"
#define PKGMGR_INSTALLER_ERRCODE_CONFIG_ERROR_STR            "Configuration error"
#define PKGMGR_INSTALLER_ERRCODE_SIGNATURE_ERROR_STR         "Signature error"
#define PKGMGR_INSTALLER_ERRCODE_SIGNATURE_INVALID_STR       "Signature invalid"
#define PKGMGR_INSTALLER_ERRCODE_CERT_ERROR_STR              "Check certificate error"
#define PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_MATCH_STR   "Author certificate not match"
#define PKGMGR_INSTALLER_ERRCODE_AUTHOR_CERT_NOT_FOUND_STR   "Author certificate not found"
#define PKGMGR_INSTALLER_ERRCODE_ICON_ERROR_STR              "Icon error"
#define PKGMGR_INSTALLER_ERRCODE_ICON_NOT_FOUND_STR          "Icon not found"
#define PKGMGR_INSTALLER_ERRCODE_MANIFEST_ERROR_STR          "Manifest error"
#define PKGMGR_INSTALLER_ERRCODE_MANIFEST_NOT_FOUND_STR      "Manifest not found"
#define PKGMGR_INSTALLER_ERRCODE_PACKAGE_NOT_FOUND_STR       "Package not found"
#define PKGMGR_INSTALLER_ERRCODE_OPERATION_NOT_ALLOWED_STR   "Operation not allowed"
#define PKGMGR_INSTALLER_ERRCODE_OUT_OF_SPACE_STR            "Out of disc space"
#define PKGMGR_INSTALLER_ERRCODE_INVALID_VALUE_STR           "Invalid argument"
#define PKGMGR_INSTALLER_ERRCODE_ERROR_STR                   "General error"
#define PKGMGR_INSTALLER_ERRCODE_OK_STR                      "Success"

/* Outdated error codes (for compatible with 2.x)
 * 1 -100 : Package command errors
 * 101-120 : reserved for Core installer
 * 121-140 : reserved for Web installer
 * 141-160 : reserved for Native installer
 */
#define PKGMGR_INSTALLER_ERR_PACKAGE_NOT_FOUND                       1
#define PKGMGR_INSTALLER_ERR_PACKAGE_INVALID                         2
#define PKGMGR_INSTALLER_ERR_PACKAGE_LOWER_VERSION                   3
#define PKGMGR_INSTALLER_ERR_PACKAGE_EXECUTABLE_NOT_FOUND            4
#define PKGMGR_INSTALLER_ERR_MANIFEST_NOT_FOUND                     11
#define PKGMGR_INSTALLER_ERR_MANIFEST_INVALID                       12
#define PKGMGR_INSTALLER_ERR_CONFIG_NOT_FOUND                       13
#define PKGMGR_INSTALLER_ERR_CONFIG_INVALID                         14
#define PKGMGR_INSTALLER_ERR_SIGNATURE_NOT_FOUND                    21
#define PKGMGR_INSTALLER_ERR_SIGNATURE_INVALID                      22
#define PKGMGR_INSTALLER_ERR_SIGNATURE_VERIFICATION_FAILED          23
#define PKGMGR_INSTALLER_ERR_ROOT_CERTIFICATE_NOT_FOUND             31
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_INVALID                    32
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED  33
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_EXPIRED                    34
#define PKGMGR_INSTALLER_ERR_INVALID_PRIVILEGE                      41
#define PKGMGR_INSTALLER_ERR_MENU_ICON_NOT_FOUND                    51
#define PKGMGR_INSTALLER_ERR_FATAL_ERROR                            61
#define PKGMGR_INSTALLER_ERR_OUT_OF_STORAGE                         62
#define PKGMGR_INSTALLER_ERR_OUT_OF_MEMORY                          63
#define PKGMGR_INSTALLER_ERR_ARGUMENT_INVALID                       64

#define PKGMGR_INSTALLER_ERR_PACKAGE_NOT_FOUND_STR                      "PACKAGE_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_PACKAGE_INVALID_STR                        "PACKAGE_INVALID"
#define PKGMGR_INSTALLER_ERR_PACKAGE_LOWER_VERSION_STR                  "PACKAGE_LOWER_VERSION"
#define PKGMGR_INSTALLER_ERR_PACKAGE_EXECUTABLE_NOT_FOUND_STR           "PACKAGE_EXECUTABLE_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_MANIFEST_NOT_FOUND_STR                     "MANIFEST_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_MANIFEST_INVALID_STR                       "MANIFEST_INVALID"
#define PKGMGR_INSTALLER_ERR_CONFIG_NOT_FOUND_STR                       "CONFIG_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_CONFIG_INVALID_STR                         "CONFIG_INVALID"
#define PKGMGR_INSTALLER_ERR_SIGNATURE_NOT_FOUND_STR                    "SIGNATURE_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_SIGNATURE_INVALID_STR                      "SIGNATURE_INVALID"
#define PKGMGR_INSTALLER_ERR_SIGNATURE_VERIFICATION_FAILED_STR          "SIGNATURE_VERIFICATION_FAILED"
#define PKGMGR_INSTALLER_ERR_ROOT_CERTIFICATE_NOT_FOUND_STR             "ROOT_CERTIFICATE_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_INVALID_STR                    "CERTIFICATE_INVALID"
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_CHAIN_VERIFICATION_FAILED_STR  "CERTIFICATE_CHAIN_VERIFICATION_FAILED"
#define PKGMGR_INSTALLER_ERR_CERTIFICATE_EXPIRED_STR                    "CERTIFICATE_EXPIRED"
#define PKGMGR_INSTALLER_ERR_INVALID_PRIVILEGE_STR                      "INVALID_PRIVILEGE"
#define PKGMGR_INSTALLER_ERR_MENU_ICON_NOT_FOUND_STR                    "MENU_ICON_NOT_FOUND"
#define PKGMGR_INSTALLER_ERR_FATAL_ERROR_STR                            "FATAL_ERROR"
#define PKGMGR_INSTALLER_ERR_OUT_OF_STORAGE_STR                         "OUT_OF_STORAGE"
#define PKGMGR_INSTALLER_ERR_OUT_OF_MEMORY_STR                          "OUT_OF_MEMORY"
#define PKGMGR_INSTALLER_ERR_ARGUMENT_INVALID_STR                       "ARGUMENT_INVALID"
#define PKGMGR_INSTALLER_ERR_UNKNOWN_STR                                "Unknown Error"

#endif
