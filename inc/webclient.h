/*
 *  File      : webclient.h
 *  COPYRIGHT (C) 2006 - 2018, RT-Thread Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Change Logs:
 * Date           Author       Notes
 * 2013-05-05     Bernard      the first version
 * 2013-06-10     Bernard      fix the slow speed issue when download file.
 * 2015-11-14     aozima       add content_length_remainder.
 * 2017-12-23     aozima       update gethostbyname to getaddrinfo.
 * 2018-01-04     aozima       add ipv6 address support.
 * 2018-07-26     chenyong     modify log information
 * 2018-08-07     chenyong     modify header processing
 */

#ifndef __WEBCLIENT_H__
#define __WEBCLIENT_H__

#include <rtthread.h>

#ifdef WEBCLIENT_USING_TLS
#include <tls_client.h>
#endif

#undef DBG_SECTION_NAME
#undef DBG_LEVEL
#undef DBG_COLOR
#undef DBG_ENABLE

#define DBG_ENABLE
#define DBG_SECTION_NAME               "WEB"
#ifdef WEBCLIENT_DEBUG
#define DBG_LEVEL                      DBG_LOG
#else
#define DBG_LEVEL                      DBG_INFO
#endif /* WEBCLIENT_DEBUG */
#define DBG_COLOR
#include <rtdbg.h>

#ifndef web_malloc
#define web_malloc                     rt_malloc
#endif

#ifndef web_calloc
#define web_calloc                     rt_calloc
#endif

#ifndef web_realloc
#define web_realloc                    rt_realloc
#endif

#ifndef web_free
#define web_free                       rt_free
#endif

#ifndef web_strdup
#define web_strdup                     rt_strdup
#endif

#define WEBCLIENT_SW_VERSION           "2.0.0"
#define WEBCLIENT_SW_VERSION_NUM       0x20000

#define WEBCLIENT_HEADER_BUFSZ         4096
#define WEBCLIENT_RESPONSE_BUFSZ       4096

enum WEBCLIENT_STATUS
{
    WEBCLIENT_OK,
    WEBCLIENT_ERROR,
    WEBCLIENT_TIMEOUT,
    WEBCLIENT_NOMEM,
    WEBCLIENT_NOSOCKET,
    WEBCLIENT_NOBUFFER,
    WEBCLIENT_CONNECT_FAILED,
    WEBCLIENT_DISCONNECT,
    WEBCLIENT_FILE_ERROR,
};

enum WEBCLIENT_METHOD
{
    WEBCLIENT_USER_METHOD,
    WEBCLIENT_GET,
    WEBCLIENT_POST,
};

struct  webclient_header
{
    char *buffer;
    size_t length;                      /* content header buffer size */

    size_t size;                        /* maximum support header size */
};

struct webclient_session
{
    struct webclient_header *header;    /* webclient response header information */
    int socket;
    int resp_status;

    char *host;                         /* server host */
    char *request;                      /* HTTP request address*/

    int chunk_sz;
    int chunk_offset;

    int content_length;
    size_t content_remainder;           /* remainder of content length */

#ifdef WEBCLIENT_USING_TLS
    MbedTLSSession *tls_session;        /* mbedtls connect session */
#endif
};

/* create webclient session and set header response size */
struct webclient_session *webclient_session_create(size_t header_sz);

/* send HTTP GET request */
int webclient_get(struct webclient_session *session, const char *URI);
int webclient_get_position(struct webclient_session *session, const char *URI, int position);

/* send HTTP POST request */
int webclient_post(struct webclient_session *session, const char *URI, const char *post_data);

/* close and release wenclient session */
int webclient_close(struct webclient_session *session);

int webclient_set_timeout(struct webclient_session *session, int millisecond);

/* send or receive data from server */
int webclient_read(struct webclient_session *session, unsigned char *buffer, size_t size);
int webclient_write(struct webclient_session *session, const unsigned char *buffer, size_t size);

/* webclient GET/POST header buffer operate by the header fields */
int webclient_header_fields_add(struct webclient_session *session, const char *fmt, ...);
char *webclient_header_fields_get(struct webclient_session *session, const char *fields);
int webclient_header_resp_status_get(struct webclient_session *session);

/* send HTTP POST/GET request, and get response data */
int webclient_response(struct webclient_session *session, unsigned char **response);
int webclient_request(const char *URI, const char *header, const char *post_data, unsigned char **response);

#ifdef RT_USING_DFS
/* file related operations */
int webclient_get_file(const char *URI, const char *filename);
int webclient_post_file(const char *URI, const char *filename, const char *form_data);
#endif

#endif