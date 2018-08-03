/*
 * File      : webclient.c
 * COPYRIGHT (C) 2006 - 2018, RT-Thread Development Team
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
 */

#include <string.h>
#include <sys/time.h>

#include "webclient.h"

#if defined(RT_USING_DFS_NET) || defined(SAL_USING_POSIX)
#include <netdb.h>
#include <sys/socket.h>
#else
#include <lwip/netdb.h>
#include <lwip/sockets.h>
#endif /* SAL_USING_POSIX */

/* default receive or send timeout */
#define WEBCLIENT_DEFAULT_TIMEO        6

extern long int strtol(const char *nptr, char **endptr, int base);

static int webclient_send(struct webclient_session* session, const unsigned char *buffer, size_t len, int flag)
{
#ifdef WEBCLIENT_USING_TLS
    if(session->tls_session)
    {
        return mbedtls_client_write(session->tls_session, buffer, len);
    }
#endif

    return send(session->socket, buffer, len, flag);     
}

static int webclient_recv(struct webclient_session* session, unsigned char *buffer, size_t len, int flag)
{
#ifdef WEBCLIENT_USING_TLS
    if(session->tls_session)
    {
        return mbedtls_client_read(session->tls_session, buffer, len);
    }
#endif 

    return recv(session->socket, buffer, len, flag);
}

static char *webclient_header_skip_prefix(char *line, const char *prefix)
{
    char *ptr;
    size_t len;

    RT_ASSERT(line);
    RT_ASSERT(prefix);

    len = strlen(prefix);

    if (strncmp(line, prefix, len))
        return RT_NULL;

    ptr = line + len;

    /* skip whitespace */
    while (*ptr && (*ptr == ' ' || *ptr == '\t'))
        ptr += 1;

    /* remove '\r\n' */
    line = ptr;
    ptr = strstr(line, "\r\n");
    if (ptr != RT_NULL)
    {
        *ptr = '\0';
    }

    return line;
}

/*
 * When a request has been sent, we can expect mime headers to be
 * before the data.  We need to read exactly to the end of the headers
 * and no more data.  This readline reads a single char at a time.
 */
static int webclient_read_line(struct webclient_session *session, char *buffer, int size)
{
    char *ptr = buffer;
    int rc, count = 0;

    RT_ASSERT(session);
    RT_ASSERT(buffer);

    /* Keep reading until we fill the buffer. */
    while (count < size)
    {
        rc = webclient_recv(session, (unsigned char *)ptr, 1, 0);
#ifdef WEBCLIENT_USING_TLS
        if(session->tls_session && rc == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
#endif 
        if (rc <= 0)
            return rc;

        if (*ptr == '\n')
        {
            ptr++;
            count++;
            break;
        }

        /* increment after check for cr.  Don't want to count the cr. */
        count++;
        ptr++;
    }

    /* add terminate string */
    *ptr = '\0';

    LOG_D("read line: %s", buffer);

    return count;
}

/**
 * resolve server address
 *
 * @param session http session
 * @param res the server address information
 * @param url the input server URI address
 * @param request the pointer to point the request url, for example, /index.html
 *
 * @return 0 on resolve server address OK, others failed
 *
 * URL example:
 * http://www.rt-thread.org/
 * http://192.168.1.1:80/index.htm
 * http://[fe80::1]/index.html
 * http://[fe80::1]:80/index.html
 */
static int webclient_resolve_address(struct webclient_session *session, struct addrinfo **res,
                                     const char *url, char **request)
{
    int rc = WEBCLIENT_OK;
    char *ptr;
    char port_str[6] = "80"; /* default port of 80(http) */

    const char *host_addr = 0;
    int url_len, host_addr_len = 0;

    RT_ASSERT(res);
    RT_ASSERT(request);

    url_len = strlen(url);

    /* strip protocol(http or https) */
    if (strncmp(url, "http://", 7) == 0)
    {
        host_addr = url + 7;
    }
    else if (strncmp(url, "https://", 8) == 0)
    {
        strncpy(port_str, "443", 4);
        host_addr = url + 8;
    }
    else
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* ipv6 address */
    if (host_addr[0] == '[')
    {
        host_addr += 1;
        ptr = strstr(host_addr, "]");
        if (!ptr)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
        host_addr_len = ptr - host_addr;

        ptr = strstr(host_addr + host_addr_len, "/");
        if (!ptr)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
        else if (ptr != (host_addr + host_addr_len + 1))
        {
            int port_len = ptr - host_addr - host_addr_len - 2;

            strncpy(port_str, host_addr + host_addr_len + 2, port_len);
            port_str[port_len] = '\0';
        }

        *request = (char *) ptr;
    }
    else /* ipv4 or domain. */
    {
        char *port_ptr;

        ptr = strstr(host_addr, "/");
        if (!ptr)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
        host_addr_len = ptr - host_addr;
        *request = (char *) ptr;
        
        /* resolve port */
        port_ptr = strstr(host_addr, ":");
        if (port_ptr && port_ptr < ptr)
        {
            int port_len = ptr - port_ptr - 1;

            strncpy(port_str, port_ptr + 1, port_len);
            port_str[port_len] = '\0';

            host_addr_len = port_ptr - host_addr;
        }
    }

    if ((host_addr_len < 1) || (host_addr_len > url_len))
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* get host address ok. */
    {
        char *host_addr_new = web_malloc(host_addr_len + 1);

        if (!host_addr_new)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

        memcpy(host_addr_new, host_addr, host_addr_len);
        host_addr_new[host_addr_len] = '\0';
        session->host = host_addr_new;
        
#ifdef WEBCLIENT_USING_TLS
        if(session->tls_session)
            session->tls_session->host = web_strdup(host_addr_new);
#endif
    }

    LOG_D("host address: %s , port: %s", session->host, port_str);

    /* resolve the host name. */
    {
        struct addrinfo hint;
        int ret;

        memset(&hint, 0, sizeof(hint));
        
#ifdef WEBCLIENT_USING_TLS
        if(session->tls_session)
        {
            session->tls_session->port = web_strdup(port_str);
            ret = getaddrinfo(session->tls_session->host, port_str, &hint, res);
            if (ret != 0)
            {
                LOG_E("getaddrinfo err: %d '%s'", ret, session->host);
                rc = -WEBCLIENT_ERROR;          
            }
            
            goto __exit;
        }
#endif

        ret = getaddrinfo(session->host, port_str, &hint, res);
        if (ret != 0)
        {
            LOG_E("getaddrinfo err: %d '%s'.", ret, session->host);
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

    }
__exit:
    if (rc != WEBCLIENT_OK)
    {
        if (session->host)
        {
            web_free(session->host);
            session->host = RT_NULL;
        }

        if (*res)
        {
            freeaddrinfo(*res);
            *res = RT_NULL;
        }
    }

    return rc;
}

#ifdef WEBCLIENT_USING_TLS
/**
 * create and initialize https session.
 *
 * @param session webclient session
 * @param URI input server URI address
 *
 * @return <0: create failed, no memory or other errors
 *         =0: success
 */
static int webclient_open_tls(struct webclient_session *session, const char *URI)
{
    int tls_ret = 0;
    const char *pers = "webclient";

    RT_ASSERT(session);

    session->tls_session = (MbedTLSSession *) web_calloc(1, sizeof(MbedTLSSession));
    if (session->tls_session == RT_NULL)
    {
        return -WEBCLIENT_NOMEM;
    }

    session->tls_session->buffer_len = session->resp_sz;
    session->tls_session->buffer = web_malloc(session->tls_session->buffer_len);
    if(session->tls_session->buffer == RT_NULL)
    {
        LOG_E("no memory for tls_session buffer!");
        return -WEBCLIENT_ERROR;
    }

    if((tls_ret = mbedtls_client_init(session->tls_session, (void *)pers, strlen(pers))) < 0)
    {
        LOG_E("initialize https client failed return: -0x%x.", -tls_ret);
        return -WEBCLIENT_ERROR;
    }

    return WEBCLIENT_OK;
}
#endif

/**
 * connect to http server.
 *
 * @param session webclient session
 * @param URI the input server URI address
 *
 * @return <0: connect failed or other error
 *         =0: connect success
 */
static int webclient_connect(struct webclient_session *session, const char *URI)
{
    int rc = WEBCLIENT_OK;
    int socket_handle;
    struct timeval timeout;
    struct addrinfo *res = RT_NULL;
    char *request;

    RT_ASSERT(session);
    RT_ASSERT(URI);

    /* initialize the socket of session */
    session->socket = -1;

    timeout.tv_sec = WEBCLIENT_DEFAULT_TIMEO;
    timeout.tv_usec = 0;

    if(strncmp(URI, "https://", 8) == 0)
    {
#ifdef WEBCLIENT_USING_TLS
        if(webclient_open_tls(session, URI) < 0)
        {
           LOG_E("connect failed, https client open URI(%s) failed!", URI);
           return -WEBCLIENT_ERROR;
        }
#else
        LOG_E("not support https connect, please enable webclient https configure!");
        rc = -WEBCLIENT_ERROR;
        goto __exit;
#endif
    }

    /* Check valid IP address and URL */
    rc = webclient_resolve_address(session, &res, URI, &request);
    if (rc != WEBCLIENT_OK)
    {
        LOG_E("connect failed, resolve address error.");
        goto __exit;
    }

    if (!res)
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* copy host address */
    if (*request)
    {
        session->request = web_strdup(request);
    }

#ifdef WEBCLIENT_USING_TLS
    if(session->tls_session)
    {
       int tls_ret = 0;

        if((tls_ret = mbedtls_client_context(session->tls_session)) < 0)
        {
            LOG_E("connect failed, https client context return: -0x%x", -tls_ret);
            return -WEBCLIENT_ERROR;
        }

        if((tls_ret = mbedtls_client_connect(session->tls_session)) < 0)
        {
            LOG_E("connect failed, https client connect return: -0x%x", -tls_ret);
            rc = -WEBCLIENT_CONNECT_FAILED;
            goto __exit;
        }

        socket_handle = session->tls_session->server_fd.fd;

        /* set recv timeout option */
        setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (void*) &timeout,
                sizeof(timeout));
        setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, (void*) &timeout,
                sizeof(timeout));

        session->socket = socket_handle;

        rc = WEBCLIENT_OK;
        goto __exit;
    }
#endif

    {
        socket_handle = socket(res->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (socket_handle < 0)
        {
            LOG_E("connect failed, create socket(%d) error.", socket_handle);
            rc = -WEBCLIENT_NOSOCKET;
            goto __exit;
        }

        /* set receive and send timeout option */
        setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeout,
                   sizeof(timeout));
        setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeout,
                   sizeof(timeout));

        if (connect(socket_handle, res->ai_addr, res->ai_addrlen) != 0)
        {
            /* connect failed */
            LOG_E("connect failed, connect socket(%d) error.", socket_handle);
            rc = -WEBCLIENT_CONNECT_FAILED;
            goto __exit;
        }

        session->socket = socket_handle;
    }

__exit:
    if (res)
    {
        freeaddrinfo(res);
    }

    return rc;
}

static int webclient_send_header(struct webclient_session *session, int method,
                          const char *header, size_t header_sz)
{
    int rc = WEBCLIENT_OK;
    unsigned char *header_buffer = RT_NULL, *header_ptr;

    RT_ASSERT(session);

    if (header == RT_NULL)
    {
        header_buffer = web_malloc(session->header_sz);
        if (header_buffer == RT_NULL)
        {
            LOG_E("send header failed, no memory for header buffer!");
            rc = -WEBCLIENT_NOMEM;
            goto __exit;
        }

        header_ptr = header_buffer;
        header_ptr += rt_snprintf((char *) header_ptr,
                                  session->header_sz - (header_ptr - header_buffer),
                                  "GET %s HTTP/1.1\r\n",
                                  session->request ? session->request : "/");
        header_ptr += rt_snprintf((char *) header_ptr,
                                  session->header_sz - (header_ptr - header_buffer),
                                  "Host: %s\r\n", session->host);
        header_ptr += rt_snprintf((char *) header_ptr,
                                  session->header_sz - (header_ptr - header_buffer),
                                  "User-Agent: RT-Thread HTTP Agent\r\n\r\n");

        webclient_write(session, header_buffer, header_ptr - header_buffer);
    }
    else
    {
        if (method != WEBCLIENT_USER_METHOD)
        {
            header_buffer = web_malloc(session->header_sz);
            if (header_buffer == RT_NULL)
            {
                LOG_E("send header failed, no memory for header buffer!");
                rc = -WEBCLIENT_NOMEM;
                goto __exit;
            }

            header_ptr = header_buffer;

            if (strstr(header, "HTTP/1.") == RT_NULL)
            {
                if (method == WEBCLIENT_GET)
                    header_ptr += rt_snprintf((char *) header_ptr,
                                              session->header_sz
                                              - (header_ptr - header_buffer),
                                              "GET %s HTTP/1.1\r\n",
                                              session->request ? session->request : "/");
                else if (method == WEBCLIENT_POST)
                    header_ptr += rt_snprintf((char *) header_ptr,
                                              session->header_sz
                                              - (header_ptr - header_buffer),
                                              "POST %s HTTP/1.1\r\n",
                                              session->request ? session->request : "/");
            }

            if (strstr(header, "Host:") == RT_NULL)
            {
                header_ptr += rt_snprintf((char *) header_ptr,
                                          session->header_sz - (header_ptr - header_buffer),
                                          "Host: %s\r\n", session->host);
            }

            if (strstr(header, "User-Agent:") == RT_NULL)
            {
                header_ptr += rt_snprintf((char *) header_ptr,
                                          session->header_sz - (header_ptr - header_buffer),
                                          "User-Agent: RT-Thread HTTP Agent\r\n");
            }

            if (strstr(header, "Accept: ") == RT_NULL)
            {
                header_ptr += rt_snprintf((char *) header_ptr,
                                          session->header_sz - (header_ptr - header_buffer),
                                          "Accept: */*\r\n");
            }

            if ((session->header_sz - (header_ptr - header_buffer))
                    < (int) header_sz + 3)
            {
                LOG_E("send header failed, not enough header buffer size(%d)!", session->header_sz);
                rc = -WEBCLIENT_NOBUFFER;
                goto __exit;
            }

            /* append user's header */
            memcpy(header_ptr, header, header_sz);
            header_ptr += header_sz;
            header_ptr += rt_snprintf((char *) header_ptr,
                                      session->header_sz - (header_ptr - header_buffer),
                                      "\r\n");

            webclient_write(session, header_buffer, header_ptr - header_buffer);
        }
        else
        {
            webclient_write(session, (unsigned char *) header, header_sz);
        }
    }

__exit:
    if(header_buffer)
    {
        web_free(header_buffer);
    }

    return rc;
}

/**
 * resolve server response data.
 *
 * @param session webclient session
 *
 * @return <0: resolve response data failed
 *         =0: success
 */
int webclient_handle_response(struct webclient_session *session)
{
    int rc = WEBCLIENT_OK;
    char *mime_buffer, *mime_ptr;

    RT_ASSERT(session);

    /* set content length of session */
    session->content_length = -1;

    mime_buffer = (char *) web_malloc(session->resp_sz + 1);
    if (!mime_buffer)
    {
        LOG_E("handle response failed, no memory for mime buffer!");
        return -WEBCLIENT_NOMEM;
    }

    /* We now need to read the header information */
    while (1)
    {
        int i;

        /* read a line from the header information. */
        rc = webclient_read_line(session, mime_buffer, session->resp_sz);
        if (rc < 0)
            break;

        /* set terminal charater */
        mime_buffer[rc] = '\0';

        /* End of headers is a blank line.  exit. */
        if (rc == 0)
            break;
        if ((rc == 2) && (mime_buffer[0] == '\r'))
            break;

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "HTTP/1.");
        if (mime_ptr != RT_NULL)
        {
            mime_ptr += 1;
            while (*mime_ptr && (*mime_ptr == ' ' || *mime_ptr == '\t'))
                mime_ptr++;
            /* Terminate string after status code */
            for (i = 0; ((mime_ptr[i] != ' ') && (mime_ptr[i] != '\t')); i++);
            mime_ptr[i] = '\0';

            session->response = (int) strtol(mime_ptr, RT_NULL, 10);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Last-Modified:");
        if (mime_ptr != RT_NULL)
        {
            session->last_modified = web_strdup(mime_ptr);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Transfer-Encoding: ");
        if (mime_ptr != RT_NULL)
        {
            session->transfer_encoding = web_strdup(mime_ptr);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Content-Type:");
        if (mime_ptr != RT_NULL)
        {
            session->content_type = web_strdup(mime_ptr);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Content-Length:");
        if (mime_ptr != RT_NULL)
        {
            session->content_length = (int) strtol(mime_ptr, RT_NULL, 10);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Location: ");
        if (mime_ptr != RT_NULL)
        {
            session->location = web_strdup(mime_ptr);
        }

        mime_ptr = webclient_header_skip_prefix(mime_buffer, "Content-Range:");
        if (mime_ptr != RT_NULL)
        {
            char *ptr = RT_NULL;
            int totle_length;

            mime_ptr = webclient_header_skip_prefix(mime_ptr, "bytes");
            while (*mime_ptr == ' ')
                mime_ptr++;

            session->position = atoi(mime_ptr);
            ptr = strstr(mime_ptr, "/");
            if (ptr)
            {
                ptr ++;
                /* The total length of the get data */
                totle_length = atoi(ptr);
                //TODO: process total length
            }
        }
    }

    session->content_length_remainder =
        (session->content_length) ? (size_t) session->content_length : 0xFFFFFFFF;

    if (session->transfer_encoding && strcmp(session->transfer_encoding, "chunked") == 0)
    {
        /* chunk mode, we should get the first chunk size */
        webclient_read_line(session, mime_buffer, session->resp_sz);
        session->chunk_sz = strtol(mime_buffer, RT_NULL, 16);
        session->chunk_offset = 0;
    }

    /* release buffer */
    if(mime_buffer)
    {
        web_free(mime_buffer);
    }

    if (rc < 0)
    {
        return rc;
    }

    return session->response;
}

/**
 * create webclient session, set maximum header and response size
 *
 * @param header_sz maximum send header size
 * @param resp_sz maximum response data size
 *
 * @return  webclient session structure
 */
struct webclient_session *webclient_session_create(size_t header_sz, size_t resp_sz)
{
    struct webclient_session *session;

    /* create session */
    session = (struct webclient_session *) web_calloc(1, sizeof(struct webclient_session));
    if (session == RT_NULL)
    {
        LOG_E("webclient create failed, no memory for session!");
        return RT_NULL;
    }

    session->header_sz = header_sz;
    session->resp_sz = resp_sz;

    return session;
}

/**
 *  send GET request to http server and get response header.
 *
 * @param session webclient session
 * @param URI input server URI address
 * @param header GET request header
 *             = NULL: use default header data
 *            != NULL: use custom header data
 *
 * @return <0: send GET request failed
 *         >0: response http status code
 */
int webclient_get(struct webclient_session *session, const char *URI, const char *header)
{
    int rc = WEBCLIENT_OK;

    RT_ASSERT(session);
    RT_ASSERT(URI);

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        /* connect to webclient server failed. */
        goto __exit;
    }

    rc = webclient_send_header(session, WEBCLIENT_GET, header, strlen(header));
    if (rc != WEBCLIENT_OK)
    {
        /* send header to webclient server failed. */
        goto __exit;
    }

    /* handle the response header of webclient server */
    rc = webclient_handle_response(session);
    if (rc > 0)
    {
        /* relocation */
        if ((session->response == 302 || session->response == 301) && session->location)
        {
            char *location = web_strdup(session->location);
            if (location)
            {
                webclient_close(session);
                rc = webclient_get(session, location, header);
                if (rc != WEBCLIENT_OK)
                {
                    goto __exit;
                }

                web_free(location);
                return session->response;
            }
        }
        else if (session->response != 200)
        {
            LOG_E("get failed, handle response(%d) error!", session->response);
            goto __exit;
        }
    }

__exit:
    if (rc < 0)
    {
        return rc;
    }

    return session->response;
}

/**
 *  http breakpoint resume.
 *
 * @param session webclient session
 * @param URI input server URI address
 * @param position last downloaded position
 *
 * @return <0: send GET request failed
 *         >0: response http status code
 */
int webclient_get_position(struct webclient_session *session, const char *URI, int position)
{
    char *range_header = RT_NULL;
    int rc = WEBCLIENT_OK;

    RT_ASSERT(session);
    RT_ASSERT(URI);

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        goto __exit;
    }

    range_header = (char *) web_malloc(session->header_sz);
    if (range_header == RT_NULL)
    {
        LOG_E("open position failed, no memory for range header!");
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    /* splice header*/
    rt_snprintf(range_header, session->header_sz - 1,
                "Range: bytes=%d-\r\n", position);

    rc = webclient_send_header(session, WEBCLIENT_GET, range_header, strlen(range_header));
    if (rc != WEBCLIENT_OK)
    {
        goto __exit;
    }

    /* handle the response header of webclient server */
    rc = webclient_handle_response(session);
    if (rc > 0)
    {
        /* relocation */
        if ((session->response == 302 || session->response == 301) && session->location)
        {
            char *location = web_strdup(session->location);
            if (location)
            {
                webclient_close(session);
                rc = webclient_get_position(session, location, position);
                if (rc != WEBCLIENT_OK)
                {
                    goto __exit;
                }

                web_free(location);
                return session->response;
            }
        }
        else if (session->response != 206)
        {
            LOG_E("get failed, handle response(%d) error!", session->response);
            goto __exit;
        }
    }

__exit:
    if (range_header)
    {
        web_free(range_header);
    }

    if (rc < 0)
    {
        return rc;
    }

    return session->response;
}

/**
 * send POST request to server and get response header data.
 *
 * @param session webclient session
 * @param URI input server URI address
 * @param header POST request header, can't be empty
 * @param post_data data sent to the server
 *                = NULL: just connect server and send header
 *               != NULL: send header and body data, resolve response data
 *
 * @return <0: send POST request failed
 *         =0: send POST header success
 *         >0: response http status code
 */
int webclient_post(struct webclient_session *session, const char *URI,
        const char *header, const char *post_data)
{
    int rc = WEBCLIENT_OK;

    RT_ASSERT(session);
    RT_ASSERT(URI);

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        /* connect to webclient server failed. */
        goto __exit;
    }

    rc = webclient_send_header(session, WEBCLIENT_POST, header, strlen(header));
    if (rc != WEBCLIENT_OK)
    {
        /* send header to webclient server failed. */
        goto __exit;
    }

    if(post_data)
    {
        webclient_write(session, (unsigned char *)post_data, strlen(post_data));

        /* resolve response data, get http status code */
        rc = webclient_handle_response(session);
        if (rc > 0)
        {
            if (session->response != 200)
            {
                LOG_E("post failed, handle response(%d) error.", session->response);
                goto __exit;
            }
        }
    }
    else
    {
        return rc;
    }

__exit:
    if (rc < 0)
    {
        return rc;
    }

    return session->response;
}


/**
 * set receive and send data timeout.
 *
 * @param session http session
 * @param millisecond timeout millisecond
 *
 * @return 0: set timeout success
 */
int webclient_set_timeout(struct webclient_session *session, int millisecond)
{
    struct timeval timeout;
    int second = rt_tick_from_millisecond(millisecond) / 1000;

    RT_ASSERT(session);

    timeout.tv_sec = second;
    timeout.tv_usec = 0;

    /* set recv timeout option */
    setsockopt(session->socket, SOL_SOCKET, SO_RCVTIMEO,
               (void *) &timeout, sizeof(timeout));
    setsockopt(session->socket, SOL_SOCKET, SO_SNDTIMEO,
               (void *) &timeout, sizeof(timeout));

    return 0;
}

static int webclient_next_chunk(struct webclient_session *session)
{
    char line[64];
    int length;

    RT_ASSERT(session);

    length = webclient_read_line(session, line, sizeof(line));
    if (length)
    {
        if (strcmp(line, "\r\n") == 0)
        {
            length = webclient_read_line(session, line, sizeof(line));
            if (length <= 0)
            {
                closesocket(session->socket);
                session->socket = -1;
                return length;
            }
        }
    }
    else
    {
        closesocket(session->socket);
        session->socket = -1;

        return length;
    }

    session->chunk_sz = strtol(line, RT_NULL, 16);
    session->chunk_offset = 0;

    if (session->chunk_sz == 0)
    {
        /* end of chunks */
        closesocket(session->socket);
        session->socket = -1;
    }

    return session->chunk_sz;
}

/**
 *  read data from http server.
 *
 * @param session http session
 * @param buffer read buffer
 * @param length the maximum of read buffer size
 *
 * @return <0: read data error
 *         =0: http server disconnect
 *         >0: successfully read data length
 */
int webclient_read(struct webclient_session *session, unsigned char *buffer, size_t length)
{
    int bytes_read = 0;
    int total_read = 0;
    int left;

    RT_ASSERT(session);

    if (session->socket < 0)
    {
        return -WEBCLIENT_DISCONNECT;
    }

    if (length == 0)
    {
        return 0;
    }

    /* which is transfered as chunk mode */
    if (session->chunk_sz)
    {
        if ((int) length > (session->chunk_sz - session->chunk_offset))
        {
            length = session->chunk_sz - session->chunk_offset;
        }

        bytes_read = webclient_recv(session, buffer, length, 0);
        if (bytes_read <= 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                /* recv timeout */
                return -WEBCLIENT_TIMEOUT;
            }
            else
            {
                closesocket(session->socket);
                session->socket = -1;
                return 0;
            }
        }

        session->chunk_offset += bytes_read;
        if (session->chunk_offset >= session->chunk_sz)
        {
            webclient_next_chunk(session);
        }

        return bytes_read;
    }

    if (session->content_length > 0)
    {
        if (length > session->content_length_remainder)
        {
            length = session->content_length_remainder;
        }

        if (length == 0)
        {
            return 0;
        }
    }

    /*
     * Read until: there is an error, we've read "size" bytes or the remote
     * side has closed the connection.
     */
    left = length;
    do
    {
        bytes_read = webclient_recv(session, buffer + total_read, left, 0);
        if (bytes_read <= 0)
        {
#ifdef WEBCLIENT_USING_TLS
            if(session->tls_session && bytes_read == MBEDTLS_ERR_SSL_WANT_READ)
                continue;
#endif  
            LOG_E("receive data error(%d).", bytes_read);

            if (total_read)
            {
                break;
            }
            else
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    /* recv timeout */
                    LOG_E("receive data timeout.");
                    return -WEBCLIENT_TIMEOUT;
                }
                else
                {
                    closesocket(session->socket);
                    session->socket = -1;
                    return 0;
                }
            }
        }

        left -= bytes_read;
        total_read += bytes_read;
    }
    while (left);

    if (session->content_length > 0)
    {
        session->content_length_remainder -= total_read;
    }

    return total_read;
}

/**
 *  write data to http server.
 *
 * @param session http session
 * @param buffer write buffer
 * @param length write buffer size
 *
 * @return <0: write data error
 *         =0: http server disconnect
 *         >0: successfully write data length
 */
int webclient_write(struct webclient_session *session, const unsigned char *buffer, size_t length)
{
    int bytes_write = 0;
    int total_write = 0;
    int left = length;

    RT_ASSERT(session);

    if (session->socket < 0)
    {
        return -WEBCLIENT_DISCONNECT;
    }

    if(length == 0)
    {
        return 0;
    }

    /* send all of data on the buffer. */
    do
    {
        bytes_write = webclient_send(session, buffer + total_write, left, 0);
        if (bytes_write <= 0)
        {
#ifdef WEBCLIENT_USING_TLS
            if(session->tls_session && bytes_write == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;
#endif
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                /* send timeout */
                if (total_write)
                {
                    return total_write;
                }
                continue;
                /* TODO: whether return the TIMEOUT
                 * return -WEBCLIENT_TIMEOUT; */
            }
            else
            {
                closesocket(session->socket);
                session->socket = -1;

                if (total_write == 0)
                {
                    return -WEBCLIENT_DISCONNECT;
                }
                break;
            }
        }

        left -= bytes_write;
        total_write += bytes_write;
    }
    while (left);

    return total_write;
}

/**
 * close a webclient client session.
 *
 * @param session http client session
 *
 * @return 0: close success
 */
int webclient_close(struct webclient_session *session)
{
    RT_ASSERT(session);
    
#ifdef WEBCLIENT_USING_TLS
    if(session->tls_session)
    {
        mbedtls_client_close(session->tls_session);
    }
    else
    {
        if (session->socket >= 0)
        {
            closesocket(session->socket); 
            session->socket = -1;
        }
    }
#else
    if (session->socket >= 0)
    {
        closesocket(session->socket);
        session->socket = -1;
    }
#endif

    if(session->transfer_encoding)
        web_free(session->transfer_encoding);

    if(session->content_type)
        web_free(session->content_type);

    if(session->last_modified)
        web_free(session->last_modified);

    if(session->host)
        web_free(session->host);

    if(session->request)
        web_free(session->request);

    if(session->location)
        web_free(session->location);

    if(session)
    {
        web_free(session);
        session = RT_NULL;
    }

    return 0;
}

/**
 * get wenclient request response data.
 *
 * @param session wenclient session
 * @param response response buffer address
 *
 * @return response data size
 */
int webclient_response(struct webclient_session *session, void **response)
{
    unsigned char *buf_ptr;
    unsigned char *response_buf = 0;
    int length, total_read = 0;

    RT_ASSERT(session);
    RT_ASSERT(response);

    /* initialize response */
    *response = RT_NULL;

    /* not content length field kind */
    if (session->content_length < 0)
    {
        size_t result_sz;

        total_read = 0;
        while (1)
        {
            unsigned char *new_resp = RT_NULL;

            result_sz = total_read + session->resp_sz;
            new_resp = web_realloc(response_buf, result_sz + 1);
            if (new_resp == RT_NULL)
            {
                LOG_E("no memory for realloc new response buffer!");
                break;
            }

            response_buf = new_resp;
            buf_ptr = (unsigned char *) response_buf + total_read;

            /* read result */
            length = webclient_read(session, buf_ptr, result_sz - total_read);
            if (length <= 0)
                break;

            total_read += length;
        }
    }
    else
    {
        int result_sz;

        result_sz = session->content_length;
        response_buf = web_malloc(result_sz + 1);
        if (!response_buf)
        {
            return -WEBCLIENT_NOMEM;
        }

        buf_ptr = (unsigned char *) response_buf;
        for (total_read = 0; total_read < result_sz;)
        {
            length = webclient_read(session, buf_ptr, result_sz - total_read);
            if (length <= 0)
                break;

            buf_ptr += length;
            total_read += length;
        }
    }

    if ((total_read == 0) && (response_buf != 0))
    {
        web_free(response_buf);
        response_buf = RT_NULL;
    }

    if (response_buf)
    {
        *response = response_buf;
        *(response_buf + total_read) = '\0';
    }

    return total_read;
}

/**
 *  send request(GET/POST) to server and get response data.
 *
 * @param URI input server address
 * @param header send header data
 *             = NULL: use default header data, must be GET request
 *            != NULL: user custom header data, GET or POST request
 * @param post_data data sent to the server
 *             = NULL: it is GET request
 *            != NULL: it is POST request
 * @param response response buffer address
 *
 * @return <0: request failed
 *        >=0: response buffer size
 */
int webclient_request(const char *URI, const char *header, const char *post_data, unsigned char **response)
{
    struct webclient_session *session;
    int rc = WEBCLIENT_OK;
    int totle_length;

    RT_ASSERT(URI);

    if(post_data && header == RT_NULL)
    {
        LOG_E("request post failed, post input header cannot be empty.");
        return -WEBCLIENT_ERROR;
    }

    if(post_data == RT_NULL && response == RT_NULL)
    {
        LOG_E("request get failed, get response data cannot be empty.");
        return -WEBCLIENT_ERROR;
    }

    if(post_data == RT_NULL)
    {
        session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ, WEBCLIENT_RESPONSE_BUFSZ);
        if(session == RT_NULL)
        {
            rc = -WEBCLIENT_NOMEM;
            goto __exit;
        }

        if(webclient_get(session, URI, header) != 200)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

        totle_length = webclient_response(session, (void **)response);
        if(totle_length <= 0)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
    }
    else
    {
        session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ, WEBCLIENT_RESPONSE_BUFSZ);
        if(session == RT_NULL)
        {
            rc = -WEBCLIENT_NOMEM;
            goto __exit;
        }

        if(webclient_post(session, URI, header, post_data) != 200)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
    }

__exit:
    if(session)
    {
        webclient_close(session);
        session = RT_NULL;
    }

    if(rc < 0)
    {
        return rc;
    }

    return totle_length;

}
