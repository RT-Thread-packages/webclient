#include <stdint.h>
#include <stdlib.h>

#include <rtthread.h>
#include "webclient.h"
#include "webclient_internal.h"

#ifdef RT_USING_FINSH
#include <finsh.h>
#endif

#ifdef RT_USING_DFS
#include <dfs_posix.h>

int webclient_get_file(const char* URI, const char* filename)
{
    int fd = -1;
    size_t offset;
    size_t length, total_length = 0;
    rt_uint8_t* ptr = NULL;
    struct webclient_session* session = NULL;

    session = webclient_open(URI);
    if (session == NULL)
    {
        rt_kprintf("open website failed.\n");
        goto __exit;
    }
    if (session->response != 200)
    {
        rt_kprintf("wrong response: %d\n", session->response);
        goto __exit;
    }

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (fd < 0)
    {
        rt_kprintf("open file failed\n");
        goto __exit;
    }

    ptr = web_malloc(WEBCLIENT_RESPONSE_BUFSZ);
    if (ptr == NULL)
    {
        rt_kprintf("out of memory\n");
        goto __exit;
    }

    if (session->content_length == 0)
    {
        while (1)
        {
            length = webclient_read(session, ptr, WEBCLIENT_RESPONSE_BUFSZ);
            if (length > 0)
            {
                write(fd, ptr, length);
                total_length += length;
                rt_kprintf(">");
            }
            else
                break;
        }
    }
    else
    {
        for (offset = 0; offset < session->content_length;)
        {
            length = webclient_read(session, ptr,
                    session->content_length - offset > WEBCLIENT_RESPONSE_BUFSZ ?
                            WEBCLIENT_RESPONSE_BUFSZ : session->content_length - offset);

            if (length > 0)
            {
                write(fd, ptr, length);
                total_length += length;
                rt_kprintf(">");
            }
            else
                break;

            offset += length;
        }
    }

    if (total_length)
    {
        rt_kprintf("\nSave %d bytes\n", total_length);
    }

__exit:
    if (fd >= 0) close(fd);
    if (session != NULL) webclient_close(session);
    if (ptr != NULL) web_free(ptr);

    return 0;
}

int webclient_post_file(const char* URI, const char* filename,
        const char* form_data)
{
    size_t length;
    char boundary[60];
    int fd = -1, rc = WEBCLIENT_OK;
    char *header = NULL, *header_ptr;
    unsigned char *buffer = NULL, *buffer_ptr;
    struct webclient_session* session = NULL;

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
    {
        rc = -WEBCLIENT_FILE_ERROR;
        goto __exit;
    }

    /* get the size of file */
    length = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    buffer = web_malloc(WEBCLIENT_RESPONSE_BUFSZ);
    if (buffer == NULL)
    {
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    session = (struct webclient_session*) web_malloc(sizeof(struct webclient_session));
    if (!session)
    {
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }
    memset(session, 0x0, sizeof(struct webclient_session));

    rc = webclient_connect(session, URI);
    if (rc < 0)
        goto __exit;

    header = (char*) web_malloc(WEBCLIENT_HEADER_BUFSZ);
    if (header == NULL)
    {
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }
    header_ptr = header;

    /* build boundary */
    rt_snprintf(boundary, sizeof(boundary), "----------------------------%012d",
            rt_tick_get());

    /* build encapsulated mime_multipart information*/
    buffer_ptr = buffer;
    /* first boundary */
    buffer_ptr += rt_snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer), "--%s\r\n", boundary);
    buffer_ptr += rt_snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer),
            "Content-Disposition: form-data; %s\r\n", form_data);
    buffer_ptr += rt_snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer),
            "Content-Type: application/octet-stream\r\n\r\n");
    /* calculate content-length */
    length += buffer_ptr - buffer;
    length += strlen(boundary) + 6; /* add the last boundary */

    /* build header for upload */
    header_ptr += rt_snprintf(header_ptr,
            WEBCLIENT_HEADER_BUFSZ - (header_ptr - header),
            "Content-Length: %d\r\n", length);
    header_ptr += rt_snprintf(header_ptr,
            WEBCLIENT_HEADER_BUFSZ - (header_ptr - header),
            "Content-Type: multipart/form-data; boundary=%s\r\n", boundary);
    /* send header */
    rc = webclient_send_header(session, WEBCLIENT_POST, header,
            header_ptr - header);
    if (rc < 0)
        goto __exit;

    /* send mime_multipart */
    webclient_write(session, buffer, buffer_ptr - buffer);

    /* send file data */
    while (1)
    {
        length = read(fd, buffer, WEBCLIENT_RESPONSE_BUFSZ);
        if (length <= 0)
            break;
        webclient_write(session, buffer, length);
    }

    /* send last boundary */
    rt_snprintf((char*) buffer, WEBCLIENT_RESPONSE_BUFSZ, "\r\n--%s--\r\n", boundary);
    webclient_write(session, buffer, strlen(boundary) + 6);

__exit:
    if (fd >= 0) close(fd);
    if (session != NULL) webclient_close(session);
    if (buffer != NULL) web_free(buffer);
    if (header != NULL) web_free(header);

    return 0;
}

int wget(int argc, char** argv)
{
    if (argc != 3)
    {
        rt_kprintf("wget URI filename\n");
        return 0;
    }

    webclient_get_file(argv[1], argv[2]);
    return 0;
}
MSH_CMD_EXPORT(wget, web download file);

#endif
