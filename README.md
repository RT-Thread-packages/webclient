# WebClient介绍 #

本章节是webclient的使用和API说明，描述了如何使用webclient与WEB Server通信。


### webclient设计简介 ###

webclient是**HTTP**协议的客户端工具，提供与WEB Server通信的基本功能。
一般而言，设备端运行RT-Thread开源实时系统，并使用webclient提供的API与 HTTP 服务器交互。

### webclient会话结构体定义 ###

webclient底层操作接口都使用了统一的webclient客户端会话:  `struct webclient_session`，它被定义成:

``` C
struct webclient_session
{
    /* the session socket */
    int socket;
    /* the response code of HTTP request */
    int response;

    /* transfer encoding */
    char *transfer_encoding;
    int chunk_sz;
    int chunk_offset;

    /* content_type of HTTP response */
    char *content_type;
    /* content_length of HTTP response */
    int  content_length;

    /* last modified timestamp of resource */
    char *last_modified;

    /* location */
    char *location;

    /* server host */
    char *host;
    /* HTTP request */
    char *request;

    /* private for webclient session. */

    /* position of reading */
    unsigned int position;

    /* remainder of content reading */
    size_t content_length_remainder;
};
```

其中当服务端有回应时:

* response：会存储服务端的相应代码，如果成功，服务端回复:200；详细描述请参考 HTTP 状态码表。
* content_type：服务端提供的内容类型。
* content_length：服务端返回的数据长度。



## webclient API说明 ##


### webclient会话接口 ###


webclient底层接口定义了面向http这层的公共访问接口（流方式接口），可以基于这层接口进行底层的http操作。


#### webclient_open ####


``` C
struct webclient_session* webclient_open(const char* URI);
```

* 功能: 打开一个webclient客户端
* 参数1: URI 指向相应的网址，可以包括域名，特殊的端口号等。例如:
`URI = "http://www.test.com:8080/index.html"`

* 返回值: 成功返回一个webclient客户端会话；失败返回RT_NULL

webclient_open用于打开一个webclient会话，默认方法为get。
返回时，客户端就已经解析了http返回头部，里面有status_code及resp_len。
根据这些信息可以做进一步处理，如使用webclient_read读取服务器返回的数据。


#### webclient_open_header ####

``` C
struct webclient_session* 
webclient_open_header(const char* URI, int method,
				      const char* header, size_t header_sz);
```

* 功能: 在打开会话时可以加入一些自定义的HTTP请求头信息
* 参数1:  URI，指向相应的网址，可以包括域名，特殊的端口号等。例如:
`URI = "http://www.test.com:8080/index.html"`


* 参数2: method，定义了打开URI的方法，当前支持GET（WEBCLIENT_GET）或POST（WEBCLIENT_POST)
* 参数3: header信息，例如:

``` C
"Host: www.host.com\r\n"
"User-Agent: YourAgent\r\n"
"Content-Type: application/x-www-form-urlencoded\r\n"
```

header信息中必须使用"CR+LF"(回车+换行)作为分隔符和结束符。
header中每项应该符合HTTP的协议标准。
而一些基本的信息，例如Host，HTTP/1.0等信息，如果header中不存在，webclient会自动添加。

* 返回值: 成功返回一个webclient客户端会话；失败返回RT_NULL

webclient_open_header用于打开一个webclient会话，method由用户指定。
相比webclient_open接口，webclient_open_header可以自定义请求的header。



#### webclient_close ####


``` C
int webclient_close(struct webclient_session* session);
```

* 功能: 关闭一个webclient客户端
* 参数1: session指向要关闭的webclient客户端会话
* 返回值: 0

webclient_close用于关闭webclient一个会话。




### webclient数据接口 ###


#### webclient_read ####


``` C
int webclient_read (struct webclient_session* session, 
					unsigned char *buffer, size_t size);
```

* 功能: 从http连接中读取一段数据（非服务端响应的http header）
* 参数1: session，一个webclient客户端会话
* 参数2: buffer，保存从http连接中读取的数据的缓冲区
* 参数3: size，每次读取的最大数据
* 返回值: 成功返回读到的数据长度；失败返回负数

webclient_read从webclient会话中读取数据。

#### webclient_write ####


``` C
int webclient_write(struct webclient_session* session, 
					const unsigned char *buffer, size_t size);
```

* 功能: 向http连接发送一段数据
* 参数1: session，一个webclient客户端会话
* 参数2: buffer，要发送的数据的缓冲区
* 参数3: size，要发送的数据的长度
* 返回值: 成功发送的数据长度

webclient_write向webclient会话写入数据。

### webclient应用接口 ###


#### webclient传输数据 ####

``` C
int webclient_transfer(const char* URI, const char* header, 
                         size_t header_sz,
						 const char* data, size_t data_sz,
						 char *result, size_t result_sz);
```

* 功能: 向指定的URI传递数据data（同时也设置附加的HTTP请求头部信息为header)，并读取结果到result缓冲区中。函数返回读取到的数据长度。
* 参数1: URI，指向相应的网址，可以包括域名，特殊的端口号等。
* 参数2: header信息。
* 参数4: header信息的长度。
* 参数4: data，要发送的数据
* 参数5: size，要发送的数据的长度
* 参数6: result，用于保存从服务器接收到的数据缓冲区，当不需要保存时，可以为空。
* 参数7: result_sz，用于保存从服务器接收到的数据缓冲区长度。
* 返回值: 成功发送的数据长度

> 注：webclient_transfer会自动创建一个session，并在传输完成后关闭session。

#### webclient文件下载 ####

``` C
int webclient_get_file(const char* URI, const char* filename);
```

这个函数用于从URI下载一个文件，并保存到filename指定的路径上。保存的文件仅包括服务端提供的文件，而不包括HTTP响应的头部信息。例如下面的例子:

``` C
/*
* 服务端的文件test.txt，放于webroot目录下(web路径的根目录下)，其内容是:
* "this is a test.\n"
*/
void test(void)
{
	/* 下载test.txt文件 */
	webclient_get_file("http://www.test.com/test.txt", "/test.txt");
}
/*
* 保存在本地根目录的test.txt文件的内容是:
* "this is a test.\n"
*/
```




#### webclient文件上传 ####

``` C
int webclient_post_file(const char* URI, 
                   const char* filename, 
				   const char* form_data);
```

这个函数用于从filename路径的文件中读取数据，并向URI以POST方法发送这个文件的
内容；
例如用于上传的form是:

``` C
<form action="uploader.php" method="post" enctype="multipart/form-data">
<label for="file">Filename:</label>
<input type="file" name="file" id="file" />
<br />
<input type="submit" name="submit" value="Submit" />
</form>
```

参数form_data可以填充服务端关心的类型信息，例如:

``` C
"name=\"file\"; filename=\"test.txt\""
```

这样，服务端可以得到filename的值是“test.txt”。

## webclient测试及示例程序 ##

下面的例子是一个使用webclient底层接口的例子

``` C
#include <http_client.h>
#include <dfs_posix.h>
#define BUF_SZ 4096
void webclient_test(void)
{
	int fd = -1;
	int offset;
	rt_uint8_t* ptr = RT_NULL;
	struct webclient_session* session = RT_NULL; /* webclient客户端会话 */

	session = webclient_open("http://www.test.com/index.html");
	if (session == RT_NULL)
	{
		rt_kprintf("open website failed.\n");
		goto __exit;
	}

	if (session->response != 200)
	{
		/* 服务端给出错误的响应 */
		rt_kprintf("wrong response: %d\n", session->response);
		goto __exit;
	}

	if (strcmp(session->content_type, "text/html") != 0)
	{
		/* 不是自己关心的内容类别，退出 */
		rt_kprintf("context_type: %d\n", session->content_type);
		goto __exit;
	}

	fd = open("/index.html", O_WRONLY | O_CREAT, 0);
	if (fd < 0)
	{
		/* 创建文件出错，返回 */
		rt_kprintf("open file failed\n");
		goto __exit;
	}

	/* 分配需要的缓冲 */
	ptr = rt_malloc (BUF_SZ);
	if (ptr == RT_NULL)
	{
		rt_kprintf("out of memory\n");
		goto __exit;
	}

	if (session->content_length == 0)
	{
		/* 如果服务端未给出数据内容长度，读取数据直到服务端关闭连接 */
		while (1)
		{
		length = webclient_read(session, ptr, BUF_SZ);
		if (length > 0) write(fd, ptr, length);
		else break;
		}
	}
	else
	{
		for (offset = 0; offset < session->content_length; )
		{
			/* 从连接读取数据 */
			length = webclient_read(session, ptr,
			session->content_length - offset > BUF_SZ?
			BUF_SZ:session->content_length - offset);
			/* 写入到文件中 */
			if (length > 0) write(fd, ptr, length);
			else break;
			/* 挪动偏移位置 */
			offset += length;
		}
	}

__exit: /* 退出出口 */
	if (session != RT_NULL) webclient_close(session);
	if (fd >= 0) close(fd);
	if (ptr != RT_NULL) rt_free(ptr);
	return;
}
```

