#ifndef WEBCLIENT_INTERNAL_H__
#define WEBCLIENT_INTERNAL_H__

#include <rtthread.h>

#define web_malloc  rt_malloc
#define web_free    rt_free
#define web_realloc rt_realloc
#define web_calloc  rt_calloc

#endif
