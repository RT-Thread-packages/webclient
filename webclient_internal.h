#ifndef WEBCLIENT_INTERNAL_H__
#define WEBCLIENT_INTERNAL_H__

#include <rtthread.h>

#ifdef RT_USING_PSRAM
#include <drv_sdram.h>

#define web_malloc  sdram_malloc
#define web_free    sdram_free
#define web_realloc sdram_realloc
#define web_calloc  sdram_calloc
#else
#define web_malloc  malloc
#define web_free    free
#define web_realloc realloc
#define web_calloc  calloc
#endif

#endif
