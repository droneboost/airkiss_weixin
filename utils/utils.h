#ifndef _UTILS_H
#define _UTILS_H

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

#include <stdio.h>
#define RECV_BUFSIZE 1024
#define LOG_ERROR(format, ...) fprintf(stderr, format"\n", ##__VA_ARGS__)
#define LOG_TRACE(format, args...) fprintf(stdout, format"\n", ##args)

#endif

