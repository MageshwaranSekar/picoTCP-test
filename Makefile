PICOTCP_INCLUDE=../picotcp/build/include
PICOTCP_LIB_PATH=../picotcp/build/lib
WOLFSSL_INCLUDE=../wolfssl
WOLFSSL_LIB_PATH=../wolfssl/src/.libs
PICOTCP_MODULES_INCLUDE=../TCP-IP_Stack/include
PICOTCP_MODULES_LIB_PATH=../TCP-IP_Stack/lib
CUSTOM_MALLOC_INCLUDE=../custom_malloc/include
CUSTOM_MALLOC_SRC_PATH=../custom_malloc/src
CC=gcc
CFLAGS+=-Wall -m32
OBJS=server_http_asym server_http_psk ping
ENABLE_PSK?=1
DEBUG?=0
PSK_FLAG=


ifeq	($(ENABLE_PSK),1)
	PSK_FLAG=-DUSE_TLS_PSK 
endif

ifeq	($(DEBUG),1)
	CFLAGS+=-DDEBUG 
endif

all: server_http_psk

server_http_psk: server_http_psk.o custom_memalloc.o
	$(CC) -o $@ $^ $(CFLAGS) -L $(PICOTCP_LIB_PATH) -lpicotcp -L $(PICOTCP_MODULES_LIB_PATH) -lstack -L $(WOLFSSL_LIB_PATH) -lwolfssl -lm

server_http_psk.o: server_http.c
	$(CC) -c $< -o $@ $(CFLAGS) $(PSK_FLAG) -I $(PICOTCP_INCLUDE) -I $(PICOTCP_MODULES_INCLUDE) -I $(CUSTOM_MALLOC_INCLUDE)

custom_memalloc.o: $(CUSTOM_MALLOC_SRC_PATH)/custom_memalloc.c
	$(CC) -c $< -o $@ $(CFLAGS) -I $(CUSTOM_MALLOC_INCLUDE)

ping: ping.o custom_memalloc.o
	$(CC) -o $@ $^ $(CFLAGS) -L $(PICOTCP_LIB_PATH) -lpicotcp

ping.o: ping_test.c
	$(CC) -c $< -o $@ $(CFLAGS) -I $(PICOTCP_INCLUDE) -I $(CUSTOM_MALLOC_INCLUDE)

clean:
	rm -f $(OBJS) *.o
