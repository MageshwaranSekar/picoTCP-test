PICOTCP_INCLUDE=../picotcp/build/include
PICOTCP_LIB_PATH=../picotcp/build/lib
WOLFSSL_INCLUDE=../wolfssl
WOLFSSL_LIB_PATH=../wolfssl/src/.libs
PICOTCP_MODULES_INCLUDE=../tcp-ip_stack/include
PICOTCP_MODULES_LIB_PATH=../tcp-ip_stack/lib
CC=gcc
CFLAGS+=-Wall
OBJS=server_http_asym server_http_psk ping

all: server_http_psk

server_http_psk: server_http.c
	$(CC) -o $@ $< $(CFLAGS) -DUSE_TLS_PSK -I $(PICOTCP_INCLUDE) -I $(WOLFSSL_INCLUDE) -I $(PICOTCP_MODULES_INCLUDE) -L $(PICOTCP_LIB_PATH) -lpicotcp -L $(PICOTCP_MODULES_LIB_PATH) -lstack -L $(WOLFSSL_LIB_PATH) -lwolfssl -lm

server_http_asym: server_http.c
	#$(CC) -o $@ $< $(CFLAGS) -I $(PICOTCP_INCLUDE) -I $(WOLFSSL_INCLUDE) -I $(PICOTCP_MODULES_INCLUDE) -L $(PICOTCP_LIB_PATH) -lpicotcp -L $(PICOTCP_MODULES_LIB_PATH) -lhttps -L $(WOLFSSL_LIB_PATH) -lwolfssl

ping: ping_test.c
	$(CC) -o $@ $< $(CFLAGS) -I $(PICOTCP_INCLUDE) -L $(PICOTCP_LIB_PATH) -lpicotcp

clean:
	rm -f $(OBJS) 
