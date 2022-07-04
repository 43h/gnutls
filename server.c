#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <resolv.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <gnutls/x509.h>
#include <sys/select.h>
#include <pthread.h>
#include <sys/time.h>

#define CLIENT_NUM 1

#define SERVER_IP "192.168.1.253"
#define SERVER_PORT 20000
#define CLIENT_PORT 10000

int32_t sock_server;


#define CA_CERT "key/ca.pem"
#define SERVER_CERT "key/peer1.pem"
#define SERVER_KEY "key/peer1.key"

enum tls_tatus_t
{
    TLS_STATUS_NULL = 0,
    TLS_STATUS_CONNECTED,
    TLS_STATUS_HANDSHAKE,
    TLS_STATUS_OK,
    TLS_STATUS_MAX
};

typedef struct _client_info
{
    int32_t sockfd;           // client socket
    gnutls_session_t session; // tls session
    int32_t status;           // tls status
} client_info_t;

client_info_t client_info[CLIENT_NUM];

/******************************************/
gnutls_certificate_credentials_t x509_cred;
gnutls_priority_t priority_cache;

static void make_non_block(int fd)
{
    int flags, rv;
    while((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR)
        ;
    if(flags == -1)
    {
        printf("fcntl:%s\n", strerror(errno));
    }
    while((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR)
        ;
    if(rv == -1)
    {
        printf("fcntl:%s\n", strerror(errno));
    }
}

static void set_tcp_nodelay(int fd)
{
    int val = 1;
    int rv;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
    if(rv == -1)
    {
        printf("fcntl:%s\n", strerror(errno));
    }
}

void listen_thread(void *param)
{
    struct sockaddr_in addr_server;
    struct sockaddr_in addr_client;
    char address[INET_ADDRSTRLEN];
    sock_server = socket(AF_INET, SOCK_STREAM, 0);
    int fd;
    int len;
    if(sock_server < 0)
    {
        printf("[l]Unable to create socket");
        pthread_exit(NULL);
    }

    int reuse = 1;
    setsockopt(sock_server, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int));
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(SERVER_PORT);
    addr_server.sin_addr.s_addr = inet_addr(SERVER_IP);
    if(bind(sock_server, (struct sockaddr *)&addr_server, sizeof(addr_server)) < 0)
    {
        perror("[l]Unable to bind");
        pthread_exit(NULL);
    }

    if(listen(sock_server, 300) < 0)
    {
        perror("[l]Unable to listen");
        pthread_exit(NULL);
    }
    else
    {
        printf("[l]start to listen\n");
    }

    while(1)
    {
        len = sizeof(addr_client);
        fd = accept(sock_server, (struct sockaddr *)&addr_client, &len);
        if(fd != -1)
        {
            printf("[l]accept new connection,%s:%hu\n", inet_ntoa(addr_client.sin_addr), ntohs(addr_client.sin_port));
            make_non_block(fd);
            //save fd
            client_info[ntohs(addr_client.sin_port) - CLIENT_PORT].sockfd = fd;
            client_info[ntohs(addr_client.sin_port) - CLIENT_PORT].status = TLS_STATUS_CONNECTED;
            //set_tcp_nodelay(client);
        }
        else
        {
            printf("fail to accept client,%s\n", strerror(errno));
            pthread_exit(NULL);
        }
    }
    pthread_exit(NULL);
}

void work_thread(void *param)
{
    int ret;
    while(1)
    {
        for(int i = 0; i < CLIENT_NUM; i++)
        {
            if(client_info[i].status == TLS_STATUS_NULL)
                continue;

            else if(client_info[i].status == TLS_STATUS_CONNECTED)
            {
                gnutls_init(&client_info[i].session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
                gnutls_set_default_priority (client_info[i].session);
                //gnutls_priority_set(client_info[i].session, priority_cache);
                //gnutls_priority_set_direct(client_info[i].session, "NONE:+VERS-TLS-ALL:+MAC-ALL:+RSA:+NULL:+SIGN-ALL:+COMP-NULL", NULL);
                gnutls_credentials_set(client_info[i].session, GNUTLS_CRD_CERTIFICATE, x509_cred);
                gnutls_certificate_server_set_request(client_info[i].session, GNUTLS_CERT_REQUIRE);
                //gnutls_certificate_server_set_request(client_info[i].session, GNUTLS_CERT_IGNORE);
                gnutls_handshake_set_timeout(client_info[i].session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
                gnutls_transport_set_int(client_info[i].session, client_info[i].sockfd);
                gnutls_session_set_verify_cert(client_info[i].session, NULL, GNUTLS_VERIFY_DO_NOT_ALLOW_SAME);
                client_info[i].status = TLS_STATUS_HANDSHAKE;
            }

            if(client_info[i].status == TLS_STATUS_HANDSHAKE)
            {
                ret = gnutls_handshake(client_info[i].session);
                if(ret == GNUTLS_E_SUCCESS)
                {
                    printf("[h][%d] handshake success\n", i);
                    client_info[i].status = TLS_STATUS_OK;
                }
                else if(ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
                {
                    //printf("[h][%d] handshake continue\n", i);
                    continue;
                }
                else if(ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
                {
                    printf("[h][%d] handshake alart\n", i);
                }
                else if(ret < 0)
                {
                    printf("[h][%d] handshake fail %s...\n", i, gnutls_strerror(ret));
                    //raise(SIGQUIT);
                    gnutls_deinit(client_info[i].session);
                    close(client_info[i].sockfd);
                    client_info[i].sockfd = 0;
                    client_info[i].status = TLS_STATUS_NULL;
                    printf("[h][%d] close socke\n", i);
                }
            }

            if(client_info[i].status == TLS_STATUS_OK)
            {
                ;//gnutls_record_recv()
            }
        }
    }
    /*end*/
    pthread_exit(NULL);
}


//close all socket
void sig_handle(int sig)
{
    printf("clean all\n");
    for(int i = 0; i < CLIENT_NUM; i++)
    {
        if(client_info[i].sockfd != 0)
            close(client_info[i].sockfd);
    }

    close(sock_server);
    gnutls_certificate_free_credentials(x509_cred);
    gnutls_priority_deinit(priority_cache);
    gnutls_global_deinit();
    exit(0);
}

void init_client(void)
{
    for(int i = 0; i < CLIENT_NUM; i++)
    {
        client_info[i].sockfd = 0;
        client_info[i].status = 0;
    }
}

void tls_log(int level, const char *str)
{
    printf("%s\n", str);
}

int32_t main(int argc, char *argv[])
{
    pthread_t tid_listen;
    pthread_t tid_work;

    signal(SIGKILL, sig_handle);
    signal(SIGTERM, sig_handle);
    signal(SIGSTOP, sig_handle);
    signal(SIGQUIT, sig_handle);
    signal(SIGINT, sig_handle);

    printf("gnutls version:%s\n", gnutls_check_version(NULL));
    gnutls_global_init();
    gnutls_certificate_allocate_credentials(&x509_cred);
    gnutls_certificate_set_x509_trust_file(x509_cred, CA_CERT, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_key_file(x509_cred, SERVER_CERT, SERVER_KEY, GNUTLS_X509_FMT_PEM);
    //gnutls_global_set_log_function((gnutls_log_func)tls_log);
    //gnutls_global_set_log_level(99);

    //init thread
    pthread_create(&tid_listen, NULL, (void *)listen_thread, NULL);
    pthread_create(&tid_work, NULL, (void *)work_thread, NULL);

    pthread_join(tid_listen, NULL);
    pthread_join(tid_work, NULL);

    gnutls_certificate_free_credentials(x509_cred);
    gnutls_global_deinit();
    return 0;
}
