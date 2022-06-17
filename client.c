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

#define CLIENT_SIZE 1
#define CLIENT_IP "192.168.1.253"
#define CLIENT_PORT 10000

#define SERVER_IP "192.168.1.253"
#define SERVER_PORT 20000

#define CA_CERT "key/ca.pem"
#define CLIENT_CERT "key/peer2.pem"
#define CLIENT_KEY "key/peer2.key"

struct sockaddr_in addr_client[CLIENT_SIZE];
struct sockaddr_in addr_server;

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

/*
 * client
 */
int32_t main(int argc, char *argv[])
{
    printf("it is client\n");
    gnutls_session_t session[CLIENT_SIZE];
    gnutls_certificate_credentials_t x509_cred;
    int32_t ret;
    int sockfd[CLIENT_SIZE];
    int flag[CLIENT_SIZE] = {0};
    struct sockaddr_in addr_client;
    //init ssl
    gnutls_global_init();
    gnutls_certificate_allocate_credentials(&x509_cred);
    gnutls_certificate_set_x509_trust_file(x509_cred, CA_CERT, GNUTLS_X509_FMT_PEM);
    gnutls_certificate_set_x509_key_file(x509_cred, CLIENT_CERT, CLIENT_KEY, GNUTLS_X509_FMT_PEM);
    //init server
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(SERVER_PORT);
    addr_server.sin_addr.s_addr = inet_addr(SERVER_IP);
loop:
    //init client
    for(int i = 0; i < CLIENT_SIZE; i++)
    {
        //init socket
        addr_client.sin_family = AF_INET;
        addr_client.sin_port = htons(CLIENT_PORT + i);
        addr_client.sin_addr.s_addr = inet_addr(CLIENT_IP);

        sockfd[i] = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd[i] < 0)
        {
            perror(" Unable to create socket");
            exit(EXIT_FAILURE);
        }
        int reuse = 1;
        setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEADDR, (void *)&reuse, sizeof(int));

        if(bind(sockfd[i], (struct sockaddr *)&addr_client, sizeof(addr_client)) < 0)
        {
            perror("[%d] Unable to bind");
            exit(EXIT_FAILURE);
        }
    }

    for(int i = 0; i < CLIENT_SIZE; i++)
    {
        //make_non_block(sockfd[i]);
        ret = connect(sockfd[i], (struct sockaddr *)&addr_server, sizeof(addr_server));
        if(ret == 0)
        {
            printf("[%d] connect to server\n", i);
        }
        else
        {
            printf("connecting, error: %s\n",strerror(errno));
            while(1)
            {
            int err = -1;
            socklen_t len = sizeof(int);
            if(getsockopt(sockfd[i],  SOL_SOCKET, SO_ERROR, &err, &len) == 0)
            {
              printf("getopt, error: %s\n",strerror(err));
            }
            }
            printf("[%d] fail to connet to server.%s\n", i, strerror(errno));
            exit(EXIT_FAILURE);
        }
        
        
        //set_tcp_nodelay(sockfd);
    }
    //init ctx
    for(int i = 0; i < CLIENT_SIZE; i++)
    {
        gnutls_init(session + i, GNUTLS_CLIENT | GNUTLS_NONBLOCK);
        gnutls_credentials_set(session[i], GNUTLS_CRD_CERTIFICATE, x509_cred);
        gnutls_priority_set_direct(session[i], "NONE:+VERS-TLS-ALL:+MAC-ALL:+RSA:+NULL:+SIGN-ALL:+COMP-NULL", NULL);
        gnutls_handshake_set_timeout(session[i], GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

        gnutls_transport_set_int(session[i], sockfd[i]);
    }

    printf("start to handshake\n");

    while(1)
    {
        int num = 0;
        for(int i = 0; i < CLIENT_SIZE; i++)
        {
            if(flag[i] == 0)
            {
                ret = gnutls_handshake(session[i]);
                if(ret == GNUTLS_E_SUCCESS)
                {
                    printf("[%d] handshake success\n", i);
                    flag[i] = 1;
                    num += 1;
                    gnutls_record_send(session[i],"hello", 5);
                }
                else if(ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
                {
                    printf("[%d] handshake continue\n", i);
                    continue;
                }
                else if(ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
                {
                    printf("[%d] handshake alart\n", i);
                    flag[i] = -1;
                    num += 1;
                }
                else if(ret < 0)
                {
                    printf("[%d] handshake fail, %s\n", i, gnutls_strerror(ret));
                    flag[i] = -1;
                    num += 1;
                }
            }
        }

        if(num == CLIENT_SIZE)
        {
            break;
        }
    }

    /*end*/
    for(int i = 0; i < CLIENT_SIZE; i++)
    {
        close(sockfd[i]);
        gnutls_deinit(session[i]);
    }
    gnutls_certificate_free_credentials(x509_cred);
    gnutls_global_deinit();
    return 0;
}