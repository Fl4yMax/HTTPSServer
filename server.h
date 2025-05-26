#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <string>

#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/wait.h>
#include <csignal>
#include <math.h>
#include <tuple>
#include <vector>
#include <mqueue.h>
#include <array>

#include "logger.h"
#include "clientProcess.h"

#define PORT 8080
#define MAX_CLIENTS 10

#define CERT_FILE "keys/server.crt"
#define KEY_FILE "keys/server.key"

#define LOG_QUEUE "/log_queue"
#define PROCESS_QUEUE "/process_queue"
#define MAX_LOG_MSG_SIZE 1024
#define MAX_PROCESS_MSG_SIZE 8
#define MAX_QUEUE_SIZE 10

#define CONN_SEM "/connection_semaphore"

using namespace std;

class Server{
    private:
        //VARIABLES-----------------------
        static Server *instance_;
        SSL_CTX *ctx;
        mqd_t mq_log;
        mqd_t available_processes;
        char buffer[1024];
        sem_t *client_sem;
        int connected_clients;
        vector<ClientProcess*> clients;
        vector<array<int, 2>> sockets;

        //METHODS--------------------------
        void setup_sigchld_handler();
        static void sigchld_handler(int);
        static void signal_handler(int signum);

        //INITIALIZERS
        void init_ssl();
        void init_sem();
        void init_logger(const string);
        void init_processes();

        //Messagee queue load or creation
        mqd_t load_msg_queue(const char*, int, int, int);
        void load_SSL_ctx_and_certificates();

        void send_fd(int, int, int);
        pair<int, int> recv_fd(int);

        void prepare_connection(int&, struct sockaddr_in&, int&);
       // void process_client(int&, SSL*);
        void disconnect(int&, SSL*);
    public:
        Server();
        Server(Server&) = delete;
        ~Server();
        void operator=(const Server&) = delete;

        static Server *get_instance();
        void start();
};