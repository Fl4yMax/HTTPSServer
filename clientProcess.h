#ifndef CLIENTPROCESS_H
#define CLIENTPROCESS_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <tuple>
#include <string>
#include <mqueue.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/wait.h>

#include "requestParser.h"

#define CONN_SEM "/connection_semaphore"

using namespace std;

class ClientProcess{
    private:
        SSL* ssl;
        int socket;
        mqd_t mq_log;
        mqd_t mq_available;
        //Named semaphore

        string get_extension(const string&);
        tuple<string, string> get_directory_from_extension(string);
        int list_files(string, string);
        void disconnect(int&, SSL*, int);
        int read_and_send(const string, const string, const string, SSL*);
        int save_file(const string, const string, const string, string&, int, unordered_map<string, string>);
        void execute_script(string);
    public:
        ClientProcess(mqd_t&, mqd_t&);
        ~ClientProcess();

        int process_connection(int&, SSL*, int);
};

#endif