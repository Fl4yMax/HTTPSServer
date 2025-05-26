#include "server.h"

Server* Server::instance_ = nullptr;

Server::Server(){
    this->connected_clients = 0;
}

Server::~Server(){
    for(int i = 0; i < MAX_CLIENTS; i++){
        delete this->clients[i];
    }
}

Server* Server::get_instance(){
    if(instance_ == nullptr){
        instance_ = new Server();
    }
    return instance_;
}

void Server::start(){
    mq_unlink(LOG_QUEUE);
    mq_unlink(PROCESS_QUEUE);
    mq_log = load_msg_queue(LOG_QUEUE, O_RDWR, MAX_LOG_MSG_SIZE, MAX_QUEUE_SIZE);
    signal(SIGINT, signal_handler);
    // string log_str = "Starting server... Maximum clients: " + MAX_CLIENTS;
    // if (mq_send(mq_log, log_str.c_str(), log_str.size(), 0) == -1) {
    //     perror("mq_send failed.");
    //     mq_close(mq_log);
    //     exit(EXIT_FAILURE);
    // }
    load_SSL_ctx_and_certificates();
    init_processes();
    init_logger("requestLog.txt");
    init_sem();
    init_ssl();

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    
    setup_sigchld_handler();

    prepare_connection(server_fd, address, opt);

    while(true){
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
            perror("Couldn't accept connection");
            exit(EXIT_FAILURE);
        } else {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
            uint16_t client_port = ntohs(address.sin_port);

            cout << "Parent process " << getpid() << " is passing the connection to child process." << endl;
            cout << "Client IP: " << client_ip << ", Port: " << client_port << endl;
            
            struct mq_attr attr;
            if (mq_getattr(available_processes, &attr) == 0) {
                if (attr.mq_curmsgs == 0) {
                    cout << "Maximum clients reached" << endl;
                    const string header = "HTTP/1.1 503 Service Unavailable\nContent-Type: text/html\n\n";
                    // ClientProcess proc = ClientProcess();
                    // mqd_t mq = load_msg_queue(LOG_QUEUE, O_RDONLY);
                    // SSL *ssl = SSL_new(ctx);
                    // if (!ssl) {
                    //     cerr << "Error creating SSL object" << endl;
                    //     exit(EXIT_FAILURE);
                    // }
                    // proc.process_connection(new_socket, mq, client_sem, ssl)
                    //proc.read_and_send("503.html", "www", header, ssl);

                    //SSL_shutdown(ssl);
                    //SSL_free(ssl);
                    close(new_socket);
                } else {
                    //cout << "Client connected" << endl;
                    this->connected_clients++;
                    string msg = "PEPE";
                    string idx_string;
                    idx_string.resize(MAX_PROCESS_MSG_SIZE);
                    ssize_t bytes_read = mq_receive(available_processes, &idx_string[0], MAX_PROCESS_MSG_SIZE, nullptr);
                    if (bytes_read == -1) {
                        perror("mq_receive failed.");
                        mq_close(available_processes);
                        exit(EXIT_FAILURE);
                    }
                    idx_string.resize(bytes_read);

                    // // Debug: Print received index as hex values
                    // std::cout << "Received index raw: ";
                    // for (char c : idx_string) {
                    //     std::cout << std::hex << (int)c << " ";
                    // }
                    // std::cout << "('" << idx_string << "')" << std::endl;

                    // // Trim possible whitespace (newlines, spaces, null characters)
                    // idx_string.erase(std::remove_if(idx_string.begin(), idx_string.end(), ::isspace), idx_string.end());

                    // // Check if idx_string is valid before calling stoi
                    // if (!std::all_of(idx_string.begin(), idx_string.end(), ::isdigit)) {
                    //     std::cerr << "Invalid index received: '" << idx_string << "'" << std::endl;
                    //     exit(EXIT_FAILURE);
                    // }
                    int idx = stoi(idx_string);
                    cout << "Server choosing index for client... IDX_NUM: " << idx_string << endl;
                    cout << "Sending FD: " << sockets[idx][0] << endl;
                    send_fd(sockets[idx][0], new_socket, idx);
                }
            }
        }
    }

    sem_close(client_sem);
    if (sem_unlink(CONN_SEM) != 0) {
        perror("sem_destroy");
        exit(EXIT_FAILURE);
    }
    close(server_fd);
    SSL_CTX_free(ctx);
    mq_unlink(LOG_QUEUE);
    mq_unlink(PROCESS_QUEUE);
}

void Server::init_ssl(){
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void Server::init_sem(){
    sem_unlink(CONN_SEM);
    client_sem = sem_open(CONN_SEM, O_CREAT, 0644, MAX_CLIENTS);
    if (client_sem == SEM_FAILED) {
        perror("sem_open failed");
    }
}

void Server::init_logger(const string filename){
    if(fork() == 0){
        //mqd_t mq = load_msg_queue(LOG_QUEUE, O_RDONLY, MAX_LOG_MSG_SIZE, MAX_QUEUE_SIZE);
        Logger logger = Logger(filename);
        while(true){
            string msg;
            msg.resize(MAX_LOG_MSG_SIZE);
            ssize_t bytes_read = mq_receive(mq_log, &msg[0], MAX_LOG_MSG_SIZE, nullptr);
            if (bytes_read == -1) {
                perror("mq_receive failed.");
                mq_close(mq_log);
                exit(EXIT_FAILURE);
            }
            msg.resize(bytes_read);
            logger.log(msg);
        }
    }
}

void Server::init_processes(){
    available_processes = load_msg_queue(PROCESS_QUEUE, O_RDWR | O_NONBLOCK, MAX_PROCESS_MSG_SIZE, MAX_QUEUE_SIZE);
    for(int i = 0; i < MAX_CLIENTS; i++){
        ClientProcess *new_process = new ClientProcess(mq_log, available_processes);
        clients.push_back(new_process);
        array<int, 2> sv;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv.data()) == -1) {
            perror("socketpair failed");
            exit(EXIT_FAILURE);
            //return 1;
        }
        sockets.push_back(sv);
        
        string strindex = to_string(i);
        
        if (mq_send(available_processes, strindex.c_str(), strindex.size(), 0) == -1) {
            perror("available processes queue failed.");
            mq_close(available_processes);
            exit(EXIT_FAILURE);
        }
        
        if(fork() == 0){
            while(true){
                close(sv[0]);
                pair<int, int> result = recv_fd(sv[1]);
                cout << "FD received " << result.first << endl;
                SSL *ssl = SSL_new(ctx);
                if (!ssl) {
                    cerr << "Error creating SSL object" << endl;
                    exit(EXIT_FAILURE);
                }
                new_process->process_connection(result.first, ssl, result.second);
            }
            close(sv[1]);
        }
    }
}

void Server::send_fd(int socket, int fd, int idx) {
    struct msghdr msg = {0};
    struct iovec io;
    //vector<char> msg_buffer(message.begin(), message.end()); 
    char cmsgbuf[CMSG_SPACE(sizeof(fd))];
    int index_net = htonl(idx);

    io.iov_base = &index_net;
    io.iov_len = sizeof(index_net);

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    *((int *)CMSG_DATA(cmsg)) = fd;

    if (sendmsg(socket, &msg, 0) == -1) {
        perror("sendmsg");
        exit(EXIT_FAILURE);
    }
}

pair<int, int> Server::recv_fd(int socket) {
    struct msghdr msg = {0};
    struct iovec io;
    char buf[1048] = {0};
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    int index_net = 0;

    io.iov_base = &index_net;
    io.iov_len = sizeof(index_net);

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = CMSG_SPACE(sizeof(int));

    if (recvmsg(socket, &msg, 0) == -1) {
        perror("recvmsg");
        exit(EXIT_FAILURE);
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        fprintf(stderr, "Invalid control message\n");
        exit(EXIT_FAILURE);
    }

    int received_fd = *((int *)CMSG_DATA(cmsg));
    int received_index = ntohl(index_net);

    return {received_fd, received_index};
}

mqd_t Server::load_msg_queue(const char* name, int flags, int msg_max_size, int msg_count){
    mqd_t mq = mq_open(name, flags, 0666, NULL);
    if (mq == (mqd_t)-1) {
        mq_unlink(name);

        struct mq_attr attr;
        attr.mq_flags = 0;
        attr.mq_maxmsg = msg_count;
        attr.mq_msgsize = msg_max_size;
        attr.mq_curmsgs = 0;

        mq = mq_open(name, O_CREAT | flags, 0666, &attr);
        if (mq == (mqd_t)-1) {
            perror(strcat((char*)"mq_create failed", name));
        }   
    } else {
        cout << "Message queue loaded." << endl;
        return mq;
    }

    cout << "Message queue created." << endl;
    return mq;
}

void Server::signal_handler(int signum) {
    cout << "\nInterrupt signal (" << signum << ") received. Exiting gracefully...\n";
    while (waitpid(-1, nullptr, 0) > 0) {
        cout << "Child process terminated." << endl;
    }
    mq_unlink(LOG_QUEUE);
    mq_unlink(PROCESS_QUEUE);
    exit(signum);
}

void Server::sigchld_handler(int signo) {
    while (waitpid(-1, nullptr, WNOHANG) > 0){
        cout << "Child process terminated." << endl;
    }
}

void Server::setup_sigchld_handler() {
    struct sigaction sa;
    sa.sa_handler = Server::sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;

    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

void Server::prepare_connection(int &server_fd, struct sockaddr_in &address, int &opt){
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET,SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
}

void Server::load_SSL_ctx_and_certificates(){
    const SSL_METHOD *method = TLS_server_method();
    this->ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        cout << "SSL context created" << endl;
    }
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        cout << "Certificate loaded" << endl;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    } else {
        cout << "Private key loaded" << endl;
    }
}