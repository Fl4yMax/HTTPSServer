#include "clientProcess.h"

ClientProcess::ClientProcess(mqd_t& mq_log, mqd_t& mq_available){
    this->mq_log = mq_log;
    this->mq_available = mq_available;
}

ClientProcess::~ClientProcess(){
    cout << "Ending process..." << endl;
    mq_close(mq_log);
    mq_close(mq_available);
}

string ClientProcess::get_extension(const string& filename) {
    return filesystem::path(filename).extension().string();
}

tuple<string, string> ClientProcess::get_directory_from_extension(string extension){
    static const unordered_map<string, tuple<string, string>> folder_and_mime = {
        {".html", {"www", "text/html"}},
        {".css", {"styles", "text/css"}},
        {".js", {"scripts", "text/javascript"}},
        {".php", {"scripts", "application/x-httpd-php"}},
        {".jpg", {"pictures", "image/jpeg"}},
        {".png", {"pictures", "image/png"}},
        {".jpeg", {"pictures", "image/jpeg"}},
        {".mp3", {"music", "audio/mpeg"}},
        {".mp4", {"videos", "video/mpeg"}},
        {".pdf", {"documents", "application/pdf"}},
        {".txt", {"texts", "text/plain"}}
    };

    auto it = folder_and_mime.find(extension);
    if (it != folder_and_mime.end()) {
        return it->second;
    }

    return {"unknown", "unknown"};
}

int ClientProcess::list_files(string directory, string filename){
    if(directory == "unknown"){
        return 1;
    }
    for (const auto& entry : filesystem::directory_iterator(directory)){
        cout << entry << endl;
        if(entry.path() == directory + "/" + filename){
            return 0;
        }
    }
    return 1;
}

int ClientProcess::read_and_send(const string filename, const string directory, const string header, SSL* ssl){
    ifstream file;

    file.open(directory + "/" + filename, ios::binary);

    if(!file.is_open()){
        cout << "Error opening file: " << filename << endl;
        return -1;
    } else {
        //cout << "File from dir: " << directory << " with name: " << filename << " was opened succesfully." << endl;

        SSL_write(ssl, header.c_str(), header.length());
        const size_t buffer_size = 2048;
        char buffer[buffer_size];

        while (!file.eof()) {
            file.read(buffer, buffer_size);
            streamsize bytes_read = file.gcount();
            if (bytes_read > 0) {
                SSL_write(ssl, buffer, bytes_read);
            }
        }
    }
    return 0;
}

int ClientProcess::save_file(const string filename, const string directory, const string header, string &initial_body, int content_length, unordered_map<string, string> request){
    ofstream file(directory + "/" + filename, ios::binary);
    if (!file) {
        cerr << "Error opening file for writing: " << filename << endl;
        return -1;
    }

    file.write(initial_body.c_str(), initial_body.size());
    
    int bytes_remaining = content_length - initial_body.size();
    char buffer[4096];

    while (bytes_remaining > 0) {
        int bytes_to_read = min(bytes_remaining, (int)sizeof(buffer));
        ssize_t bytes_read = SSL_read(ssl, buffer, bytes_to_read);
        
        if (bytes_read <= 0) {
            cerr << "Error reading from SSL socket." << endl;
            break;
        }

        file.write(buffer, bytes_read);
        bytes_remaining -= bytes_read;
    }

    file.close();
    cout << "File received and saved: " << filename << endl;
    return 0;
}

void ClientProcess::execute_script(string path){
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
    }
    int pid = 0;

    if(pid = fork() == 0){
        close(pipefd[0]);
        
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        close(pipefd[1]);

        char *args[] = {(char*)"/usr/bin/php", (char*)path.c_str(), NULL};

        int exec_result = execve("/usr/bin/php", args, NULL);
        cout << "I shouldnt print..." << endl;
        if (exec_result == -1) {
            perror("execve failed");
            exit(EXIT_FAILURE);
        }
    }
    close(pipefd[1]);

    string httpHeader =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "X-Server: MyCppServer\r\n"
    "Connection: close\r\n\r\n";
        
    SSL_write(ssl, httpHeader.c_str(), httpHeader.length());

    char buffer[4096];
    ssize_t bytesRead;
    while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
        SSL_write(ssl, buffer, bytesRead);
    }

    close(pipefd[0]);
    waitpid(pid, NULL, 0);
}

int ClientProcess::process_connection(int &fd, SSL* ss, int idx){
    this->ssl = ss;
    SSL_set_fd(ssl, fd);
    // SSL handshake
    if (SSL_accept(ssl) <= 0) {
        cout << "Couldn't accept SSL connection in child process" << endl;
        ERR_print_errors_fp(stderr);
        disconnect(fd, ssl, idx);
        return -1;
    }
    //cout << "Accepted SSL Connection..." << endl;

    struct sockaddr_in client_address;
    socklen_t addr_len = sizeof(client_address);
    getpeername(fd, (struct sockaddr*)&client_address, &addr_len);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_address.sin_addr, client_ip, INET_ADDRSTRLEN);
    uint16_t client_port = ntohs(client_address.sin_port);

    cout << "Child process " << getpid() << " is handling client connection." << endl;
    cout << "Client IP: " << client_ip << ", Port: " << client_port << endl;

    string buffer;
    buffer.resize(4096);

    ssize_t bytes_read = SSL_read(ssl, &buffer[0], buffer.size()); 
    cout << buffer << endl;

    if (bytes_read < 0) {
        std::cerr << "SSL_read failed!" << std::endl;
        ERR_print_errors_fp(stderr);
        return -1;
    }
    buffer.resize(bytes_read);

    //ssize_t bytesRead;
   // while ((bytesRead = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        //SSL_write(ssl, buffer, bytesRead);

    RequestParser parser;
    pair<unordered_map<string, string>, string> result = parser.parse(buffer);
    unordered_map<string, string> request = result.first;
    string body = result.second;

     for (const auto& pair : request) {
         cout << "Key: " << pair.first << ", Value: " << pair.second << endl;
     }

    if(request["method"] != ""){
        cout << "Method: " << request["method"] << " file: " << request["path"] << " version: " << request["version"] << endl;
        string msg = request["method"] + " " + request["path"] + " " + request["version"];
        if (mq_send(mq_log, msg.c_str(), msg.size(), 0) == -1) {
            perror("log mq_send failed in client.");
            mq_close(mq_log);
            //exit(EXIT_FAILURE);
        }
    }

    if(request["method"] == "GET"){
        string filename = request["path"];
        //cout << "Page requested: " << filename << endl;

        string extension = get_extension(filename);
        auto [dir, mime] = get_directory_from_extension(extension);
        
        //cout << "Folder: " << dir << ", MIME: " << mime << endl
        if(list_files(dir, filename) == 0){
            const string header = "HTTP/1.1 200 OK\nContent-Type: " + mime + "\n\n";
            if(dir == "scripts"){
                execute_script(dir + "/" + filename);
            } else {
                read_and_send(filename, dir, header, ssl);
            }
        } else {
            const string header = "HTTP/1.1 404 Not Found\nContent-Type: " + mime + "\n\n";
            read_and_send("404.html", "www", header, ssl);
        }
    }
    else if(request["method"] == "POST"){
        string filename = request["filename"];
        string extension = get_extension(filename);
        auto [dir, mime] = get_directory_from_extension(extension);

        cout << "Filename is: " << filename << "Extension is: " << extension << "Directory is... " << dir << endl;

        const string header = "HTTP/1.1 200 OK\nContent-Type: " + mime + "\n\n";
        int content_length = stoi(request["Content-Length"]);
        save_file(filename, dir, header, body, content_length, request);
    } else {
        cout << "Unknown request received." << endl;
    }

    disconnect(fd, ssl, idx);   
    return 0;
}

void ClientProcess::disconnect(int &new_socket, SSL *ssl, int idx){

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);

    string strindex = to_string(idx);
    cout << "Client returning its index to pool... IDX_NUM: " << strindex << endl;
    if (mq_send(mq_available, strindex.c_str(), strindex.size(), 0) == -1) {
        perror("available mq_send failed in client.");
        //mq_close(mq_log);
        //exit(EXIT_FAILURE);
    }
    struct mq_attr attr;
    if (mq_getattr(mq_available, &attr) == -1) {
        perror("mq_getattr");
    } else {
        cout << "Messages in queue: " << attr.mq_curmsgs << endl;
    }
    //cout << "Client disconnected" << endl;
}