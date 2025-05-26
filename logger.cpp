#include "logger.h"

Logger::Logger(const string &filename){
    this->filename = filename;
    file.open(this->filename, ios::app);
    if(!file.is_open()){
        cout << "Error opening file: " << this->filename << endl;
        exit(EXIT_FAILURE);
    }
};

Logger::~Logger(){
    if(file.is_open()){
        file.close();
    }
};

void Logger::log(const string &request){
    time_t now = time(0);
    tm *ltm = localtime(&now);
    char timestamp[20];

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", ltm);
    file << timestamp << " " << request << endl;
};