#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <iostream>
#include <ctime>
#include <mutex>

using namespace std;

class Logger{
    private:
        ofstream file;
        string filename;
    public:
        Logger(const string &filename);
        ~Logger();
        void log(const string &request);
};

#endif