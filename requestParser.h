#ifndef REQUESTPARSER_H
#define REQUESTPARSER_H

#include <iostream>
#include <sstream>
#include <algorithm>
#include <unordered_map>

using namespace std;

class RequestParser{
    private:
        string extract_boundary(const string&);
    public:
        RequestParser();
        pair<unordered_map<string, string>, string> parse(string text);
};

#endif