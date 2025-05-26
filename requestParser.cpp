#include "requestParser.h"

RequestParser::RequestParser(){}

pair<unordered_map<string, string>, string> RequestParser::parse(string text){
    unordered_map<string, string> request;
    istringstream stream(text);
    string line;
    string body;
    bool exists_content_type = false;
    int counter = 0;

    if (getline(stream, line)) {
        istringstream request_line(line);
        request_line >> request["method"] >> request["path"] >> request["version"];
    }

    while (getline(stream, line) && !line.empty()) {
        if(exists_content_type && line == request["boundary"]){
            break;
        }
        size_t pos = line.find(": ");
        if (pos != string::npos) {
            string key = line.substr(0, pos);
            string value = line.substr(pos + 2);

            if (!exists_content_type && key == "Content-Type" && request["method"] == "POST") {
                string boundary = extract_boundary(value);
                request["boundary"] = boundary;
                exists_content_type = true;
            }
            request[key] = value;
        }
    }

    if(exists_content_type && getline(stream, line)){
        size_t pos = line.find("filename=\"");
        if (pos != string::npos) {
            pos += 10;
            size_t end_pos = line.find("\"", pos);
            if (end_pos != string::npos) {
                request["filename"] = line.substr(pos, end_pos - pos);
            }
        }
    }

    while(exists_content_type && getline(stream, line)){
        body += line;
    }

    return {request, body};
}

string RequestParser::extract_boundary(const string& content_type) {
    size_t boundary_pos = content_type.find("boundary=");
    if (boundary_pos != string::npos) {
        return "--" + content_type.substr(boundary_pos + 9);
    }
    return "";
}