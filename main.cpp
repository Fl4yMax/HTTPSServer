#include "server.h"

using namespace std;

int main(){
    Server *server = Server::get_instance();
    server->start();

    delete server;
    return 0;
}