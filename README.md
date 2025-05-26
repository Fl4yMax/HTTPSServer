### HTTP server implementation with SSL -> HTTPS
HTTPS server with multiple processes, error pages, images, php and logging

## COMPILE
 - g++ main.cpp server.cpp requestParser.cpp logger.cpp clientProcess.cpp -o run -lssl -lcrypto -lrt -lpthread

## RUN
 - ./run

## INFO
    https://localhost:8080/index.html

    for image showcase https://localhost:8080/kitten.jpg

    for script showcase https://localhost:8080/script.php

## EXIT
    ctrl + c