cmake_minimum_required(VERSION 3.8)
project(h3c)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES
        main.c
        echo.h
        echo.c
        h3c.h
        h3c.c
        handler.h
        handler.c
        ./md5/md5.h
        ./md5/md5.c
        )

add_executable(h3c ${SOURCE_FILES})