cmake_minimum_required(VERSION 3.12)
project(X509)

set(CMAKE_CXX_STANDARD 14)
add_executable(X509 main.cpp X509.h X509.cpp staticNumbers.h)