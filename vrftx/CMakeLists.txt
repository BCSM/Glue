cmake_minimum_required(VERSION 2.8.11)
project (vrftx)

link_directories(/usr/local/lib)

add_executable(vrftx main.c)
target_link_libraries(vrftx crypto ssl pthread)
