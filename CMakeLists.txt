cmake_minimum_required(VERSION 3.5)
project(GDBMemoryMapProblem)

aux_source_directory(src sourceFiles)

add_executable(${PROJECT_NAME} ${sourceFiles})