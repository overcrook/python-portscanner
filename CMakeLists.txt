cmake_minimum_required(VERSION 3.2)
project(python-portscanner)

find_package(Python COMPONENTS Interpreter Development)

if (NOT Python_FOUND)
    message(FATAL_ERROR "Python interpreter/development tools are not found")
endif()

find_library(LIB_PORTSCANNER portscanner)

if (NOT LIB_PORTSCANNER)
    message(STATUS "libportscanner is NOT FOUND. Using version from the submodule.")

    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
        option(GIT_SUBMODULE "Check submodules during build" ON)
        if(GIT_SUBMODULE)
            message(STATUS "Submodule update")
            execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                            RESULT_VARIABLE GIT_SUBMOD_RESULT)
            if(NOT GIT_SUBMOD_RESULT EQUAL "0")
                message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
            endif()
        endif()
    endif()

    set(LIB_PORTSCANNER portscanner)
    add_subdirectory(submodule/portscanner)
    include_directories(submodule/portscanner/include)
endif()

include_directories(${Python_INCLUDE_DIRS})
add_library(python-portscanner SHARED python_portscan.c)
target_link_libraries(python-portscanner ${LIB_PORTSCANNER} ${Python_LIBRARIES})
target_link_options(python-portscanner PRIVATE ${Python_LINK_OPTIONS})
