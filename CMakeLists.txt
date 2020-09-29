cmake_minimum_required (VERSION 2.8)
project (OpenSmbC)

#switch this ON to build shared library
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_EXAMPLES "Build example programs" ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -O2 -fshort-wchar -Werror -Wno-unused-but-set-variable -Wno-strict-aliasing -Wno-narrowing -Wno-literal-suffix")

#not sure if it should be here
add_definitions(-D_REENTRANT -DR_LINUX_3 -D_POSIX_PTHREAD_SEMANTICS -D_GNU_SOURCE=1)

#get the target architecture
# each output has a '\n' which needs to be truncated
EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE MARCH)
EXECUTE_PROCESS( COMMAND uname -s COMMAND awk "{ print tolower($$1) }" COMMAND tr -d '\n' OUTPUT_VARIABLE OS)
set(ARCH ${MARCH}-${OS})

message("Build Architecture = " ${ARCH})

include_directories("${PROJECT_SOURCE_DIR}/include")

# check for the gssapi libraries and headers
find_library(GSSAPI_LIBRARY NAMES gssapi_krb5)
find_path(GSSAPI_INCLUDE_DIR NAMES gssapi.h gssapi/gssapi.h)

if (GSSAPI_LIBRARY AND GSSAPI_INCLUDE_DIRS)
  set(GSSAPI_FOUND TRUE)
endif ()

if(GSSAPI_FOUND)
  set(GSSAPI_LIBRARIES ${GSSAPI_LIBRARY})
  set(GSSAPI_INCLUDE_DIRS ${GSSAPI_INCLUDE_DIR})
endif()

set(core_DEPENDS ${GSSAPI_LIBRARIES} CACHE STRING "" FORCE)

add_definitions(-DHAVE_LIBKRB5)
#check for OpneSSL library
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND CORE_LIBRARIES ${OPENSSL_LIBRARIES})

if(OPENSSL_FOUND)
  add_definitions(-DHAVE_OPENSSL_LIBS)
endif()

if(ENABLE_EXAMPLES)
  add_subdirectory(examples)
endif()

add_subdirectory (src)
