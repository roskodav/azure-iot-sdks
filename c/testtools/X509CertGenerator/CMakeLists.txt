#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

#this is CMakeLists for X509CertGenerator
compileAsC99()
if(NOT DEFINED ENV{OpenSSLDir})
    message(STATUS "OpenSSLDir environment variable should be defined to proceed building X509 Generator")
else ()
    set(X509CertGenerator_c_files
    ./src/generateX509Cert.c
    )

    set(X509CertGenerator_h_files
    ./inc/generateX509Cert.h
    )

    #these are the include folders
    #the following "set" statetement exports across the project a global variable called X509CertGenerator_INC_FOLDER that expands to whatever needs to included when using X509CertGenerator library
    set(X509GenerateCert_INC_FOLDER ${CMAKE_CURRENT_LIST_DIR}/inc CACHE INTERNAL "this is what needs to be included if using X509CertGenerator" FORCE)

    add_library(X509CertGenerator ${X509CertGenerator_c_files} ${X509CertGenerator_h_files})

    if(WIN32)
        include_directories($ENV{OpenSSLDir}/include)
        include_directories(${X509GenerateCert_INC_FOLDER} ${SHARED_UTIL_INC_FOLDER})
        target_link_libraries(X509CertGenerator $ENV{OpenSSLDir}/lib/ssleay32.lib $ENV{OpenSSLDir}/lib/libeay32.lib)
        #windows needs this define
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
        add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
    else ()
        target_link_libraries(X509CertGenerator ssl)
    endif()

    linkSharedUtil(X509CertGenerator)

    set_target_properties(X509CertGenerator
               PROPERTIES
               FOLDER "test_tools")

    #executable for generating X509
    add_executable(generateX509 ./src/generateX509.c)
    target_link_libraries(generateX509 X509CertGenerator)

    set_target_properties(generateX509
               PROPERTIES
               FOLDER "test_tools")

endif()
