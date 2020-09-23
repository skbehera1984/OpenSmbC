set(SOURCES NtError.cpp
            Stringf.cpp
            DataTypes.cpp
            NtlmAuthProvider.cpp
            Krb5AuthProvider.cpp
            Smb2Context.cpp
            Smb2Socket.cpp
            Smb2Pdu.cpp
            Smb2Negotiate.cpp
            Smb2SessionSetup.cpp
            Smb2TreeConnect.cpp
            Smb2TreeDisconnect.cpp
            Smb2Logoff.cpp
            Smb2Create.cpp
            Smb2Close.cpp
            Smb2Echo.cpp
            Smb2Flush.cpp
            Smb2QueryDir.cpp
            Smb2QueryInfo.cpp
            Smb2SetInfo.cpp
            Smb2Read.cpp
            Smb2Write.cpp
            Smb2Ioctl.cpp
            Smb2DataFile.cpp
            Smb2DataFs.cpp
            Smb2DataSecurity.cpp
            Smb2RequestBuilder.cpp
            Smb2Api.cpp
            util.cpp
            DceRpc.cpp)

if(OPENSSL_FOUND)
  list(APPEND SOURCES Smb2Signing.cpp)
endif()

add_library(smb2 ${SOURCES})
target_link_libraries(smb2 PUBLIC ${core_DEPENDS} ${CORE_LIBRARIES})
set_target_properties(smb2 PROPERTIES
                           VERSION ${PROJECT_VERSION}
                           SOVERSION ${SOVERSION})
if(NOT MSVC)
  add_definitions("-D_U_=__attribute__((unused))")
else()
  add_definitions("-D_U_=")
  if(CMAKE_SYSTEM_NAME STREQUAL WindowsStore)
    add_definitions("-D_MSC_UWP")
  endif()
endif()

install(TARGETS smb2 EXPORT smb2
                     RUNTIME DESTINATION bin
                     ARCHIVE DESTINATION lib
                     LIBRARY DESTINATION lib)
