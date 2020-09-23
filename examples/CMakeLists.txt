find_library(POPT_LIBRARY popt)

list(APPEND CORE_LIBRARIES ${POPT_LIBRARY})

set(SOURCES smb2-cat
            smb2-ftruncate
            smb2-ls
            smb2-put
            smb2-stat
            smb2-stat-all
            smb2-truncate
            smb2-sharelist
            smb2-lookupsid
            smb2-getsd)

foreach(TARGET ${SOURCES})
  add_executable(${TARGET} ${TARGET}.cpp)
  target_link_libraries(${TARGET} ${CORE_LIBRARIES})
  target_link_libraries(${TARGET} smb2 gssapi_krb5 krb5)
  link_directories("${CMAKE_BINARY_DIR}/lib")
  add_dependencies(${TARGET} smb2)
endforeach()

add_definitions(-Werror "-D_U_=__attribute__((unused))")
