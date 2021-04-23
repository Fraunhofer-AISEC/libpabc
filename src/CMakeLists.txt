add_library(pabc
  SHARED
  attributes.c
  context.c
  hash.c
  issuer.c
  json_creds.c
  nonce.c
  serialize.c
  user.c
  utils.c
  verifier.c
)

#set_property(TARGET pabc PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(pabc PUBLIC ${SOURCE_DIR}/include)
target_include_directories(pabc PUBLIC ${BINARY_DIR}/include)
find_library(GMP_LIB gmp REQUIRED)
find_library(JANSSON_LIB jansson REQUIRED)
find_library(B64_LIB b64 REQUIRED)
find_path(GMP_PATH gmp.h REQUIRED)
target_include_directories(pabc PUBLIC ../include)
target_include_directories(pabc PUBLIC ${GMP_PATH})
target_link_libraries(pabc PUBLIC ${GMP_LIB})
target_link_libraries(pabc PRIVATE
  ${BINARY_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}relic_s${CMAKE_STATIC_LIBRARY_SUFFIX})
target_link_libraries(pabc PUBLIC ${JANSSON_LIB})
target_link_libraries(pabc PUBLIC ${B64_LIB})

add_dependencies(pabc relic)

add_executable(pabc-issuer
  pabc-issuer.c
  cli_helper.c)
target_include_directories(pabc-issuer PUBLIC ../include)
target_link_libraries(pabc-issuer PRIVATE pabc)

add_executable(pabc-user
  pabc-user.c
  cli_helper.c)
target_include_directories(pabc-user PUBLIC ../include)
target_link_libraries(pabc-user PRIVATE pabc)

add_executable(pabc-verifier
  pabc-verifier.c
  cli_helper.c)
target_include_directories(pabc-verifier PUBLIC ../include)
target_link_libraries(pabc-verifier PRIVATE pabc)

include(GNUInstallDirs)
install(TARGETS pabc
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS pabc-user pabc-issuer pabc-verifier
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
