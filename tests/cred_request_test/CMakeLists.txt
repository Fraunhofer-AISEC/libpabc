add_executable(02_cred_request
  02_cred_request.c
  ${PROJECT_SOURCE_DIR}/src/cli_helper.c)

add_test(NAME credRequestTest COMMAND 02_cred_request WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/cred_request_test)

target_include_directories(02_cred_request PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(02_cred_request PRIVATE pabc)
