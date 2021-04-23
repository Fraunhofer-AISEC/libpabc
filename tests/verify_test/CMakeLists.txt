add_executable(05_verify
  05_verify.c
  ${PROJECT_SOURCE_DIR}/src/cli_helper.c)

add_test(NAME verifyTest COMMAND 05_verify WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/verify_test)

target_include_directories(05_verify PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(05_verify PRIVATE pabc)
