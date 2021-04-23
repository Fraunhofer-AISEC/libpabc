add_executable(03_issue_cred
  03_issue_cred.c
  ${PROJECT_SOURCE_DIR}/src/cli_helper.c)

add_test(NAME credIssueTest COMMAND 03_issue_cred WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/cred_issue_test)

target_include_directories(03_issue_cred PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(03_issue_cred PRIVATE pabc)
