add_executable(01_setup
  01_setup.c
  ${PROJECT_SOURCE_DIR}/src/cli_helper.c)

add_test(setupTest 01_setup)

target_include_directories(01_setup PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(01_setup PRIVATE pabc)
