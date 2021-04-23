add_executable(04_proof
  04_proof.c
  ${PROJECT_SOURCE_DIR}/src/cli_helper.c)

add_test(NAME proofTest COMMAND 04_proof WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/tests/proof_test)

target_include_directories(04_proof PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(04_proof PRIVATE pabc)
