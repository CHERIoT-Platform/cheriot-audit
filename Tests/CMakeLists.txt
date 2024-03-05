message(STATUS "Adding tests")
file(GLOB TESTS CONFIGURE_DEPENDS "*.query")

message(STATUS "Tests: ${TESTS}")

foreach(TEST ${TESTS})
	get_filename_component(TEST_NAME ${TEST} NAME_WE)
	add_test(${TEST_NAME}_expected "${CMAKE_CURRENT_SOURCE_DIR}/testexpected.sh" "${CMAKE_BINARY_DIR}/cheriot-audit" ${TEST})
endforeach()

