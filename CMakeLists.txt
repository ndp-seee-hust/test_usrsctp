cmake_minimum_required(VERSION 3.16.3)
project(test_usrsctp)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/usrsctplib)
find_package(Threads)


list(APPEND test
	test/server.c
	test/client.c
    )

foreach (source_file ${test})
	get_filename_component(source_file_we ${source_file} NAME_WE)
	add_executable(
		${source_file_we}
		${source_file}
		usrsctplib/programs_helper.c
	)

	target_link_libraries(
		${source_file_we}
		${CMAKE_CURRENT_SOURCE_DIR}/usrsctplib/libusrsctp.a
		${CMAKE_THREAD_LIBS_INIT}
	)

endforeach ()