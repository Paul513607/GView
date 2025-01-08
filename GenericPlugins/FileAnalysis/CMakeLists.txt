include(generic_plugin)
create_generic_plugin(FileAnalysis)

find_package(CURL REQUIRED)
target_link_libraries(FileAnalysis PRIVATE CURL::libcurl)
include_directories(${CURL_INCLUDE_DIRS})