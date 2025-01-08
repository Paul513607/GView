include(generic_plugin)
create_generic_plugin(FileAnalysis)

find_package(CURL REQUIRED)
target_link_libraries(FileAnalysis PRIVATE CURL::libcurl)
include_directories(${CURL_INCLUDE_DIRS})

find_package(nlohmann_json REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
include_directories(${NLOHMANN_JSON_INCLUDE_DIRS})