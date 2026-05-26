cmake_minimum_required(VERSION 3.15)
project(Chiiki LANGUAGES CXX)

add_compile_options("/source-charset:utf-8")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 静态链接 CRT，生成的二进制无运行时 DLL 依赖
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# 所有产物输出到同一目录
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>)
# set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/$<CONFIG>)

# ── Microsoft Detours（内联钩子库）───────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    detours
    GIT_REPOSITORY https://github.com/microsoft/Detours.git
    GIT_TAG        v4.0.1
)
FetchContent_Populate(detours)

add_library(detours STATIC
    ${detours_SOURCE_DIR}/src/detours.cpp
    ${detours_SOURCE_DIR}/src/disasm.cpp
    ${detours_SOURCE_DIR}/src/image.cpp
    ${detours_SOURCE_DIR}/src/modules.cpp
    ${detours_SOURCE_DIR}/src/creatwth.cpp
)
target_include_directories(detours PUBLIC ${detours_SOURCE_DIR}/src)
target_compile_definitions(detours PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(detours PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# ── dll ─────────────────────────────────────────────────────────────
add_library(chiiki SHARED src/lib.cpp)
target_compile_definitions(chiiki PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_link_libraries(chiiki PRIVATE detours imm32)

# ── chiiki.exe（控制台程序）─────────────────────────────────────────────────
add_executable(launcher WIN32 src/main.cpp)
target_compile_definitions(launcher PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_link_libraries(launcher PRIVATE shell32)
# 内嵌 UAC 清单：双击时自动弹出提权对话框，以管理员身份运行
target_link_options(launcher PRIVATE
    "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
set_target_properties(launcher PROPERTIES
    OUTPUT_NAME "chiiki"
)
