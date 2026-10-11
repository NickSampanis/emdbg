# Pinned third-party code. Only build settings live here; the sources are
# git submodules and are never edited.

# --- SDL3 ---------------------------------------------------------------
set(SDL_SHARED        OFF CACHE BOOL "" FORCE)
set(SDL_STATIC        ON  CACHE BOOL "" FORCE)
set(SDL_TEST_LIBRARY  OFF CACHE BOOL "" FORCE)
set(SDL_TESTS         OFF CACHE BOOL "" FORCE)
set(SDL_EXAMPLES      OFF CACHE BOOL "" FORCE)
set(SDL_INSTALL       OFF CACHE BOOL "" FORCE)
add_subdirectory(SDL EXCLUDE_FROM_ALL)

# --- Dear ImGui (docking) + cimgui + SDL3/OpenGL3 backends --------------
# cimgui's own CMakeLists builds neither the backends nor a static library
# without extra flags, so we define the target ourselves.
set(CIMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cimgui)
set(IMGUI_DIR  ${CIMGUI_DIR}/imgui)

add_library(cimgui STATIC
    ${CIMGUI_DIR}/cimgui.cpp
    ${CIMGUI_DIR}/cimgui_impl.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_sdl3.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# CIMGUI_USE_* select which backend declarations cimgui_impl.h exposes, so
# C consumers need them too. CIMGUI_NO_EXPORT: static library, no dllexport.
target_compile_definitions(cimgui
    PUBLIC  CIMGUI_USE_SDL3 CIMGUI_USE_OPENGL3 CIMGUI_NO_EXPORT
    PRIVATE IMGUI_USER_CONFIG="imconfig_emdbg.h"
)
target_include_directories(cimgui SYSTEM PUBLIC ${CIMGUI_DIR})
target_include_directories(cimgui PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${CMAKE_CURRENT_SOURCE_DIR}/config
)
target_link_libraries(cimgui PUBLIC SDL3::SDL3-static)
if(WIN32)
    target_link_libraries(cimgui PRIVATE imm32)
elseif(UNIX)
    target_link_libraries(cimgui PRIVATE ${CMAKE_DL_LIBS})
endif()

set(IMGUI_FONTS_DIR ${IMGUI_DIR}/misc/fonts PARENT_SCOPE)

# --- Zydis (disassembler for dbgeng; builds its bundled Zycore) ---------
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TOOLS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS      OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_MAN        OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN    OFF CACHE BOOL "" FORCE)
add_subdirectory(zydis EXCLUDE_FROM_ALL)

# --- emstub (protocol headers; becomes its own repo later) ---------------
add_subdirectory(emstub)
