find_package(OpenGL REQUIRED)

add_executable(emdbg_gui
    src/main.c
    src/layout.c
    src/pane_disasm.c
    src/pane_source.c
    src/pane_registers.c
    src/pane_jit.c
    src/pane_command.c
    src/settings.c
    src/pane_watch.c
    src/pane_stack.c
)

set_target_properties(emdbg_gui PROPERTIES OUTPUT_NAME emdbg)

target_link_libraries(emdbg_gui PRIVATE dbgeng cimgui SDL3::SDL3-static OpenGL::GL)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    # Project style: declarations at the top of each function.
    target_compile_options(emdbg_gui PRIVATE -Wall -Wextra -Wdeclaration-after-statement)
endif()
if(WIN32)
    target_compile_definitions(emdbg_gui PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_custom_command(TARGET emdbg_gui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_FILE_DIR:emdbg_gui>/fonts
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${IMGUI_FONTS_DIR}/Cousine-Regular.ttf
            $<TARGET_FILE_DIR:emdbg_gui>/fonts/
)
