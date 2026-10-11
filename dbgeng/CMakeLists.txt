add_library(dbgeng STATIC
    src/bp.c
    src/cmd.c
    src/dbg.c
    src/disasm.c
    src/expr.c
    src/find.c
    src/ids.c
    src/image.c
    src/link.c
    src/pdb.c
    src/pdb_syms.c
    src/pdb_types.c
    src/step.c
    src/sym.c
    src/symbuild.c
    src/unwind.c
    src/value.c
)
if(WIN32)
    target_sources(dbgeng PRIVATE src/plat_win.c)
    target_link_libraries(dbgeng PRIVATE ws2_32)
else()
    target_sources(dbgeng PRIVATE src/plat_posix.c)
endif()

target_include_directories(dbgeng PUBLIC include PRIVATE src)
target_link_libraries(dbgeng PUBLIC emstub_proto PRIVATE Zydis)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(dbgeng PRIVATE -Wall -Wextra -Wdeclaration-after-statement)
endif()
if(WIN32)
    target_compile_definitions(dbgeng PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Command / expression tests; no target needed. Uses private headers.
add_executable(dbgeng_exec_test tests/exec_test.c)
target_link_libraries(dbgeng_exec_test PRIVATE dbgeng)
target_include_directories(dbgeng_exec_test PRIVATE src)
if(WIN32)
    target_compile_definitions(dbgeng_exec_test PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME dbgeng_exec_test COMMAND dbgeng_exec_test)

# Command-line frontend: type dbg_exec commands against a target.
add_executable(dbgeng_cli tools/cli.c)
target_link_libraries(dbgeng_cli PRIVATE dbgeng)

# Needs a running emstub_fake_target, so it is not registered with ctest.
add_executable(dbgeng_smoke tests/smoke.c)
target_link_libraries(dbgeng_smoke PRIVATE dbgeng)
target_include_directories(dbgeng_smoke PRIVATE src)
