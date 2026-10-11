/* emdbg GUI entry point: SDL3 window + OpenGL3 context + Dear ImGui (cimgui). */
#include "app.h"

#include <stdio.h>

#include <SDL3/SDL.h>
#include <SDL3/SDL_main.h>
#include <SDL3/SDL_opengl.h>

#include "cimgui_impl.h"

static void load_fonts(ImGuiIO *io)
{
    char    path[1024];
    ImFont *font = NULL;

    snprintf(path, sizeof path, "%sfonts/Cousine-Regular.ttf", SDL_GetBasePath());
    if (SDL_GetPathInfo(path, NULL))
        font = ImFontAtlas_AddFontFromFileTTF(io->Fonts, path, 15.0f, NULL, NULL);
    if (font)
        io->FontDefault = font;
    else
        fprintf(stderr, "warning: %s not found, using the built-in font\n", path);
}

int main(int argc, char **argv)
{
    static app_state app;   /* large (log buffer); keep it off the stack */
    static char      ini_path[1024];   /* io->IniFilename keeps the pointer */
    SDL_WindowFlags  wflags = SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIDDEN |
                              SDL_WINDOW_HIGH_PIXEL_DENSITY;
    SDL_Window      *window;
    SDL_GLContext    gl;
    SDL_Window      *backup_window;
    SDL_GLContext    backup_gl;
    SDL_Event        ev;
    ImGuiIO         *io;
    ImGuiStyle      *style;
    float            scale;
    char             connect[300];

    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        return 1;
    }

    /* OpenGL 3.0 core; the matching GLSL version is picked by the backend. */
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);

    scale = SDL_GetDisplayContentScale(SDL_GetPrimaryDisplay());
    if (scale <= 0.0f)
        scale = 1.0f;

    window = SDL_CreateWindow("emdbg", (int)(1440 * scale), (int)(900 * scale), wflags);
    if (!window) {
        fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError());
        return 1;
    }
    gl = SDL_GL_CreateContext(window);
    if (!gl) {
        fprintf(stderr, "SDL_GL_CreateContext: %s\n", SDL_GetError());
        return 1;
    }
    SDL_GL_MakeCurrent(window, gl);
    SDL_GL_SetSwapInterval(1);
    SDL_SetWindowPosition(window, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);
    SDL_ShowWindow(window);

    igCreateContext(NULL);
    io = igGetIO_Nil();
    /* Layout and the symbol / source folders are saved next to the executable, not in
     * whatever directory emdbg was started from. */
    snprintf(ini_path, sizeof ini_path, "%simgui.ini", SDL_GetBasePath());
    io->IniFilename = ini_path;
    io->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io->ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io->ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;   /* panes can leave the main window */
    io->ConfigDpiScaleFonts = true;
    io->ConfigDpiScaleViewports = true;

    igStyleColorsDark(NULL);
    style = igGetStyle();
    ImGuiStyle_ScaleAllSizes(style, scale);
    style->FontScaleDpi = scale;
    /* With viewports, platform windows must be opaque and square. */
    style->WindowRounding = 0.0f;
    style->Colors[ImGuiCol_WindowBg].w = 1.0f;

    ImGui_ImplSDL3_InitForOpenGL(window, gl);
    ImGui_ImplOpenGL3_Init(NULL);
    load_fonts(io);

    app_init(&app);
    if (argc > 1) {                          /* emdbg host:port connects at startup */
        snprintf(connect, sizeof connect, ".connect %s", argv[1]);
        app_exec(&app, connect);
    }

    while (!app.quit) {
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL3_ProcessEvent(&ev);
            if (ev.type == SDL_EVENT_QUIT)
                app.quit = true;
            if (ev.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                ev.window.windowID == SDL_GetWindowID(window))
                app.quit = true;
        }
        if (SDL_GetWindowFlags(window) & SDL_WINDOW_MINIMIZED) {
            SDL_Delay(10);
            continue;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        igNewFrame();

        app_frame(&app);

        igRender();
        glViewport(0, 0, (int)io->DisplaySize.x, (int)io->DisplaySize.y);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(igGetDrawData());

        if (io->ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            backup_window = SDL_GL_GetCurrentWindow();
            backup_gl     = SDL_GL_GetCurrentContext();
            igUpdatePlatformWindows();
            igRenderPlatformWindowsDefault(NULL, NULL);
            SDL_GL_MakeCurrent(backup_window, backup_gl);
        }
        SDL_GL_SwapWindow(window);
    }

    app_shutdown(&app);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    igDestroyContext(NULL);
    SDL_GL_DestroyContext(gl);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
