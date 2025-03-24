#ifndef UTILS_ERROR_H
#define UTILS_ERROR_H

#define LOG_ERROR(format, ...)                                                                     \
    do                                                                                             \
    {                                                                                              \
        printf_s("%s(%s):%d. ", __FILE__, __FUNCTION__, __LINE__);                                 \
        printf_s(format, __VA_ARGS__);                                                             \
                                                                                                   \
    } while (0)

#define LOG_SUCCESS(format, ...)                                                                   \
    do                                                                                             \
    {                                                                                              \
        printf_s("[+] " format, __VA_ARGS__);                                                      \
                                                                                                   \
    } while (0)

#define CHILD_LOG_SUCCESS(write_pipe, format, ...)                                                 \
    do                                                                                             \
    {                                                                                              \
        char child_buffer[0x100] = {0};                                                            \
        int len = snprintf(child_buffer, 0x100, "[+]    " format, __VA_ARGS__);                    \
        WriteFile(write_pipe, child_buffer, len, nullptr, nullptr);                                \
    } while (0)

#define CHILD_LOG_KEYSTROKE(write_pipe, format, ...)                                                 \
    do                                                                                             \
    {                                                                                              \
        char child_buffer[0x100] = {0};                                                            \
        int len = snprintf(child_buffer, 0x100, format, __VA_ARGS__);                    \
        WriteFile(write_pipe, child_buffer, len, nullptr, nullptr);                                \
    } while (0)

#define CHILD_LOG_ERROR(write_pipe, format, ...)                                                   \
    do                                                                                             \
    {                                                                                              \
        char child_buffer[0x100] = {0};                                                            \
        int len = _snprintf_s(                                                                     \
            child_buffer,                                                                          \
            0x100,                                                                                 \
            0xFF,                                                                                  \
            "%s(%s):%d. ",                                                                         \
            __FILE__,                                                                              \
            __FUNCTION__,                                                                          \
            __LINE__                                                                               \
        );                                                                                         \
        WriteFile(write_pipe, child_buffer, len, nullptr, nullptr);                                \
        len = _snprintf_s(child_buffer, 0x100, 0xFF, format, __VA_ARGS__);                         \
        WriteFile(write_pipe, child_buffer, len, nullptr, nullptr);                                \
    } while (0)

#endif