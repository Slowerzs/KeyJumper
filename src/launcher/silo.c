#include "launcher/silo.h"
#include "utils/alloc.h"
#include "utils/error.h"
#include "utils/native.h"
#include "utils/vec.h"
#include <handleapi.h>
#include <minwindef.h>
#include <namedpipeapi.h>
#include <stdalign.h>
#include <stddef.h>
#include <strsafe.h>
#include <winnt.h>

bool silo_create_server(SiloServer **server)
{
    SiloServer *server_silo = nullptr;
    bool result = false;

    result = silo_allocate(&server_silo);
    if (result == false)
        goto end;
    result = silo_convert_job_to_server_silo(server_silo);
    if (result == false)
        goto end;
    result = silo_set_system_root(server_silo);
    if (result == false)
        goto end;
    result = silo_create_device_object_directory(server_silo);
    if (result == false)
        goto end;
    result = silo_set_ready(server_silo);
    if (result == false)
        goto end;

    LOG_SUCCESS("Successfully created server silo.\n");
    result = true;

end:
    if (result == false)
    {
        if (server_silo->delete_event)
            CloseHandle(server_silo->delete_event);

        if (server_silo->job_object)
            CloseHandle(server_silo->job_object);

        if (server_silo != nullptr)
            jfree(server_silo);
    }

    *server = server_silo;

    return result;
}

bool silo_allocate(SiloServer **server)
{
    SiloServer *server_silo = nullptr;
    NTSTATUS status = 0;
    HANDLE job_handle = {0};
    bool result = false;

    server_silo = (SiloServer *)jalloc(sizeof(SiloServer));
    if (server_silo == nullptr)
    {
        LOG_ERROR("Failed allocating memory.\n");
        goto end;
    }

    server_silo->delete_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (server_silo->delete_event == NULL)
    {
        LOG_ERROR("Failed creating unnamed event. GetLastError(): %ld", GetLastError());
        goto end;
    }

    status = NtCreateJobObject(&job_handle, JOB_OBJECT_ALL_ACCESS, NULL);
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed creating Job object. NTSTATUS: %lx\n", status);
        goto end;
    }
    server_silo->job_object = job_handle;

    result = true;
    *server = server_silo;

end:
    return result;
}

bool silo_set_ready(SiloServer *server)
{
    NTSTATUS status = 0;
    bool result = false;
    SERVERSILO_INIT_INFORMATION init_infos = {0};

    init_infos.DeleteEvent = server->delete_event;
    init_infos.IsDownlevelContainer = FALSE;

    status = NtSetInformationJobObject(
        server->job_object,
        JobObjectServerSiloInitialize,
        &init_infos,
        sizeof(init_infos)
    );
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        status = NtSetInformationJobObject(
            server->job_object,
            JobObjectServerSiloInitialize,
            &server->delete_event,
            sizeof(server->delete_event)
        );
    }

    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed setting server silo delete event. NTSTATUS: %lx\n", status);
        goto end;
    }

    result = true;
    LOG_SUCCESS("Succesfully set server silo as ready.\n");

end:

    return result;
}

bool silo_convert_job_to_server_silo(SiloServer *server)
{
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION_EXTENDED job_object_informations = {0};
    NTSTATUS status = 0;
    bool result = false;

    job_object_informations.Informations.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_SILO_READY;

    status = NtSetInformationJobObject(
        server->job_object,
        JobObjectExtendedLimitInformation,
        &job_object_informations,
        sizeof(job_object_informations)
    );
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed setting Job object limit flags. NTSTATUS: %lx\n", status);
        goto end;
    }

    status = NtSetInformationJobObject(server->job_object, JobObjectCreateSilo, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed converting Job object to silo. NTSTATUS: %lx\n", status);
        goto end;
    }

    status = NtAssignProcessToJobObject(server->job_object, (HANDLE)-7);
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed assigning current process to silo. NTSTATUS: %lx\n", status);
        goto end;
    }

    result = true;
end:

    return result;
}

bool silo_set_system_root(SiloServer *server_silo)
{

    alignas(0x10) UNICODE_STRING system_root_unicode_string = {0};
    SILOOBJECT_ROOT_DIRECTORY silo_root_directory = {0};
    NTSTATUS status = 0;
    bool result = false;

    silo_root_directory.ControlFlags = SILO_OBJECT_ROOT_DIRECTORY_ALL;
    status = NtSetInformationJobObject(
        server_silo->job_object,
        JobObjectSiloRootDirectory,
        &silo_root_directory,
        sizeof(silo_root_directory)
    );
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed setting silo root directory. NTSTATUS: %lx\n", status);
        goto end;
    }

    RtlCreateUnicodeString(&system_root_unicode_string, L"C:\\WINDOWS");

    status = NtSetInformationJobObject(
        server_silo->job_object,
        JobObjectSiloSystemRoot,
        &system_root_unicode_string,
        sizeof(system_root_unicode_string)
    );
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed setting system root. NTSTATUS: %lx\n", status);
        goto end;
    }

    result = true;

end:

    return result;
}

bool silo_create_device_object_directory(SiloServer *server_silo)
{
    HANDLE device_directory_handle = {0}, created_directory_handle = {0};
    alignas(0x10) UNICODE_STRING device_path = {0};
    OBJECT_ATTRIBUTES device_object_attributes = {0};
    SILOOBJECT_ROOT_DIRECTORY *query_silo_root_directory = nullptr;
    PCWSTR concat_device_path = nullptr;
    bool result = false;
    ULONG length = 0;
    NTSTATUS status = 0;

    query_silo_root_directory = (SILOOBJECT_ROOT_DIRECTORY *)jalloc(0x1000);
    if (query_silo_root_directory == nullptr)
    {
        LOG_ERROR("Failed allocating memory.\n");
        goto end;
    }
    status = NtQueryInformationJobObject(
        server_silo->job_object,
        JobObjectSiloRootDirectory,
        query_silo_root_directory,
        0x1000,
        &length
    );
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed querying root directory. NTSTATUS: %lx\n", status);
        goto end;
    }

    RtlInitUnicodeString(&device_path, L"\\Device");
    InitializeObjectAttributes(
        &device_object_attributes,
        &device_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status =
        NtOpenDirectoryObject(&device_directory_handle, MAXIMUM_ALLOWED, &device_object_attributes);
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR("Failed opening \\Device directory object. NTSTATUS: %lx\n", status);
        goto end;
    }

    concat_device_path = jalloc(query_silo_root_directory->Path.Length + sizeof(L"\\Device"));
    StringCchPrintfW(
        (STRSAFE_LPWSTR)concat_device_path,
        query_silo_root_directory->Path.Length + sizeof(L"\\Device"),
        L"%ws\\Device",
        query_silo_root_directory->Path.Buffer
    );
    RtlInitUnicodeString(&device_path, concat_device_path);

    InitializeObjectAttributes(
        &device_object_attributes,
        &device_path,
        OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_OPENIF,
        NULL,
        NULL
    );
    status = NtCreateDirectoryObjectEx(
        &created_directory_handle,
        MAXIMUM_ALLOWED,
        &device_object_attributes,
        device_directory_handle,
        0
    );
    if (!NT_SUCCESS(status))
    {
        LOG_ERROR(
            "Failed creating %ws\\Device directory object. NTSTATUS: %lx\n",
            query_silo_root_directory->Path.Buffer,
            status
        );
        goto end;
    }
    result = true;

end:

    CloseHandle(created_directory_handle);
    CloseHandle(device_directory_handle);

    if (concat_device_path != nullptr)
        jfree((void *)concat_device_path);
    if (query_silo_root_directory != nullptr)
        jfree(query_silo_root_directory);

    return result;
}

bool silo_spawn_new_process(Vec *pipes, SiloServer *silo_server, HANDLE *child_write_pipe)
{
    HANDLE process_handle = {0}, thread_handle = {0};
    HANDLE read_pipe = {0}, write_pipe = {0};
    PS_CREATE_INFO create_infos = {0};
    PS_ATTRIBUTE_LIST *attributes_list = nullptr;
    SECURITY_ATTRIBUTES sec_attributes = {0};
    char buffer = 0;
    BOOL winapi_result = FALSE;
    NTSTATUS status = 0;
    bool result = false;

    sec_attributes.nLength = sizeof(sec_attributes);
    sec_attributes.bInheritHandle = TRUE;
    sec_attributes.lpSecurityDescriptor = nullptr;
    winapi_result = CreatePipe(&read_pipe, &write_pipe, &sec_attributes, 0);
    if (winapi_result == FALSE)
    {
        LOG_ERROR("Failed creating pipe for communication\n");
        goto end;
    }

    create_infos.Size = sizeof(create_infos);

    attributes_list = jalloc(sizeof(PS_ATTRIBUTE_LIST));
    if (attributes_list == nullptr)
    {
        LOG_ERROR("Failed allocating memory.\n");
        goto end;
    }

    attributes_list->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    attributes_list->Attributes[0].Attribute = PS_ATTRIBUTE_JOB_LIST;
    attributes_list->Attributes[0].Size = sizeof(HANDLE);
    attributes_list->Attributes[0].ValuePtr = &silo_server->job_object;

    status = NtCreateUserProcess(
        &process_handle,
        &thread_handle,
        MAXIMUM_ALLOWED,
        MAXIMUM_ALLOWED,
        nullptr,
        nullptr,
        PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        0,
        nullptr,
        &create_infos,
        attributes_list
    );

    if (status == STATUS_SUCCESS)
    {
        for (size_t i = 0; i < pipes->length; i++)
        {
            //CloseHandle(((NonPagedBuffer *)pipes->buffer[i])->read_pipe);
            CloseHandle(((NonPagedBuffer *)pipes->buffer[i])->write_pipe);
        }
        CloseHandle(write_pipe);
        LOG_SUCCESS("Succesfully created new process. Handle: %x\n", process_handle);
        while (WaitForSingleObject(process_handle, 0) == WAIT_TIMEOUT)
        {
            winapi_result = ReadFile(read_pipe, &buffer, 0x1, nullptr, nullptr);
            if (winapi_result != FALSE)
                printf_s("%c", buffer);
        }

        // Drain remaining bytes
        while (ReadFile(read_pipe, &buffer, 0x1, nullptr, nullptr) != FALSE)
        {
            printf_s("%c", buffer);
        }

        LOG_SUCCESS("Child process exited.\n");
    }
    else if (status == STATUS_PROCESS_CLONED)
    {
        CloseHandle(read_pipe);

        *child_write_pipe = write_pipe;

        CHILD_LOG_SUCCESS(write_pipe, "Child process starting...\n");
        result = true;
    }

end:

    if (attributes_list != nullptr)
        jfree(attributes_list);

    return result;
}