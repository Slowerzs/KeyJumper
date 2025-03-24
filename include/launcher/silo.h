#ifndef LAUNCHER_SILO_H
#define LAUNCHER_SILO_H

#include "utils/vec.h"
#include <Windows.h>

typedef struct _SiloServer
{
    HANDLE delete_event;
    HANDLE job_object;
} SiloServer;

bool silo_create_server(SiloServer** server);
bool silo_allocate(SiloServer **server);
bool silo_set_ready(SiloServer *server);
bool silo_convert_job_to_server_silo(SiloServer *server);
bool silo_set_system_root(SiloServer *server_silo);
bool silo_create_device_object_directory(SiloServer *server_silo);
bool silo_spawn_new_process(Vec* pipes, SiloServer *silo_server, HANDLE* child_write_pipe);

#endif
