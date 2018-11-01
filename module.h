#pragma once

#include "base.h"
#include "server.h"
#include "sysfs.h"

struct tlb_server;

struct tlb_context {
	struct tlb_server srv;
	struct tlb_kobject_holder kobj_holder;
};
