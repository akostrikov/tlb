#pragma once

#include "base.h"

struct resample {
	struct rnd_state rnd;
	u64 *value;
	int count;
	int capacity;
	u64 seqno;
};

void resample_init(struct resample *res, u64 *buf, int capacity);

void resample_add(struct resample *res, u64 value);

void resample_sort(struct resample *res);

u64 resample_get(struct resample *res, int index);

int resample_count(struct resample *res);
