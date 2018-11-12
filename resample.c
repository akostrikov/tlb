#include "resample.h"

void resample_init(struct resample *res, u64 *buf, int capacity)
{
	prandom_seed_state(&res->rnd, ktime_get());
	res->value = buf;
	res->count = 0;
	res->capacity = capacity;
	res->seqno = 0;
}

void resample_add(struct resample *res, u64 value)
{
	u64 j;
	u64 r;

	if (res->count < res->capacity) {
		res->value[res->count++] = value;
		res->seqno++;
		return;
	}

	prandom_bytes_state(&res->rnd, &r, sizeof(r));
	j = r % (res->seqno + 1); //gen random from [0..res->seqno]
	if (j < res->capacity)
		res->value[j] = value;

	res->seqno++;
}

static void u64_swap(void *a, void *b, int size)
{
	u64 t = *(u64 *)a;
	*(u64 *)a = *(u64 *)b;
	*(u64 *)b = t;
}

static int u64_cmp(const void *a, const void *b)
{
	if (*(u64*)a > *(u64*)b)
		return 1;
	else if (*(u64*)a < *(u64*)b)
		return -1;
	return 0;
}

void resample_sort(struct resample *res)
{
	sort(res->value, res->count, sizeof(u64), u64_cmp, u64_swap);
}

u64 resample_get(struct resample *res, int index)
{
	BUG_ON(index < 0 || index >= res->count);

	return res->value[index];
}

int resample_count(struct resample *res)
{
	return res->count;
}
