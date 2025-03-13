#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "bitmap.h"
#include "block_store.h"
// include more if you need

typedef struct block_store {
        bitmap_t *bitmap;
} block_store_t;

// You might find this handy. I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)

block_store_t *block_store_create()
{
	block_store_t *bs;
	bs = (block_store_t *)malloc(sizeof(block_store_t));
	memset(bs, 0, sizeof(block_store_t));
	bs->bitmap = bitmap_create(BITMAP_SIZE_BYTES);
	bitmap_set(bs->bitmap, BITMAP_START_BLOCK);	
	block_store_request(bs, 0);
	return bs;
}

void block_store_destroy(block_store_t *const bs)
{
	if(bs != NULL)
	{
		bitmap_destroy(bs->bitmap);
		free(bs);
	}
}

size_t block_store_allocate(block_store_t *const bs)
{
	UNUSED(bs);
	return 0;
}

bool block_store_request(block_store_t *const bs, const size_t block_id)
{
	UNUSED(bs);
	UNUSED(block_id);
	return false;
}

void block_store_release(block_store_t *const bs, const size_t block_id)
{
	if(bs !=  NULL && block_id < BLOCK_STORE_NUM_BLOCKS - 1)
	{
		bitmap_reset((bs -> bitmap), block_id);
	}
	
}

size_t block_store_get_used_blocks(const block_store_t *const bs)
{
	UNUSED(bs);
	return 0;
}

size_t block_store_get_free_blocks(const block_store_t *const bs)
{
	UNUSED(bs);
	return 0;
}

size_t block_store_get_total_blocks()
{
	return 0;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer)
{
	UNUSED(bs);
	UNUSED(block_id);
	UNUSED(buffer);
	return 0;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer)
{
	UNUSED(bs);
	UNUSED(block_id);
	UNUSED(buffer);
	return 0;
}

block_store_t *block_store_deserialize(const char *const filename)
{
	UNUSED(filename);
	return NULL;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename)
{
	UNUSED(bs);
	UNUSED(filename);
	return 0;
}
