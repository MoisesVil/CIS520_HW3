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
	// Initializing the block_store and creating memory for it
	block_store_t *bs;
	bs = (block_store_t *)malloc(sizeof(block_store_t));
	// Making sure malloc() call worked
	if (bs == NULL) return NULL;

	// Setting all of the memory to 0
	memset(bs, 0, sizeof(block_store_t));

	// Creating the bitmap
	bs->bitmap = bitmap_create(BITMAP_SIZE_BITS);

	// Setting blocks used by bitmap as allocated
	for (size_t i = BITMAP_START_BLOCK; i < BITMAP_START_BLOCK + BITMAP_NUM_BLOCKS; i++) 
	{
		block_store_request(bs, i);
	}

	// Returning the block_store
	return bs;
}

void block_store_destroy(block_store_t *const bs)
{
	// Checking to make sure bs is not NULL
	if(bs != NULL)
	{
		// Freeing space created by the bitmap
		bitmap_destroy(bs->bitmap);

		// Freeing space create by the block_store
		free(bs);
	}
}

size_t block_store_allocate(block_store_t *const bs)
{
	// Checking params to not be NULL
	if(bs != NULL)
	{
		// Getting the first free block in the bitmap
		size_t free_block = bitmap_ffz(bs->bitmap);

		// If bitmap_ffz threw an error, return SIZE_MAX
		if (free_block == SIZE_MAX) 
		{
			return SIZE_MAX;
		}

		// Setting the block in the bitmap and returning that block
		bitmap_set(bs->bitmap, free_block);
		return free_block;
	}

	// If error with params, reutn SIZE_MAX
	return SIZE_MAX;
}

bool block_store_request(block_store_t *const bs, const size_t block_id)
{
	// Checking params
	if (bs == NULL || block_id >= BLOCK_STORE_NUM_BLOCKS) 
	{
		return false;
	}

	// Making sure bit is not already set
	if (bitmap_test(bs -> bitmap, block_id)) 
	{
		return false;
	}

	// Allocating the block
	bitmap_set(bs -> bitmap, block_id);

	// Testing to make sure bit was properly set, 
	// returns true if it was and false otherwise
	return bitmap_test(bs -> bitmap, block_id);
}

void block_store_release(block_store_t *const bs, const size_t block_id)
{
	// Checking params to make sure they work properly
	if (bs != NULL && block_id < BLOCK_STORE_NUM_BLOCKS) 
	{
		// Resetting the block in the bitmap
		bitmap_reset((bs -> bitmap), block_id);
	}
}

size_t block_store_get_used_blocks(const block_store_t *const bs)
{
	// Check to make sure bs is not null
	if (bs == NULL) {
 		return SIZE_MAX;
	}

	// Return to total number of used blocks
	return bitmap_total_set(bs -> bitmap);
}

size_t block_store_get_free_blocks(const block_store_t *const bs)
{
	// Check to make sure bs is not null
	if (bs == NULL) {
		return SIZE_MAX;
	}

	// Return the difference between total blocks in block store
	// and blocks being used, which is the number of free blocks
	return BLOCK_STORE_NUM_BLOCKS - block_store_get_used_blocks(bs);
}

size_t block_store_get_total_blocks()
{
	return BLOCK_STORE_NUM_BLOCKS;
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
