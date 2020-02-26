// SPDX-License-Identifier: GPL-2.0+
/**
 * @file xaprc00x-ring.c
 * @brief Functions for reading and writing arbitrary data to and form a circ
 *        buffer.
 */

#include <linux/circ_buf.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "xaprc00x-ring.h"

/**
 * xaprc00x_ring_section - Gives the caller parameters to consume data from a
 * ring buffer.
 *
 * Not all consumers want to perform a memcpy to another locationso this
 * function provides the caller with parameters describing the portions of the
 * buffer they can safely read. This structure may then be passed to []
 * to actually move the ring forward upon completion.
 *
 * @ring A pointer to the circ_buf object to manipulate
 * @ring_len The length of the circ_buf buffer
 * @len The length to consume from the ring buffer
 *
 * Returns: {-1,-,-} on failure, the copy parameters if the entire length can
 * be served. On success the first member (start) is the offset on the buffer
 * to begin reading, the second (len) is the length to read from start. The
 * final member (wrap) is the number of bytes to read from the beginning of
 * the buffer.
 *
 * Notes:
 * This only returns information on where to read from the buffer, it does not
 * reserve or restrict other consumers from using this data.
 */
struct xaprc00x_ring_section xaprc00x_consumer_section(
	struct circ_buf *ring, int ring_len, int len)
{
	int head;
	int tail;
	struct xaprc00x_ring_section ret = {-1, 0, 0};

	head = READ_ONCE(ring->head);
	tail = READ_ONCE(ring->tail);

	/* If there is not enough data to return */
	if (CIRC_CNT(head, tail, ring_len) < len)
		goto exit;

	ret.len = min(len, CIRC_CNT_TO_END(head, tail, ring_len));
	ret.start = tail;
	ret.wrap = len - ret.len;

exit:
	return ret;
}

/**
 * xaprc00x_ring_consume - Consumes a secion of data on the ring
 *
 * When a consumer no longer needs a section of data on the circular buffer
 * this function should be called to free the data in the structure. Once
 * called the memory described in this section is no longer safe to read.
 *
 * @ring A pointer to the circ_buf object to manipulate
 * @ring_len The length of the circ_buf buffer
 * @section The section of memory to consume
 */
void xaprc00x_ring_consume(
	struct circ_buf *ring,
	int ring_len,
	struct xaprc00x_ring_section section)
{
	int newtail =
		(section.start + section.len + section.wrap) & (ring_len - 1);
	WRITE_ONCE(ring->tail, newtail);
}

/**
 * xaprc00x_ring_write - Place an arbitrary number of bytes on a circ_buf
 * structure
 *
 * @ring A pointer to the circ_buf object to manipulate
 * @ring_len The length of the circ_buf buffer
 * @buf A pointer to the incoming data
 * @len The length to place from buf onto the ring
 *
 * Returns: 0 on success, 1 if full copy could not be performed
 *
 * Notes:
 * If the entire requested buffer cannot be inserted then nothing will be
 * ring_len must be a power-of-two. See the documentation for circ_buf for info
 * dst must already be allocated with space for a `n` byte copy
 * This function may modify ring->head to fill the buffer
 */
int xaprc00x_ring_write(struct circ_buf *ring, int ring_len, char *buf, int len)
{
	int head;
	int tail;
	int space_to_end;
	int ret = 0;

	/* Make sure there is enough space to perform the operation */
	head = READ_ONCE(ring->head);
	tail = READ_ONCE(ring->tail);
	if (CIRC_SPACE(head, tail, ring_len) < len) {
		ret = 1;
		goto exit;
	}

	space_to_end = min(len, CIRC_SPACE_TO_END(head, tail, ring_len));

	memcpy(ring->buf + head, buf, space_to_end);
	memcpy(ring->buf, buf + space_to_end, len - space_to_end);

	/* Update the circ buffer head */
	WRITE_ONCE(ring->head, (head + len) & (ring_len - 1));
exit:
	return ret;
}
