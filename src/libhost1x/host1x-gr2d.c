/*
 * Copyright (c) 2012, 2013 Erik Faye-Lund
 * Copyright (c) 2013 Thierry Reding
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <math.h>

#include "host1x.h"
#include "host1x-private.h"

#define HOST1X_GR2D_TEST 0

#define FLOAT_TO_FIXED_6_12(fp) \
	(((int32_t) (fp * 4096.0f + 0.5f)) & ((1 << 18) - 1))

#define FLOAT_TO_FIXED_2_7(fp) \
    ((((int32_t) (fp * 128.0f)) & 0x300) | \
        (((int32_t) (fabs(fp) * 128.0f + 0.5f)) & ((1 << 8) - 1)))

#define FLOAT_TO_FIXED_1_7(fp) \
    ((((int32_t) (fp * 128.0f)) & 0x100) | \
        (((int32_t) (fabs(fp) * 128.0f + 0.5f)) & ((1 << 8) - 1)))

#define FLOAT_TO_FIXED_0_8(fp) \
	(((int32_t) (fp * 256.0f + 0.5f)) & ((1 << 8) - 1))

static int host1x_gr2d_test(struct host1x_gr2d *gr2d)
{
	struct host1x_syncpt *syncpt = &gr2d->client->syncpts[0];
	struct host1x_fence *fence;
	struct host1x_pushbuf *pb;
	struct host1x_job *job;
	int err = 0;

	job = HOST1X_JOB_CREATE(syncpt->id, 1);
	if (!job)
		return -ENOMEM;

	pb = HOST1X_JOB_APPEND(job, gr2d->commands, 0);
	if (!pb) {
		host1x_job_free(job);
		return -ENOMEM;
	}

	host1x_pushbuf_push(pb, HOST1X_OPCODE_SETCL(0x000, 0x051, 0x00));
	host1x_pushbuf_sync(pb, 0, 1, HOST1X_SYNC_COND_OP_DONE, true);

	err = HOST1X_CLIENT_SUBMIT(gr2d->client, job);
	if (err < 0) {
		host1x_job_free(job);
		return err;
	}

	host1x_job_free(job);

	err = HOST1X_CLIENT_FLUSH(gr2d->client, &fence);
	if (err < 0)
		return err;

	err = HOST1X_CLIENT_WAIT(gr2d->client, fence, ~0u);
	if (err < 0)
		return err;

	return 0;
}

int host1x_gr2d_init(struct host1x *host1x, struct host1x_gr2d *gr2d)
{
	int err;

	gr2d->commands = HOST1X_BO_CREATE(host1x, 8 * 4096,
					  NVHOST_BO_FLAG_COMMAND_BUFFER);
	if (!gr2d->commands)
		return -ENOMEM;

	err = HOST1X_BO_MMAP(gr2d->commands, NULL);
	if (err < 0)
		return err;

	gr2d->scratch = HOST1X_BO_CREATE(host1x, 64, NVHOST_BO_FLAG_SCRATCH);
	if (!gr2d->scratch) {
		host1x_bo_free(gr2d->commands);
		return -ENOMEM;
	}

	if (HOST1X_GR2D_TEST) {
		err = host1x_gr2d_test(gr2d);
		if (err < 0) {
			host1x_error("host1x_gr2d_test() failed: %d\n", err);
			return err;
		}
	}

	return 0;
}

void host1x_gr2d_exit(struct host1x_gr2d *gr2d)
{
	host1x_bo_free(gr2d->commands);
	host1x_bo_free(gr2d->scratch);
}

int host1x_gr2d_clear(struct host1x_gr2d *gr2d,
		      struct host1x_pixelbuffer *pixbuf,
		      uint32_t color)
{
	return host1x_gr2d_clear_rect(gr2d, pixbuf, color, 0, 0,
				      pixbuf->width, pixbuf->height);
}

int host1x_gr2d_clear_rect(struct host1x_gr2d *gr2d,
			   struct host1x_pixelbuffer *pixbuf,
			   uint32_t color,
			   unsigned x, unsigned y,
			   unsigned width, unsigned height)
{
	struct host1x_syncpt *syncpt = &gr2d->client->syncpts[0];
	struct host1x_fence *fence;
	struct host1x_pushbuf *pb;
	struct host1x_job *job;
	unsigned tiled = 0;
	int err;

	job = HOST1X_JOB_CREATE(syncpt->id, 1);
	if (!job)
		return -ENOMEM;

	pb = HOST1X_JOB_APPEND(job, gr2d->commands, 0);
	if (!pb) {
		host1x_job_free(job);
		return -ENOMEM;
	}

	if (x + width > pixbuf->width)
		return -EINVAL;

	if (y + height > pixbuf->height)
		return -EINVAL;

	switch (pixbuf->layout) {
	case PIX_BUF_LAYOUT_TILED_16x16:
		tiled = 1;
	case PIX_BUF_LAYOUT_LINEAR:
		break;
	default:
		host1x_error("Invalid layout %u\n", pixbuf->layout);
		return -EINVAL;
	}

	host1x_pushbuf_push(pb, HOST1X_OPCODE_SETCL(0, 0x51, 0));
	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x09, 9));
	host1x_pushbuf_push(pb, 0x0000003a);
	host1x_pushbuf_push(pb, 0x00000000);
	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x1e, 7));
	host1x_pushbuf_push(pb, 0x00000000);
	host1x_pushbuf_push(pb, /* controlmain */
			(PIX_BUF_FORMAT_BYTES(pixbuf->format) >> 1) << 16 |
			1 << 6 | /* srcsld */
			1 << 2 /* turbofill */);
	host1x_pushbuf_push(pb, 0x000000cc);
	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x2b, 9));
	HOST1X_PUSHBUF_RELOCATE(pb, pixbuf->bo, pixbuf->bo->offset, 0);
	host1x_pushbuf_push(pb, 0xdeadbeef);
	host1x_pushbuf_push(pb, pixbuf->pitch);
	host1x_pushbuf_push(pb, HOST1X_OPCODE_NONINCR(0x35, 1));
	host1x_pushbuf_push(pb, color);
	host1x_pushbuf_push(pb, HOST1X_OPCODE_NONINCR(0x46, 1));
	host1x_pushbuf_push(pb, tiled << 20); /* tilemode */
	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x38, 5));
	host1x_pushbuf_push(pb, height << 16 | width);
	host1x_pushbuf_push(pb, y << 16 | x);
	host1x_pushbuf_sync(pb, 0, 1, HOST1X_SYNC_COND_OP_DONE, true);

	err = HOST1X_CLIENT_SUBMIT(gr2d->client, job);
	if (err < 0) {
		host1x_job_free(job);
		return err;
	}

	host1x_job_free(job);

	err = HOST1X_CLIENT_FLUSH(gr2d->client, &fence);
	if (err < 0)
		return err;

	err = HOST1X_CLIENT_WAIT(gr2d->client, fence, ~0u);
	if (err < 0)
		return err;

	host1x_pixelbuffer_check_guard(pixbuf);

	return 0;
}

int host1x_gr2d_blit(struct host1x_gr2d *gr2d,
		     struct host1x_pixelbuffer *src,
		     struct host1x_pixelbuffer *dst,
		     unsigned int sx, unsigned int sy,
		     unsigned int dx, unsigned int dy,
		     unsigned int width, int height)
{
	struct host1x_bo *src_orig = src->bo->wrapped ?: src->bo;
	struct host1x_bo *dst_orig = dst->bo->wrapped ?: dst->bo;
	struct host1x_syncpt *syncpt = &gr2d->client->syncpts[0];
	struct host1x_fence *fence;
	struct host1x_pushbuf *pb;
	struct host1x_job *job;
	unsigned src_tiled = 0;
	unsigned dst_tiled = 0;
	unsigned yflip = 0;
	unsigned xdir = 0;
	unsigned ydir = 0;
	int err;

	if (PIX_BUF_FORMAT_BYTES(src->format) !=
		PIX_BUF_FORMAT_BYTES(dst->format))
	{
		host1x_error("Unequal bytes size\n");
		return -EINVAL;
	}

	switch (src->layout) {
	case PIX_BUF_LAYOUT_TILED_16x16:
		src_tiled = 1;
	case PIX_BUF_LAYOUT_LINEAR:
		break;
	default:
		host1x_error("Invalid src layout %u\n", src->layout);
		return -EINVAL;
	}

	switch (dst->layout) {
	case PIX_BUF_LAYOUT_TILED_16x16:
		dst_tiled = 1;
	case PIX_BUF_LAYOUT_LINEAR:
		break;
	default:
		host1x_error("Invalid dst layout %u\n", dst->layout);
		return -EINVAL;
	}

	if (height < 0) {
		yflip = 1;
		height = -height;
	}

	if (sx + width > src->width ||
	    dx + width > dst->width ||
	    sy + height > src->height ||
	    dy + height > dst->height) {
		host1x_error("Coords out of range\n");
		return -EINVAL;
	}

	if (src_orig != dst_orig)
		goto yflip_setup;

	/*
	 * For now this should never fail as host1x_pixelbuffer_create()
	 * allocates new BO. Keep that check just in case.
	 */
	if (src->bo->offset != dst->bo->offset ||
	    src->width != dst->width ||
	    src->pitch != dst->pitch ||
	    src->height != dst->height||
	    src->format != dst->format) {
		host1x_error("Sub-allocations are forbidden\n");
		return -EINVAL;
	}

	if (sx >= dx + width || sx + width <= dx)
		goto yflip_setup;

	if (sy >= dy + height || sy + height <= dy)
		goto yflip_setup;

	if (dx > sx) {
		xdir = 1;
		sx += width - 1;
		dx += width - 1;
	}

	if (dy > sy) {
		ydir = 1;
		sy += height - 1;
		dy += height - 1;
	}

yflip_setup:
	if (yflip && !ydir)
		dy += height - 1;

	job = HOST1X_JOB_CREATE(syncpt->id, 1);
	if (!job)
		return -ENOMEM;

	pb = HOST1X_JOB_APPEND(job, gr2d->commands, 0);
	if (!pb) {
		host1x_job_free(job);
		return -ENOMEM;
	}

	host1x_pushbuf_push(pb, HOST1X_OPCODE_SETCL(0, 0x51, 0));

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x009, 0x9));
	host1x_pushbuf_push(pb, 0x0000003a); /* trigger */
	host1x_pushbuf_push(pb, 0x00000000); /* cmdsel */

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x01e, 0x7));
	host1x_pushbuf_push(pb, 0x00000000); /* controlsecond */
	/*
	 * [20:20] source color depth (0: mono, 1: same)
	 * [17:16] destination color depth (0: 8 bpp, 1: 16 bpp, 2: 32 bpp)
	 */
	host1x_pushbuf_push(pb, /* controlmain */
			1 << 20 |
			(PIX_BUF_FORMAT_BYTES(dst->format) >> 1) << 16 |
			yflip << 14 | ydir << 10 | xdir << 9);
	host1x_pushbuf_push(pb, 0x000000cc); /* ropfade */

	host1x_pushbuf_push(pb, HOST1X_OPCODE_NONINCR(0x046, 1));
	/*
	 * [20:20] destination write tile mode (0: linear, 1: tiled)
	 * [ 0: 0] tile mode Y/RGB (0: linear, 1: tiled)
	 */
	host1x_pushbuf_push(pb, dst_tiled << 20 | src_tiled); /* tilemode */

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x02b, 0xe149));
	HOST1X_PUSHBUF_RELOCATE(pb, dst->bo, dst->bo->offset, 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* dstba */
	host1x_pushbuf_push(pb, dst->pitch); /* dstst */
	HOST1X_PUSHBUF_RELOCATE(pb, src->bo, src->bo->offset, 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* srcba */
	host1x_pushbuf_push(pb, src->pitch); /* srcst */
	host1x_pushbuf_push(pb, height << 16 | width); /* dstsize */
	host1x_pushbuf_push(pb, sy << 16 | sx); /* srcps */
	host1x_pushbuf_push(pb, dy << 16 | dx); /* dstps */
	host1x_pushbuf_sync(pb, 0, 1, HOST1X_SYNC_COND_OP_DONE, true);

	err = HOST1X_CLIENT_SUBMIT(gr2d->client, job);
	if (err < 0) {
		host1x_job_free(job);
		return err;
	}

	host1x_job_free(job);

	err = HOST1X_CLIENT_FLUSH(gr2d->client, &fence);
	if (err < 0)
		return err;

	err = HOST1X_CLIENT_WAIT(gr2d->client, fence, ~0u);
	if (err < 0)
		return err;

	host1x_pixelbuffer_check_guard(dst);

	return 0;
}

static uint32_t sb_offset(struct host1x_pixelbuffer *pixbuf,
			  uint32_t xpos, uint32_t ypos)
{
	uint32_t offset;
	uint32_t bytes_per_pixel = PIX_BUF_FORMAT_BYTES(pixbuf->format);
	uint32_t pixels_per_line = pixbuf->pitch / bytes_per_pixel;
	uint32_t xb;

	if (pixbuf->layout == PIX_BUF_LAYOUT_LINEAR) {
		offset = ypos * pixbuf->pitch;
		offset += xpos * bytes_per_pixel;
	} else {
		xb = xpos * bytes_per_pixel;
		offset = 16 * pixels_per_line * (ypos / 16);
		offset += 256 * (xb / 16);
		offset += 16 * (ypos % 16);
		offset += xb % 16;
	}

	return offset;
}

int host1x_gr2d_surface_blit(struct host1x_gr2d *gr2d,
			     struct host1x_pixelbuffer *src,
			     struct host1x_pixelbuffer *dst,
			     unsigned int sx, unsigned int sy,
			     unsigned int src_width, unsigned int src_height,
			     unsigned int dx, unsigned int dy,
			     unsigned int dst_width, int dst_height)
{
	struct host1x_syncpt *syncpt = &gr2d->client->syncpts[0];
	struct host1x_fence *fence;
	struct host1x_pushbuf *pb;
	struct host1x_job *job;
	float inv_scale_x;
	float inv_scale_y;
	unsigned src_tiled = 0;
	unsigned dst_tiled = 0;
	unsigned yflip = 0;
	unsigned src_fmt;
	unsigned dst_fmt;
	unsigned hftype;
	unsigned vftype;
	unsigned vfen;
	int err;

	switch (src->layout) {
	case PIX_BUF_LAYOUT_TILED_16x16:
		src_tiled = 1;
	case PIX_BUF_LAYOUT_LINEAR:
		break;
	default:
		host1x_error("Invalid src layout %u\n", src->layout);
		return -EINVAL;
	}

	switch (dst->layout) {
	case PIX_BUF_LAYOUT_TILED_16x16:
		dst_tiled = 1;
	case PIX_BUF_LAYOUT_LINEAR:
		break;
	default:
		host1x_error("Invalid dst layout %u\n", dst->layout);
		return -EINVAL;
	}

	/*
	 * GR2DSB doesn't support this format. Not sure that this is fine
	 * to do, but scaled result looks correct.
	 */
	if (src->format == dst->format &&
	    src->format == PIX_BUF_FMT_RGBA8888) {
		src_fmt = 14;
		dst_fmt = 14;
		goto coords_check;
	}

	switch (src->format) {
	case PIX_BUF_FMT_ABGR8888:
		src_fmt = 14;
		break;
	case PIX_BUF_FMT_ARGB8888:
		src_fmt = 15;
		break;
	default:
		host1x_error("Invalid src format %u\n", src->format);
		return -EINVAL;
	}

	switch (dst->format) {
	case PIX_BUF_FMT_ABGR8888:
		dst_fmt = 14;
		break;
	case PIX_BUF_FMT_ARGB8888:
		dst_fmt = 15;
		break;
	default:
		host1x_error("Invalid dst format %u\n", dst->format);
		return -EINVAL;
	}

coords_check:
	if (dst_height < 0) {
		yflip = 1;
		dst_height = -dst_height;
	}

	if (sx + src_width > src->width ||
	    dx + dst_width > dst->width ||
	    sy + src_height > src->height ||
	    dy + dst_height > dst->height) {
		host1x_error("Coords out of range\n");
		return -EINVAL;
	}

	inv_scale_x = (src_width) / (float)(dst_width);
	inv_scale_y = (src_height) / (float)(dst_height);

	if (inv_scale_y > 64.0f || inv_scale_y < 1.0f / 4096.0f) {
		host1x_error("Unsupported Y scale\n");
		return -EINVAL;
	}

	if (inv_scale_x > 64.0f || inv_scale_x < 1.0f / 4096.0f) {
		host1x_error("Unsupported X scale\n");
		return -EINVAL;
	}

	if (inv_scale_x == 1.0f)
		hftype = 7;
	else if (inv_scale_x < 1.0f)
		hftype = 0;
	else if (inv_scale_x < 1.3f)
		hftype = 1;
	else if (inv_scale_x < 2.0f)
		hftype = 3;
	else
		hftype = 6;

	if (inv_scale_y == 1.0f) {
		vftype = 0;
		vfen = 0;
	} else {
		vfen = 1;

		if (inv_scale_y < 1.0f)
			vftype = 0;
		else if (inv_scale_y < 1.3f)
			vftype = 1;
		else if (inv_scale_y < 2.0f)
			vftype = 2;
		else
			vftype = 3;
	}

	job = HOST1X_JOB_CREATE(syncpt->id, 1);
	if (!job)
		return -ENOMEM;

	pb = HOST1X_JOB_APPEND(job, gr2d->commands, 0);
	if (!pb) {
		host1x_job_free(job);
		return -ENOMEM;
	}

	host1x_pushbuf_push(pb, HOST1X_OPCODE_SETCL(0, 0x52, 0));

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x009, 0xF09));
	host1x_pushbuf_push(pb, 0x00000038); /* trigger */
	host1x_pushbuf_push(pb, 0x00000001); /* cmdsel */
	host1x_pushbuf_push(pb, FLOAT_TO_FIXED_6_12(inv_scale_y)); /* vdda */
	host1x_pushbuf_push(pb, FLOAT_TO_FIXED_0_8(sy)); /* vddaini */
	host1x_pushbuf_push(pb, FLOAT_TO_FIXED_6_12(inv_scale_x)); /* hdda */
	host1x_pushbuf_push(pb, FLOAT_TO_FIXED_0_8(sx)); /* hddainils */

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x15, 0x787));
	/* CSC RGB -> RGB coefficients */
	host1x_pushbuf_push(pb,
			/* cvr */ FLOAT_TO_FIXED_2_7(1.0f) << 12 |
			/* cub */ FLOAT_TO_FIXED_2_7(1.0f)); /* cscfirst */
	host1x_pushbuf_push(pb,
			/* cyx */ FLOAT_TO_FIXED_1_7(1.0f) << 24 |
			/* cur */ FLOAT_TO_FIXED_2_7(0.0f) << 12 |
			/* cug */ FLOAT_TO_FIXED_1_7(0.0f)); /* cscsecond */
	host1x_pushbuf_push(pb,
			/* cvb */ FLOAT_TO_FIXED_2_7(0.0f) << 16 |
			/* cvg */ FLOAT_TO_FIXED_1_7(0.0f)); /* cscthird */

	host1x_pushbuf_push(pb, dst_fmt << 8 | src_fmt); /* sbformat */
	host1x_pushbuf_push(pb, /* controlsb */
			    hftype << 20 | vfen << 18 | vftype << 16);
	host1x_pushbuf_push(pb, 0x00000000); /* controlsecond */
	/*
	 * [20:20] source color depth (0: mono, 1: same)
	 * [17:16] destination color depth (0: 8 bpp, 1: 16 bpp, 2: 32 bpp)
	 */
	host1x_pushbuf_push(pb, /* controlmain */
			1 << 28 | 1 << 27 |
			(PIX_BUF_FORMAT_BYTES(dst->format) >> 1) << 16 |
			yflip << 14);

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x046, 0xD));
	/*
	 * [20:20] destination write tile mode (0: linear, 1: tiled)
	 * [ 0: 0] tile mode Y/RGB (0: linear, 1: tiled)
	 */
	host1x_pushbuf_push(pb, dst_tiled << 20 | src_tiled); /* tilemode */
	HOST1X_PUSHBUF_RELOCATE(pb, src->bo,
				src->bo->offset + sb_offset(src, sx, sy), 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* srcba_sb_surfbase */
	HOST1X_PUSHBUF_RELOCATE(pb, dst->bo,
				dst->bo->offset + sb_offset(dst, dx, dy) +
				yflip * dst->pitch * (dst_height - 1), 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* dstba_sb_surfbase */

	host1x_pushbuf_push(pb, HOST1X_OPCODE_MASK(0x02b, 0x3149));
	HOST1X_PUSHBUF_RELOCATE(pb, dst->bo,
				dst->bo->offset + sb_offset(dst, dx, dy) +
				yflip * dst->pitch * (dst_height - 1), 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* dstba */
	host1x_pushbuf_push(pb, dst->pitch); /* dstst */
	HOST1X_PUSHBUF_RELOCATE(pb, src->bo,
				src->bo->offset + sb_offset(src, sx, sy), 0);
	host1x_pushbuf_push(pb, 0xdeadbeef); /* srcba */
	host1x_pushbuf_push(pb, src->pitch); /* srcst */
	host1x_pushbuf_push(pb,
			    (src_height - 1) << 16 | src_width); /* srcsize */
	host1x_pushbuf_push(pb,
			    (dst_height - 1) << 16 | dst_width); /* dstsize */

	host1x_pushbuf_sync(pb, 0, 1, HOST1X_SYNC_COND_OP_DONE, true);

	err = HOST1X_CLIENT_SUBMIT(gr2d->client, job);
	if (err < 0) {
		host1x_job_free(job);
		return err;
	}

	host1x_job_free(job);

	err = HOST1X_CLIENT_FLUSH(gr2d->client, &fence);
	if (err < 0)
		return err;

	err = HOST1X_CLIENT_WAIT(gr2d->client, fence, ~0u);
	if (err < 0)
		return err;

	host1x_pixelbuffer_check_guard(dst);

	return 0;
}
