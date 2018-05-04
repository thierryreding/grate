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
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>

#include <libdrm/drm_fourcc.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#include "host1x-private.h"
#include "tegra_drm.h"
#include "x11-display.h"

#define HOST1X_FENCE_WAIT (1 << 0)
#define HOST1X_FENCE_EMIT (1 << 1)
#define HOST1X_FENCE_FD   (1 << 2)

struct host1x_fence {
	unsigned int handle;
	unsigned int flags;
};

struct drm;

struct drm_bo {
	struct host1x_bo base;
	struct drm *drm;
};

static inline struct drm_bo *to_drm_bo(struct host1x_bo *bo)
{
	return container_of(bo, struct drm_bo, base);
}

struct drm_channel {
	struct host1x_client client;
	uint64_t context;
	struct drm *drm;

	struct host1x_fence fence;
};

static inline struct drm_channel *to_drm_channel(struct host1x_client *client)
{
	return container_of(client, struct drm_channel, client);
}

struct drm_display {
	struct host1x_display base;
	struct drm *drm;
	drmModeModeInfo mode;
	uint32_t connector;
	unsigned int pipe;
	uint32_t crtc;
};

static inline struct drm_display *to_drm_display(struct host1x_display *display)
{
	return container_of(display, struct drm_display, base);
}

struct drm_overlay {
	struct host1x_overlay base;
	struct drm_display *display;
	uint32_t plane;

	unsigned int x;
	unsigned int y;
	unsigned int width;
	unsigned int height;
	uint32_t format;
};

static inline struct drm_overlay *to_drm_overlay(struct host1x_overlay *overlay)
{
	return container_of(overlay, struct drm_overlay, base);
}

struct drm_gr2d {
	struct drm_channel channel;
	struct host1x_gr2d base;
};

struct drm_gr3d {
	struct drm_channel channel;
	struct host1x_gr3d base;
};

struct drm {
	struct host1x base;

	struct drm_display *display;
	struct drm_gr2d *gr2d;
	struct drm_gr3d *gr3d;

	int fd;
};

static struct drm *to_drm(struct host1x *host1x)
{
	return container_of(host1x, struct drm, base);
}

static int drm_display_find_plane(struct drm_display *display, uint32_t *plane)
{
	struct drm *drm = display->drm;
	drmModePlaneRes *res;
	uint32_t id = 0, i;

	res = drmModeGetPlaneResources(drm->fd);
	if (!res)
		return -errno;

	for (i = 0; i < res->count_planes && !id; i++) {
		drmModePlane *p = drmModeGetPlane(drm->fd, res->planes[i]);
		if (!p) {
			continue;
		}

		if (!p->crtc_id && (p->possible_crtcs & (1u << display->pipe)))
			id = p->plane_id;

		drmModeFreePlane(p);
	}

	drmModeFreePlaneResources(res);

	if (!id)
		return -ENODEV;

	if (plane)
		*plane = id;

	return 0;
}

static int drm_overlay_close(struct host1x_overlay *overlay)
{
	struct drm_overlay *plane = to_drm_overlay(overlay);
	struct drm_display *display = plane->display;
	struct drm *drm = display->drm;

	drmModeSetPlane(drm->fd, plane->plane, display->crtc, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0);

	free(plane);
	return 0;
}

static int drm_overlay_set(struct host1x_overlay *overlay,
			   struct host1x_framebuffer *fb, unsigned int x,
			   unsigned int y, unsigned int width,
			   unsigned int height, bool vsync)
{
	struct drm_overlay *plane = to_drm_overlay(overlay);
	struct drm_display *display = plane->display;
	struct drm *drm = display->drm;
	int err;

	if (vsync) {
		drmVBlank vblank = {
			.request = {
				.type = DRM_VBLANK_RELATIVE,
				.sequence = 1,
			},
		};

		vblank.request.type |=
				display->pipe << DRM_VBLANK_HIGH_CRTC_SHIFT;

		err = drmWaitVBlank(drm->fd, &vblank);
		if (err < 0) {
			host1x_error("drmWaitVBlank() failed: %m\n");
			return -errno;
		}
	}

	err = drmModeSetPlane(drm->fd, plane->plane, display->crtc,
			      fb->handle, 0, x, y, width, height, 0, 0,
			      fb->pixbuf->width << 16,
			      fb->pixbuf->height << 16);
	if (err < 0)
		return -errno;

	return 0;
}

static int drm_overlay_create(struct host1x_display *display,
			      struct host1x_overlay **overlayp)
{
	struct drm_display *drm = to_drm_display(display);
	struct drm_overlay *overlay;
	uint32_t plane = 0;
	int err;

	err = drm_display_find_plane(drm, &plane);
	if (err < 0)
		return err;

	overlay = calloc(1, sizeof(*overlay));
	if (!overlay)
		return -ENOMEM;

	overlay->base.close = drm_overlay_close;
	overlay->base.set = drm_overlay_set;

	overlay->display = drm;
	overlay->plane = plane;

	*overlayp = &overlay->base;

	return 0;
}

static void drm_display_on_page_flip(int fd, unsigned int frame,
				     unsigned int sec, unsigned int usec,
				     void *data)
{
}

static void drm_display_on_vblank(int fd, unsigned int frame,
				  unsigned int sec, unsigned int usec,
				  void *data)
{
}

static int drm_display_set(struct host1x_display *display,
			   struct host1x_framebuffer *fb, bool vsync)
{
	struct drm_display *drm = to_drm_display(display);
	int err;

	if (vsync) {
		struct timeval timeout;
		fd_set fds;

		err = drmModePageFlip(drm->drm->fd, drm->crtc, fb->handle,
				      DRM_MODE_PAGE_FLIP_EVENT, drm);
		if (err < 0) {
			err = drmModeSetCrtc(drm->drm->fd, drm->crtc,
					     fb->handle, 0, 0, &drm->connector,
					     1, &drm->mode);
		}

		if (err < 0) {
			host1x_error("drmModePageFlip() failed: %m\n");
			return -errno;
		}

		memset(&timeout, 0, sizeof(timeout));
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		FD_ZERO(&fds);
		FD_SET((unsigned)drm->drm->fd, &fds);

		err = select(drm->drm->fd + 1, &fds, NULL, NULL, &timeout);
		if (err <= 0) {
		}

		if (FD_ISSET((unsigned)drm->drm->fd, &fds)) {
			drmEventContext context;

			memset(&context, 0, sizeof(context));
			context.version = DRM_EVENT_CONTEXT_VERSION;
			context.page_flip_handler = drm_display_on_page_flip;
			context.vblank_handler = drm_display_on_vblank;

			drmHandleEvent(drm->drm->fd, &context);
		}
	} else {
		err = drmModeSetCrtc(drm->drm->fd, drm->crtc, fb->handle, 0,
				     0, &drm->connector, 1, &drm->mode);
		if (err < 0)
			return -errno;
	}

	return 0;
}

static int drm_display_setup(struct drm_display *display)
{
	struct drm *drm = display->drm;
	int ret = -ENODEV;
	drmModeRes *res;
	uint32_t i;

	res = drmModeGetResources(drm->fd);
	if (!res)
		return -ENODEV;

	for (i = 0; i < res->count_connectors; i++) {
		drmModeConnector *connector;
		drmModeEncoder *encoder;

		connector = drmModeGetConnector(drm->fd, res->connectors[i]);
		if (!connector)
			continue;

		if (connector->connection != DRM_MODE_CONNECTED) {
			drmModeFreeConnector(connector);
			continue;
		}

		encoder = drmModeGetEncoder(drm->fd, connector->encoder_id);
		if (!encoder) {
			drmModeFreeConnector(connector);
			continue;
		}

		display->connector = res->connectors[i];
		display->mode = connector->modes[0];
		display->crtc = encoder->crtc_id;

		drmModeFreeEncoder(encoder);
		drmModeFreeConnector(connector);
		ret = 0;
		break;
	}

	for (i = 0; i < res->count_crtcs; i++) {
		drmModeCrtc *crtc;

		crtc = drmModeGetCrtc(drm->fd, res->crtcs[i]);
		if (!crtc)
			continue;

		if (crtc->crtc_id == display->crtc) {
			drmModeFreeCrtc(crtc);
			display->pipe = i;
			break;
		}

		drmModeFreeCrtc(crtc);
	}

	drmModeFreeResources(res);
	return ret;
}

static int drm_display_create(struct drm_display **displayp, struct drm *drm)
{
	struct drm_display *display;
	int err;

	display = calloc(1, sizeof(*display));
	if (!display)
		return -ENOMEM;

	display->drm = drm;

	err = drmSetMaster(drm->fd);
	if (err < 0)
		goto try_x11;

	err = drm_display_setup(display);
	if (err < 0)
		goto try_x11;

	display->base.width = display->mode.hdisplay;
	display->base.height = display->mode.vdisplay;
	display->base.create_overlay = drm_overlay_create;
	display->base.set = drm_display_set;

	*displayp = display;

	return 0;
try_x11:
	err = x11_display_create(&drm->base, &display->base);
	if (err < 0) {
		free(display);
		return err;
	}

	*displayp = display;

	return 0;
}

static int drm_display_close(struct drm_display *display)
{
	struct drm *drm;

	if (!display)
		return -EINVAL;

	drm = display->drm;

	drmDropMaster(drm->fd);
	free(display);

	return 0;
}

static int drm_bo_mmap(struct host1x_bo *bo)
{
	struct drm_bo *drm = to_drm_bo(bo);
	struct drm_tegra_gem_mmap args;
	struct host1x_bo *orig;
	void *ptr;
	int err;

	orig = bo->wrapped ?: bo;

	if (orig->ptr) {
		bo->ptr = orig->ptr;
		return 0;
	}

	memset(&args, 0, sizeof(args));
	args.handle = bo->handle;

	err = ioctl(drm->drm->fd, DRM_IOCTL_TEGRA_GEM_MMAP, &args);
	if (err < 0)
		return -errno;

	ptr = mmap(NULL, orig->size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   drm->drm->fd, (__off_t)args.offset);
	if (ptr == MAP_FAILED)
		return -errno;

	orig->ptr = ptr;
	bo->ptr = ptr;

	return 0;
}

static int drm_bo_invalidate(struct host1x_bo *bo, unsigned long offset,
			     size_t length)
{
	return 0;
}

static int drm_bo_flush(struct host1x_bo *bo, unsigned long offset,
			size_t length)
{
	return 0;
}

static void drm_bo_free(struct host1x_bo *bo)
{
	struct drm_bo *drm_bo = to_drm_bo(bo);
	struct drm_gem_close args;
	int err;

	if (bo->wrapped)
		return free(drm_bo);

	memset(&args, 0, sizeof(args));
	args.handle = bo->handle;

	err = ioctl(drm_bo->drm->fd, DRM_IOCTL_GEM_CLOSE, &args);
	if (err < 0)
		host1x_error("failed to delete buffer object: %m\n");

	free(drm_bo);
}

static struct host1x_bo *drm_bo_clone(struct host1x_bo *bo)
{
	struct drm_bo *dbo = to_drm_bo(bo);
	struct drm_bo *clone = malloc(sizeof(*dbo));

	if (!clone)
		return NULL;

	memcpy(clone, dbo, sizeof(*dbo));

	return &clone->base;
}

static int drm_bo_export(struct host1x_bo *bo, uint32_t *handle)
{
	struct drm_bo *dbo = to_drm_bo(bo);
	struct drm_gem_flink args;
	int err;

	memset(&args, 0, sizeof(args));
	args.handle = bo->handle;

	err = drmIoctl(dbo->drm->fd, DRM_IOCTL_GEM_FLINK, &args);
	if (err < 0)
		return -errno;

	*handle = args.name;

	return 0;
}

static struct host1x_bo *drm_bo_create(struct host1x *host1x,
				       struct host1x_bo_priv *priv,
				       size_t size, unsigned long flags)
{
	struct drm_tegra_gem_create args;
	struct drm *drm = to_drm(host1x);
	struct drm_bo *bo;
	int err;

	bo = calloc(1, sizeof(*bo));
	if (!bo)
		return NULL;

	bo->drm = drm;
	bo->base.priv = priv;

	memset(&args, 0, sizeof(args));
	args.size = size;

	/*
	if (flags & HOST1X_BO_CREATE_FLAG_BOTTOM_UP)
		args.flags |= DRM_TEGRA_GEM_CREATE_BOTTOM_UP;

	if (flags & HOST1X_BO_CREATE_FLAG_TILED)
		args.flags |= DRM_TEGRA_GEM_CREATE_TILED;
	*/

	err = ioctl(drm->fd, DRM_IOCTL_TEGRA_GEM_CREATE, &args);
	if (err < 0) {
		free(bo);
		return NULL;
	}

	bo->base.handle = args.handle;

	bo->base.priv->mmap = drm_bo_mmap;
	bo->base.priv->invalidate = drm_bo_invalidate;
	bo->base.priv->flush = drm_bo_flush;
	bo->base.priv->free = drm_bo_free;
	bo->base.priv->clone = drm_bo_clone;
	bo->base.priv->export = drm_bo_export;

	return &bo->base;
}

static struct host1x_bo *drm_bo_import(struct host1x *host1x,
				       struct host1x_bo_priv *priv,
				       uint32_t handle)
{
	struct drm_gem_open args;
	struct drm *drm = to_drm(host1x);
	struct drm_bo *bo;
	int err;

	bo = calloc(1, sizeof(*bo));
	if (!bo)
		return NULL;

	bo->drm = drm;
	bo->base.priv = priv;

	memset(&args, 0, sizeof(args));
	args.name = handle;

	err = ioctl(drm->fd, DRM_IOCTL_GEM_OPEN, &args);
	if (err < 0) {
		free(bo);
		return NULL;
	}

	bo->base.handle = args.handle;

	bo->base.priv->mmap = drm_bo_mmap;
	bo->base.priv->invalidate = drm_bo_invalidate;
	bo->base.priv->flush = drm_bo_flush;
	bo->base.priv->free = drm_bo_free;
	bo->base.priv->clone = drm_bo_clone;
	bo->base.priv->export = drm_bo_export;

	return &bo->base;
}

static int drm_framebuffer_init(struct host1x *host1x,
				struct host1x_framebuffer *fb)
{
	uint32_t handles[4], pitches[4], offsets[4], format;
#ifdef DRM_FORMAT_MOD_NVIDIA_TEGRA_TILED
	uint64_t modifiers[4];
#endif
	struct host1x_pixelbuffer *pixbuf = fb->pixbuf;
	struct drm *drm = to_drm(host1x);
	int err = -1;

	/* XXX: support other formats */
	switch (pixbuf->format)
	{
	case PIX_BUF_FMT_RGB565:
		format = DRM_FORMAT_RGB565;
		break;
	case PIX_BUF_FMT_RGBA8888:
		format = DRM_FORMAT_XBGR8888;
		break;
	default:
		host1x_error("Unsupported framebuffer format\n");
		return -EINVAL;
	}

	memset(handles, 0, sizeof(handles));
	memset(pitches, 0, sizeof(pitches));
	memset(offsets, 0, sizeof(offsets));

	handles[0] = pixbuf->bo->handle;
	pitches[0] = pixbuf->pitch;
	offsets[0] = pixbuf->bo->offset;

#ifdef DRM_FORMAT_MOD_NVIDIA_TEGRA_TILED
	memset(modifiers, 0, sizeof(modifiers));

	if (pixbuf->layout == PIX_BUF_LAYOUT_TILED_16x16)
		modifiers[0] = DRM_FORMAT_MOD_NVIDIA_TEGRA_TILED;
	else
		modifiers[0] = DRM_FORMAT_MOD_LINEAR;

	err = drmModeAddFB2WithModifiers(drm->fd, pixbuf->width, pixbuf->height,
					 format, handles, pitches, offsets,
					 modifiers, &fb->handle,
					 DRM_MODE_FB_MODIFIERS);
	if (!err)
		return 0;
#endif
	err = drmModeAddFB2(drm->fd, pixbuf->width, pixbuf->height, format,
			    handles, pitches, offsets, &fb->handle, 0);
	if (err < 0)
		return -errno;

	return 0;
}

static int drm_channel_open(struct drm *drm, uint32_t class, uint64_t *channel,
			    unsigned int *num_syncpts)
{
	struct drm_tegra_open_channel args;
	int err;

	memset(&args, 0, sizeof(args));
	args.client = class;

	err = ioctl(drm->fd, DRM_IOCTL_TEGRA_OPEN_CHANNEL, &args);
	if (err < 0)
		return -errno;

	*num_syncpts = args.syncpts;
	*channel = args.context;

	return 0;
}

static int add_buffer(struct drm_tegra_buffer **buffersp,
		      unsigned int *num_buffersp, uint32_t handle)
{
	unsigned int num_buffers = *num_buffersp, i;
	struct drm_tegra_buffer *buf = *buffersp;

	for (i = 0; i < num_buffers; i++) {
		if (buf[i].handle == handle)
			return 0;
	}

	buf = realloc(buf, (num_buffers + 1) * sizeof(*buf));
	if (!buf)
		return -ENOMEM;

	buf[num_buffers].handle = handle;

	*num_buffersp = num_buffers + 1;
	*buffersp = buf;

	return 0;
}

static unsigned int get_buffer_index(struct drm_tegra_buffer *buffers,
				     unsigned int num_buffers,
				     uint32_t handle)
{
	unsigned int i;

	for (i = 0; i < num_buffers; i++) {
		if (buffers[i].handle == handle)
			return i;
	}

	abort();
	return 0;
}

static int drm_channel_submit(struct host1x_client *client,
			      struct host1x_job *job)
{
	unsigned int i, j, num_buffers = 0, num_relocs = 0, num_fences = 0;
	struct drm_channel *channel = to_drm_channel(client);
	struct drm_tegra_buffer *buffers = NULL;
	struct drm_tegra_reloc *relocs, *reloc;
	struct drm_tegra_fence *fences, *fence;
	struct drm_tegra_cmdbuf *cmdbufs;
	struct drm_tegra_submit args;
	int err;

	for (i = 0; i < job->num_pushbufs; i++) {
		struct host1x_pushbuf *pushbuf = &job->pushbufs[i];

		err = add_buffer(&buffers, &num_buffers, pushbuf->bo->handle);
		if (err < 0) {
			free(buffers);
			return err;
		}

		for (j = 0; j < pushbuf->num_relocs; j++) {
			struct host1x_pushbuf_reloc *r = &pushbuf->relocs[j];

			err = add_buffer(&buffers, &num_buffers,
					 r->target_handle);
			if (err < 0) {
				free(buffers);
				return err;
			}
		}

		num_relocs += pushbuf->num_relocs;
		num_fences += pushbuf->num_fences;
	}

	cmdbufs = calloc(job->num_pushbufs, sizeof(*cmdbufs));
	if (!cmdbufs) {
		free(buffers);
		return -ENOMEM;
	}

	relocs = calloc(num_relocs, sizeof(*relocs));
	if (!relocs) {
		free(cmdbufs);
		free(buffers);
		return -ENOMEM;
	}

	reloc = relocs;

	fences = calloc(num_fences, sizeof(*fences));
	if (!fences) {
		free(relocs);
		free(cmdbufs);
		free(buffers);
		return -ENOMEM;
	}

	fence = fences;

	for (i = 0; i < job->num_pushbufs; i++) {
		struct host1x_pushbuf *pushbuf = &job->pushbufs[i];
		struct drm_tegra_cmdbuf *cmdbuf = &cmdbufs[i];

		cmdbuf->index = get_buffer_index(buffers, num_buffers,
						 pushbuf->bo->handle);
		cmdbuf->offset = pushbuf->offset;
		cmdbuf->words = pushbuf->length;

		/* XXX flags */

		for (j = 0; j < pushbuf->num_relocs; j++) {
			struct host1x_pushbuf_reloc *r = &pushbuf->relocs[j];

			reloc->cmdbuf.index = get_buffer_index(buffers,
							       num_buffers,
							       pushbuf->bo->handle);
			reloc->cmdbuf.offset = r->source_offset;
			reloc->target.index = get_buffer_index(buffers,
							       num_buffers,
							       r->target_handle);
			reloc->target.offset = r->target_offset;
			reloc->shift = r->shift;

			/* XXX flags */

			reloc++;
		}

		if (pushbuf->num_fences) {
			cmdbuf->num_fences = pushbuf->num_fences;
			cmdbuf->fences = (uintptr_t)fence;
		}

		for (j = 0; j < pushbuf->num_fences; j++) {
			struct host1x_pushbuf_fence *f = &pushbuf->fences[j];

			fence->handle = f->handle;

			if (f->flags & HOST1X_PUSHBUF_FENCE_WAIT)
				fence->flags |= DRM_TEGRA_FENCE_WAIT;

			if (f->flags & HOST1X_PUSHBUF_FENCE_EMIT)
				fence->flags |= DRM_TEGRA_FENCE_EMIT;

			if (f->flags & HOST1X_PUSHBUF_FENCE_FD)
				fence->flags |= DRM_TEGRA_FENCE_FD;

			fence->offset = f->offset;
			fence->index = f->index;
			fence->value = f->value;

			fence++;
		}
	}

	memset(&args, 0, sizeof(args));
	args.context = channel->context;
	args.num_buffers = num_buffers;
	args.num_cmdbufs = job->num_pushbufs;
	args.num_relocs = num_relocs;
	args.timeout = 1000;

	args.buffers = (unsigned long)buffers;
	args.cmdbufs = (unsigned long)cmdbufs;
	args.relocs = (unsigned long)relocs;

	/* XXX flags */

	err = ioctl(channel->drm->fd, DRM_IOCTL_TEGRA_SUBMIT, &args);
	if (err < 0) {
		host1x_error("ioctl(DRM_IOCTL_TEGRA_SUBMIT) failed: %d\n",
			     errno);
		err = -errno;
	} else {
		channel->fence.handle = 0;
		channel->fence.flags = 0;

		for (i = 0; i < num_fences; i++) {
			if (fences[i].flags & DRM_TEGRA_FENCE_EMIT) {
				channel->fence.handle = fences[i].handle;
				channel->fence.flags = HOST1X_FENCE_EMIT;

				if (fences[i].flags & DRM_TEGRA_FENCE_WAIT)
					channel->fence.flags |= HOST1X_FENCE_WAIT;

				if (fences[i].flags & DRM_TEGRA_FENCE_FD)
					channel->fence.flags |= HOST1X_FENCE_FD;
			}
		}

		err = 0;
	}

	free(fences);
	free(relocs);
	free(cmdbufs);
	free(buffers);

	return err;
}

static int drm_channel_flush(struct host1x_client *client,
			     struct host1x_fence **fencep)
{
	struct drm_channel *channel = to_drm_channel(client);

	*fencep = &channel->fence;

	return 0;
}

static int drm_syncobj_destroy(int fd, uint32_t handle)
{
	struct drm_syncobj_destroy args;
	int err;

	memset(&args, 0, sizeof(args));
	args.handle = handle;

	err = ioctl(fd, DRM_IOCTL_SYNCOBJ_DESTROY, &args);
	if (err < 0)
		return -errno;

	return 0;
}

uint64_t clock_get_nanoseconds(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

static int drm_channel_wait(struct host1x_client *client,
			    struct host1x_fence *fence,
			    uint32_t timeout)
{
	struct drm_channel *channel = to_drm_channel(client);
	int err;

	if ((fence->flags & HOST1X_FENCE_EMIT) == 0)
		return 0;

	if (fence->flags & HOST1X_FENCE_FD) {
		while (true) {
			struct pollfd fds = {
				.fd = fence->handle,
				.events = POLLIN,
			};

			err = poll(&fds, 0, timeout);
			if (err > 0) {
				if (fds.revents & (POLLERR | POLLNVAL))
					err = -EINVAL;
				else
					err = 0;

				break;
			}

			if (err == 0) {
				err = -ETIMEDOUT;
				break;
			}

			if (errno != EINTR && errno != EAGAIN) {
				err = -errno;
				break;
			}
		}

		close(fence->handle);
	} else {
		struct drm_syncobj_wait args;
		uint64_t timeout;

		timeout = clock_get_nanoseconds() + UINT64_C(5 * 1000000000);

		memset(&args, 0, sizeof(args));
		args.handles = (uintptr_t)&fence->handle;
		args.count_handles = 1;
		args.timeout_nsec = timeout;
		args.flags = DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL;

		err = ioctl(channel->drm->fd, DRM_IOCTL_SYNCOBJ_WAIT, &args);
		if (err < 0)
			err = -errno;

		drm_syncobj_destroy(channel->drm->fd, fence->handle);
	}

	return err;
}

static int drm_channel_init(struct drm *drm, struct drm_channel *channel,
			    uint32_t class)
{
	struct host1x_syncpt *syncpts;
	unsigned int num_syncpts = 0;
	int err;

	err = drm_channel_open(drm, class, &channel->context, &num_syncpts);
	if (err < 0)
		return err;

	channel->drm = drm;

	syncpts = calloc(num_syncpts, sizeof(*syncpts));
	if (!syncpts)
		return -ENOMEM;

	channel->client.num_syncpts = num_syncpts;
	channel->client.syncpts = syncpts;

	channel->client.submit = drm_channel_submit;
	channel->client.flush = drm_channel_flush;
	channel->client.wait = drm_channel_wait;

	return 0;
}

static void drm_channel_exit(struct drm_channel *channel)
{
	struct drm_tegra_close_channel args;
	int err;

	memset(&args, 0, sizeof(args));
	args.context = channel->context;

	err = ioctl(channel->drm->fd, DRM_IOCTL_TEGRA_CLOSE_CHANNEL, &args);
	if (err < 0)
		host1x_error("ioctl(DRM_IOCTL_TEGRA_CLOSE_CHANNEL) failed: %d\n",
			     -errno);

	free(channel->client.syncpts);
}

static int drm_gr2d_create(struct drm_gr2d **gr2dp, struct drm *drm)
{
	struct drm_gr2d *gr2d;
	int err;

	gr2d = calloc(1, sizeof(*gr2d));
	if (!gr2d)
		return -ENOMEM;

	err = drm_channel_init(drm, &gr2d->channel, HOST1X_CLASS_GR2D);
	if (err < 0) {
		free(gr2d);
		return err;
	}

	gr2d->base.client = &gr2d->channel.client;

	err = host1x_gr2d_init(&drm->base, &gr2d->base);
	if (err < 0) {
		free(gr2d);
		return err;
	}

	*gr2dp = gr2d;

	return 0;
}

static void drm_gr2d_close(struct drm_gr2d *gr2d)
{
	if (gr2d) {
		drm_channel_exit(&gr2d->channel);
		host1x_gr2d_exit(&gr2d->base);
	}

	free(gr2d);
}

static int drm_gr3d_create(struct drm_gr3d **gr3dp, struct drm *drm)
{
	struct drm_gr3d *gr3d;
	int err;

	gr3d = calloc(1, sizeof(*gr3d));
	if (!gr3d)
		return -ENOMEM;

	err = drm_channel_init(drm, &gr3d->channel, HOST1X_CLASS_GR3D);
	if (err < 0) {
		free(gr3d);
		return err;
	}

	gr3d->base.client = &gr3d->channel.client;

	err = host1x_gr3d_init(&drm->base, &gr3d->base);
	if (err < 0) {
		free(gr3d);
		return err;
	}

	*gr3dp = gr3d;

	return 0;
}

static void drm_gr3d_close(struct drm_gr3d *gr3d)
{
	if (gr3d) {
		drm_channel_exit(&gr3d->channel);
		host1x_gr3d_exit(&gr3d->base);
	}

	free(gr3d);
}

static void drm_close(struct host1x *host1x)
{
	struct drm *drm = to_drm(host1x);

	drm_gr3d_close(drm->gr3d);
	drm_gr2d_close(drm->gr2d);
	drm_display_close(drm->display);

	close(drm->fd);
	free(drm);
}

struct host1x *host1x_drm_open(int fd)
{
	struct drm *drm;
	int err;

	if (fd < 0) {
		fd = open("/dev/dri/card0", O_RDWR);
		if (fd < 0)
			return NULL;
	}

	drm = calloc(1, sizeof(*drm));
	if (!drm) {
		close(fd);
		return NULL;
	}

	drm->fd = fd;

	drm->base.bo_create = drm_bo_create;
	drm->base.framebuffer_init = drm_framebuffer_init;
	drm->base.close = drm_close;
	drm->base.bo_import = drm_bo_import;

	err = drm_gr2d_create(&drm->gr2d, drm);
	if (err < 0) {
		host1x_error("drm_gr2d_create() failed: %d\n", err);
		free(drm);
		close(fd);
		return NULL;
	}

	err = drm_gr3d_create(&drm->gr3d, drm);
	if (err < 0) {
		host1x_error("drm_gr3d_create() failed: %d\n", err);
		free(drm);
		close(fd);
		return NULL;
	}

	drm->base.gr2d = &drm->gr2d->base;
	drm->base.gr3d = &drm->gr3d->base;

	return &drm->base;
}

void host1x_drm_display_init(struct host1x *host1x)
{
	struct drm *drm = to_drm(host1x);
	int err;

	err = drm_display_create(&drm->display, drm);
	if (err < 0) {
		host1x_error("drm_display_create() failed: %d\n", err);
	} else {
		drm->base.display = &drm->display->base;
	}
}
