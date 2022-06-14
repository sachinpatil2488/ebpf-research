// Author : Sachin Patil
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 sachinp*/

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __OPENAT_BPF_SKEL_H__
#define __OPENAT_BPF_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

struct openat_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *itracepoint__syscalls__sys_enter_openat;
	} progs;
	struct {
		struct bpf_link *itracepoint__syscalls__sys_enter_openat;
	} links;
	struct openat_bpf__rodata {
		int PATH_MAX;
	} *rodata;

#ifdef __cplusplus
	static inline struct openat_bpf *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct openat_bpf *open_and_load();
	static inline int load(struct openat_bpf *skel);
	static inline int attach(struct openat_bpf *skel);
	static inline void detach(struct openat_bpf *skel);
	static inline void destroy(struct openat_bpf *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
openat_bpf__destroy(struct openat_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
openat_bpf__create_skeleton(struct openat_bpf *obj);

static inline struct openat_bpf *
openat_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct openat_bpf *obj;
	int err;

	obj = (struct openat_bpf *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = openat_bpf__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	openat_bpf__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct openat_bpf *
openat_bpf__open(void)
{
	return openat_bpf__open_opts(NULL);
}

static inline int
openat_bpf__load(struct openat_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct openat_bpf *
openat_bpf__open_and_load(void)
{
	struct openat_bpf *obj;
	int err;

	obj = openat_bpf__open();
	if (!obj)
		return NULL;
	err = openat_bpf__load(obj);
	if (err) {
		openat_bpf__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
openat_bpf__attach(struct openat_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
openat_bpf__detach(struct openat_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *openat_bpf__elf_bytes(size_t *sz);

static inline int
openat_bpf__create_skeleton(struct openat_bpf *obj)
{
	struct bpf_object_skeleton *s;
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "openat_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	s->maps[0].name = "openat_b.rodata";
	s->maps[0].map = &obj->maps.rodata;
	s->maps[0].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "itracepoint__syscalls__sys_enter_openat";
	s->progs[0].prog = &obj->progs.itracepoint__syscalls__sys_enter_openat;
	s->progs[0].link = &obj->links.itracepoint__syscalls__sys_enter_openat;

	s->data = (void *)openat_bpf__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *openat_bpf__elf_bytes(size_t *sz)
{
	*sz = 8640;
	return (const void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x1c\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x17\0\x01\
\0\xbf\x16\0\0\0\0\0\0\x79\x68\x10\0\0\0\0\0\x79\x63\x18\0\0\0\0\0\xbf\xa7\0\0\
\0\0\0\0\x07\x07\0\0\0\xff\xff\xff\xbf\x71\0\0\0\0\0\0\xb7\x02\0\0\0\x01\0\0\
\x85\0\0\0\x70\0\0\0\x79\x69\x20\0\0\0\0\0\x79\x66\x28\0\0\0\0\0\x57\x06\0\0\
\xff\xff\0\0\x85\0\0\0\x0e\0\0\0\x7b\x6a\xf8\xfe\0\0\0\0\x67\x09\0\0\x20\0\0\0\
\xc7\x09\0\0\x20\0\0\0\x7b\x9a\xf0\xfe\0\0\0\0\x7b\x7a\xe8\xfe\0\0\0\0\x67\x08\
\0\0\x20\0\0\0\x77\x08\0\0\x20\0\0\0\x7b\x8a\xe0\xfe\0\0\0\0\x77\0\0\0\x20\0\0\
\0\x7b\x0a\xd8\xfe\0\0\0\0\xbf\xa3\0\0\0\0\0\0\x07\x03\0\0\xd8\xfe\xff\xff\x18\
\x01\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x59\0\0\0\xb7\x04\0\0\x28\0\0\0\
\x85\0\0\0\xb1\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x44\x75\x61\x6c\x20\
\x42\x53\x44\x2f\x47\x50\x4c\0\0\0\0\0\x01\0\0\x54\x72\x69\x70\x77\x69\x72\x65\
\x20\x65\x42\x50\x46\x20\x74\x72\x61\x63\x65\x20\x5b\x6f\x70\x65\x6e\x61\x74\
\x5d\x20\x3a\x20\x7b\x20\x70\x69\x64\x20\x3a\x20\x25\x6c\x75\x2c\x20\x66\x64\
\x20\x3a\x20\x25\x6c\x75\x2c\x20\x6e\x61\x6d\x65\x3a\x20\x25\x73\x2c\x20\x66\
\x6c\x61\x67\x73\x20\x3a\x20\x25\x64\x2c\x20\x6d\x6f\x64\x65\x20\x3a\x20\x25\
\x75\x20\x7d\x0a\0\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x31\
\x30\x2e\x30\x2e\x30\x2d\x34\x75\x62\x75\x6e\x74\x75\x31\x20\0\x6f\x70\x65\x6e\
\x61\x74\x2e\x62\x70\x66\x2e\x63\0\x2f\x68\x6f\x6d\x65\x2f\x76\x61\x67\x72\x61\
\x6e\x74\x2f\x65\x62\x70\x66\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x6f\x70\
\x65\x61\x6e\x74\0\x4c\x49\x43\x45\x4e\x53\x45\0\x63\x68\x61\x72\0\x5f\x5f\x41\
\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x50\x41\x54\
\x48\x5f\x4d\x41\x58\0\x69\x6e\x74\0\x5f\x5f\x5f\x66\x6d\x74\0\x62\x70\x66\x5f\
\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\x75\x73\x65\x72\0\x6c\x6f\x6e\x67\
\x20\x69\x6e\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\
\x75\x33\x32\0\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\
\x70\x69\x64\x5f\x74\x67\x69\x64\0\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\x20\x75\
\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x75\x36\x34\0\x62\x70\
\x66\x5f\x74\x72\x61\x63\x65\x5f\x76\x70\x72\x69\x6e\x74\x6b\0\x75\x6e\x73\x69\
\x67\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x75\x6d\x6f\x64\x65\x5f\x74\0\x6c\
\x6f\x6e\x67\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x69\x74\x72\
\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\
\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x66\x69\
\x6c\x65\x4e\x61\x6d\x65\0\x5f\x5f\x5f\x70\x61\x72\x61\x6d\0\x63\x74\x78\0\x65\
\x6e\x74\0\x74\x79\x70\x65\0\x66\x6c\x61\x67\x73\0\x75\x6e\x73\x69\x67\x6e\x65\
\x64\x20\x63\x68\x61\x72\0\x70\x72\x65\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\
\0\x70\x69\x64\0\x74\x72\x61\x63\x65\x5f\x65\x6e\x74\x72\x79\0\x69\x64\0\x61\
\x72\x67\x73\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\
\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x6e\x61\x6d\
\x65\x5f\x70\x74\x72\0\x6d\x6f\x64\x65\0\x64\x66\x64\0\0\0\0\0\0\0\0\0\x08\0\0\
\0\0\0\0\0\x01\0\x51\x08\0\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x01\0\x56\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x01\0\x53\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x48\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x03\0\x79\0\x9f\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x58\0\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\x03\0\x76\0\x9f\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x98\0\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\x03\0\x78\
\0\x9f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\xe8\0\0\0\0\0\0\0\x01\
\0\x50\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\x11\x01\x25\x0e\x13\x05\x03\x0e\x10\
\x17\x1b\x0e\x11\x01\x12\x06\0\0\x02\x34\0\x03\x0e\x49\x13\x3f\x19\x3a\x0b\x3b\
\x0b\x02\x18\0\0\x03\x01\x01\x49\x13\0\0\x04\x21\0\x49\x13\x37\x0b\0\0\x05\x24\
\0\x03\x0e\x3e\x0b\x0b\x0b\0\0\x06\x24\0\x03\x0e\x0b\x0b\x3e\x0b\0\0\x07\x26\0\
\x49\x13\0\0\x08\x2e\x01\x11\x01\x12\x06\x40\x18\x97\x42\x19\x03\x0e\x3a\x0b\
\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x09\x34\0\x03\x0e\x49\x13\x3a\x0b\x3b\x0b\
\x02\x18\0\0\x0a\x05\0\x02\x17\x03\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x0b\x34\0\
\x02\x18\x03\x0e\x3a\x0b\x3b\x0b\x49\x13\0\0\x0c\x34\0\x02\x17\x03\x0e\x3a\x0b\
\x3b\x0b\x49\x13\0\0\x0d\x0b\x01\x55\x17\0\0\x0e\x34\0\x03\x0e\x49\x13\x3a\x0b\
\x3b\x05\0\0\x0f\x0f\0\x49\x13\0\0\x10\x15\x01\x49\x13\x27\x19\0\0\x11\x05\0\
\x49\x13\0\0\x12\x0f\0\0\0\x13\x16\0\x49\x13\x03\x0e\x3a\x0b\x3b\x0b\0\0\x14\
\x26\0\0\0\x15\x15\0\x49\x13\x27\x19\0\0\x16\x21\0\x49\x13\x37\x05\0\0\x17\x13\
\x01\x03\x0e\x0b\x0b\x3a\x0b\x3b\x05\0\0\x18\x0d\0\x03\x0e\x49\x13\x3a\x0b\x3b\
\x05\x38\x0b\0\0\0\xa3\x02\0\0\x04\0\0\0\0\0\x08\x01\0\0\0\0\x0c\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\0\0\0\x02\0\0\0\0\x3f\0\0\0\x01\x05\x09\x03\0\
\0\0\0\0\0\0\0\x03\x4b\0\0\0\x04\x52\0\0\0\x0d\0\x05\0\0\0\0\x06\x01\x06\0\0\0\
\0\x08\x07\x02\0\0\0\0\x6e\0\0\0\x01\x06\x09\x03\0\0\0\0\0\0\0\0\x07\x73\0\0\0\
\x05\0\0\0\0\x05\x04\x08\0\0\0\0\0\0\0\0\xf8\0\0\0\x01\x5a\0\0\0\0\x01\x11\x73\
\0\0\0\x09\0\0\0\0\x25\x01\0\0\x01\x22\x09\x03\x04\0\0\0\0\0\0\0\x0a\0\0\0\0\0\
\0\0\0\x01\x11\x12\x02\0\0\x0b\x02\x91\x28\0\0\0\0\x01\x17\xf9\x01\0\0\x0c\x36\
\0\0\0\0\0\0\0\x01\x16\xcf\x01\0\0\x0c\x59\0\0\0\0\0\0\0\x01\x1a\x73\0\0\0\x0c\
\x7e\0\0\0\0\0\0\0\x01\x1d\xd4\x01\0\0\x0c\xa3\0\0\0\0\0\0\0\x01\x13\x6f\x01\0\
\0\x0c\xc8\0\0\0\0\0\0\0\x01\x20\xf2\x01\0\0\x0d\0\0\0\0\x0b\x02\x91\0\0\0\0\0\
\x01\x22\x06\x02\0\0\0\0\x03\x31\x01\0\0\x04\x52\0\0\0\x59\0\x07\x4b\0\0\0\x0e\
\0\0\0\0\x42\x01\0\0\x03\xbd\x0a\x0f\x47\x01\0\0\x10\x5c\x01\0\0\x11\x63\x01\0\
\0\x11\x64\x01\0\0\x11\x76\x01\0\0\0\x05\0\0\0\0\x05\x08\x12\x13\x6f\x01\0\0\0\
\0\0\0\x02\x12\x05\0\0\0\0\x07\x04\x0f\x7b\x01\0\0\x14\x0e\0\0\0\0\x88\x01\0\0\
\x03\x6b\x01\x0f\x8d\x01\0\0\x15\x92\x01\0\0\x13\x9d\x01\0\0\0\0\0\0\x02\x16\
\x05\0\0\0\0\x07\x08\x0e\0\0\0\0\xb0\x01\0\0\x03\xfd\x0f\x0f\xb5\x01\0\0\x10\
\x5c\x01\0\0\x11\xcf\x01\0\0\x11\x64\x01\0\0\x11\x76\x01\0\0\x11\x64\x01\0\0\0\
\x0f\x31\x01\0\0\x13\xdf\x01\0\0\0\0\0\0\x02\x4b\x05\0\0\0\0\x07\x02\x03\xf2\
\x01\0\0\x04\x52\0\0\0\x06\0\x05\0\0\0\0\x07\x08\x03\x4b\0\0\0\x16\x52\0\0\0\0\
\x01\0\x03\x9d\x01\0\0\x04\x52\0\0\0\x05\0\x0f\x17\x02\0\0\x17\0\0\0\0\x40\x02\
\x81\x8c\x18\0\0\0\0\x55\x02\0\0\x02\x82\x8c\0\x18\0\0\0\0\x5c\x01\0\0\x02\x83\
\x8c\x08\x18\0\0\0\0\xe6\x01\0\0\x02\x84\x8c\x10\x18\0\0\0\0\x9a\x02\0\0\x02\
\x85\x8c\x40\0\x17\0\0\0\0\x08\x02\xe5\x2a\x18\0\0\0\0\xdf\x01\0\0\x02\xe6\x2a\
\0\x18\0\0\0\0\x93\x02\0\0\x02\xe7\x2a\x02\x18\0\0\0\0\x93\x02\0\0\x02\xe8\x2a\
\x03\x18\0\0\0\0\x73\0\0\0\x02\xe9\x2a\x04\0\x05\0\0\0\0\x08\x01\x03\x4b\0\0\0\
\x04\x52\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x88\0\0\0\0\0\0\0\x98\0\0\0\0\0\0\0\xa0\
\0\0\0\0\0\0\0\xa8\0\0\0\0\0\0\0\xb8\0\0\0\0\0\0\0\xc0\0\0\0\0\0\0\0\xe8\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\xf8\
\x01\0\0\xf8\x01\0\0\x95\x03\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\x01\0\0\0\x04\0\0\
\x04\x40\0\0\0\x1b\0\0\0\x03\0\0\0\0\0\0\0\x1f\0\0\0\x07\0\0\0\x40\0\0\0\x22\0\
\0\0\x09\0\0\0\x80\0\0\0\x27\0\0\0\x0c\0\0\0\0\x02\0\0\x2e\0\0\0\x04\0\0\x04\
\x08\0\0\0\x3a\0\0\0\x04\0\0\0\0\0\0\0\x3f\0\0\0\x05\0\0\0\x10\0\0\0\x45\0\0\0\
\x05\0\0\0\x18\0\0\0\x53\0\0\0\x06\0\0\0\x20\0\0\0\x57\0\0\0\0\0\0\x01\x02\0\0\
\0\x10\0\0\0\x66\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\0\x74\0\0\0\0\0\0\x01\x04\0\
\0\0\x20\0\0\x01\x78\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\x01\x81\0\0\0\0\0\0\x01\
\x08\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x08\0\0\0\x0a\0\0\0\x06\0\0\0\
\x93\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\xa7\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\
\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x0b\0\0\0\x0a\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x0d\
\x06\0\0\0\xac\0\0\0\x01\0\0\0\xb0\0\0\0\x01\0\0\x0c\x0d\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\0\x0b\0\0\0\x0a\0\0\0\x0d\0\0\0\x45\x03\0\0\0\0\0\x0e\x0f\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\x0a\x06\0\0\0\x4d\x03\0\0\0\0\0\x0e\x11\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\x0a\x0b\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x13\0\0\0\x0a\0\0\0\x59\0\
\0\0\x56\x03\0\0\0\0\0\x0e\x14\0\0\0\0\0\0\0\x85\x03\0\0\x02\0\0\x0f\0\0\0\0\
\x12\0\0\0\0\0\0\0\x04\0\0\0\x15\0\0\0\x04\0\0\0\x59\0\0\0\x8d\x03\0\0\x01\0\0\
\x0f\0\0\0\0\x10\0\0\0\0\0\0\0\x0d\0\0\0\0\x74\x72\x61\x63\x65\x5f\x65\x76\x65\
\x6e\x74\x5f\x72\x61\x77\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\0\x65\x6e\x74\
\0\x69\x64\0\x61\x72\x67\x73\0\x5f\x5f\x64\x61\x74\x61\0\x74\x72\x61\x63\x65\
\x5f\x65\x6e\x74\x72\x79\0\x74\x79\x70\x65\0\x66\x6c\x61\x67\x73\0\x70\x72\x65\
\x65\x6d\x70\x74\x5f\x63\x6f\x75\x6e\x74\0\x70\x69\x64\0\x75\x6e\x73\x69\x67\
\x6e\x65\x64\x20\x73\x68\x6f\x72\x74\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x63\
\x68\x61\x72\0\x69\x6e\x74\0\x6c\x6f\x6e\x67\x20\x69\x6e\x74\0\x6c\x6f\x6e\x67\
\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\
\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x63\x68\x61\x72\0\x63\
\x74\x78\0\x69\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\
\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\
\x6e\x61\x74\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\
\x6c\x6c\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\
\x74\0\x2f\x68\x6f\x6d\x65\x2f\x76\x61\x67\x72\x61\x6e\x74\x2f\x65\x62\x70\x66\
\x2d\x65\x78\x61\x6d\x70\x6c\x65\x73\x2f\x6f\x70\x65\x61\x6e\x74\x2f\x6f\x70\
\x65\x6e\x61\x74\x2e\x62\x70\x66\x2e\x63\0\x69\x6e\x74\x20\x69\x74\x72\x61\x63\
\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\
\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\x28\x73\x74\x72\
\x75\x63\x74\x20\x74\x72\x61\x63\x65\x5f\x65\x76\x65\x6e\x74\x5f\x72\x61\x77\
\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x20\x2a\x63\x74\x78\x29\0\x30\x3a\x32\
\x3a\x30\0\x20\x20\x20\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\x20\
\x64\x66\x64\x20\x3d\x20\x28\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\
\x29\x63\x74\x78\x2d\x3e\x61\x72\x67\x73\x5b\x30\x5d\x3b\0\x30\x3a\x32\x3a\x31\
\0\x20\x20\x20\x20\x63\x6f\x6e\x73\x74\x20\x63\x68\x61\x72\x20\x2a\x20\x6e\x61\
\x6d\x65\x5f\x70\x74\x72\x20\x3d\x20\x28\x63\x6f\x6e\x73\x74\x20\x63\x68\x61\
\x72\x20\x2a\x29\x63\x74\x78\x2d\x3e\x61\x72\x67\x73\x5b\x31\x5d\x3b\0\x20\x20\
\x20\x20\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\x72\x65\x61\x64\x5f\x75\x73\
\x65\x72\x28\x26\x66\x69\x6c\x65\x4e\x61\x6d\x65\x2c\x20\x73\x69\x7a\x65\x6f\
\x66\x28\x66\x69\x6c\x65\x4e\x61\x6d\x65\x29\x2c\x20\x6e\x61\x6d\x65\x5f\x70\
\x74\x72\x29\x3b\0\x30\x3a\x32\x3a\x32\0\x20\x20\x20\x20\x69\x6e\x74\x20\x66\
\x6c\x61\x67\x73\x20\x3d\x20\x28\x69\x6e\x74\x29\x63\x74\x78\x2d\x3e\x61\x72\
\x67\x73\x5b\x32\x5d\x3b\0\x30\x3a\x32\x3a\x33\0\x20\x20\x20\x20\x75\x6d\x6f\
\x64\x65\x5f\x74\x20\x6d\x6f\x64\x65\x20\x3d\x20\x28\x75\x6d\x6f\x64\x65\x5f\
\x74\x29\x63\x74\x78\x2d\x3e\x61\x72\x67\x73\x5b\x33\x5d\x3b\0\x20\x20\x20\x20\
\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\x20\x70\x69\x64\x20\x3d\
\x20\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\
\x64\x5f\x74\x67\x69\x64\x28\x29\x20\x3e\x3e\x20\x33\x32\x3b\0\x20\x20\x20\x20\
\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x54\x72\x69\x70\x77\x69\x72\
\x65\x20\x65\x42\x50\x46\x20\x74\x72\x61\x63\x65\x20\x5b\x6f\x70\x65\x6e\x61\
\x74\x5d\x20\x3a\x20\x7b\x20\x70\x69\x64\x20\x3a\x20\x25\x6c\x75\x2c\x20\x66\
\x64\x20\x3a\x20\x25\x6c\x75\x2c\x20\x6e\x61\x6d\x65\x3a\x20\x25\x73\x2c\x20\
\x66\x6c\x61\x67\x73\x20\x3a\x20\x25\x64\x2c\x20\x6d\x6f\x64\x65\x20\x3a\x20\
\x25\x75\x20\x7d\x5c\x6e\x22\x2c\x20\0\x20\x20\x20\x20\x72\x65\x74\x75\x72\x6e\
\x20\x30\x3b\0\x4c\x49\x43\x45\x4e\x53\x45\0\x50\x41\x54\x48\x5f\x4d\x41\x58\0\
\x69\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\
\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\
\x74\x2e\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\
\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x1c\x01\
\0\0\x30\x01\0\0\x4c\0\0\0\x08\0\0\0\xd8\0\0\0\x01\0\0\0\0\0\0\0\x0e\0\0\0\x10\
\0\0\0\xd8\0\0\0\x11\0\0\0\0\0\0\0\xfd\0\0\0\x2d\x01\0\0\0\x44\0\0\x08\0\0\0\
\xfd\0\0\0\x86\x01\0\0\x26\x4c\0\0\x10\0\0\0\xfd\0\0\0\xbf\x01\0\0\x2b\x58\0\0\
\x20\0\0\0\xfd\0\0\0\0\0\0\0\0\0\0\0\x28\0\0\0\xfd\0\0\0\xf7\x01\0\0\x05\x60\0\
\0\x40\0\0\0\xfd\0\0\0\x3d\x02\0\0\x16\x68\0\0\x48\0\0\0\xfd\0\0\0\x66\x02\0\0\
\x1d\x74\0\0\x50\0\0\0\xfd\0\0\0\0\0\0\0\0\0\0\0\x58\0\0\0\xfd\0\0\0\x90\x02\0\
\0\x19\x80\0\0\x60\0\0\0\xfd\0\0\0\xca\x02\0\0\x05\x88\0\0\x88\0\0\0\xfd\0\0\0\
\0\0\0\0\0\0\0\0\x98\0\0\0\xfd\0\0\0\xca\x02\0\0\x05\x88\0\0\xa0\0\0\0\xfd\0\0\
\0\x90\x02\0\0\x34\x80\0\0\xa8\0\0\0\xfd\0\0\0\xca\x02\0\0\x05\x88\0\0\xb8\0\0\
\0\xfd\0\0\0\0\0\0\0\0\0\0\0\xc0\0\0\0\xfd\0\0\0\xca\x02\0\0\x05\x88\0\0\xe8\0\
\0\0\xfd\0\0\0\x37\x03\0\0\x05\x94\0\0\x10\0\0\0\xd8\0\0\0\x04\0\0\0\x08\0\0\0\
\x02\0\0\0\x80\x01\0\0\0\0\0\0\x10\0\0\0\x02\0\0\0\xb9\x01\0\0\0\0\0\0\x40\0\0\
\0\x02\0\0\0\x37\x02\0\0\0\0\0\0\x48\0\0\0\x02\0\0\0\x60\x02\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\x0b\0\x14\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\xcb\0\0\0\x04\0\x6d\0\0\0\x08\x01\x01\xfb\
\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\x2e\0\x2f\x68\x6f\x6d\x65\x2f\x76\
\x61\x67\x72\x61\x6e\x74\0\0\x6f\x70\x65\x6e\x61\x74\x2e\x62\x70\x66\x2e\x63\0\
\0\0\0\x76\x6d\x6c\x69\x6e\x75\x78\x2e\x68\0\x01\0\0\x6c\x69\x62\x62\x70\x66\
\x2f\x73\x72\x63\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x70\x66\x2f\x62\x70\
\x66\x5f\x68\x65\x6c\x70\x65\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x02\0\0\0\0\x09\
\x02\0\0\0\0\0\0\0\0\x03\x11\x01\x05\x26\x0a\x21\x05\x2b\x23\x06\x03\x6a\x20\
\x05\x05\x06\x03\x18\x2e\x05\x16\x3e\x05\x1d\x23\x05\0\x06\x03\x63\x20\x05\x19\
\x06\x03\x20\x20\x05\x05\x22\x05\0\x06\x03\x5e\x58\x05\x05\x03\x22\x2e\x05\x34\
\x06\x1e\x05\x05\x22\x05\0\x06\x03\x5e\x2e\x05\x05\x03\x22\x20\x06\x5b\x02\x02\
\0\x01\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0d\x01\0\0\x04\0\
\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x1f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\x2c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x4f\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x57\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\x5c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x70\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x79\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\x7d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x84\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x98\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\xa1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xae\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xb4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\xcd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xe4\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xea\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\xfc\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x0b\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x13\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x07\0\x25\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x4d\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x56\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x07\0\x5f\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x63\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x67\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x07\0\x6c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\
\x72\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x80\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x8e\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x07\0\x92\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\x9e\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xa1\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x07\0\xa6\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xad\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xc7\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x07\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x07\0\xd5\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x01\0\x06\0\x04\0\0\0\0\0\0\0\x59\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\x0c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x11\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\x13\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x44\x01\0\0\
\x11\0\x05\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x32\x01\0\0\x11\0\x06\0\0\0\0\0\
\0\0\0\0\x04\0\0\0\0\0\0\0\x51\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\xf8\0\0\0\0\0\
\0\0\xc0\0\0\0\0\0\0\0\x01\0\0\0\x2a\0\0\0\x06\0\0\0\0\0\0\0\x0a\0\0\0\x2c\0\0\
\0\x0c\0\0\0\0\0\0\0\x0a\0\0\0\x02\0\0\0\x12\0\0\0\0\0\0\0\x0a\0\0\0\x03\0\0\0\
\x16\0\0\0\0\0\0\0\x0a\0\0\0\x2f\0\0\0\x1a\0\0\0\0\0\0\0\x0a\0\0\0\x04\0\0\0\
\x1e\0\0\0\0\0\0\0\x01\0\0\0\x29\0\0\0\x2b\0\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\
\x37\0\0\0\0\0\0\0\x01\0\0\0\x30\0\0\0\x4c\0\0\0\0\0\0\0\x0a\0\0\0\x06\0\0\0\
\x53\0\0\0\0\0\0\0\x0a\0\0\0\x07\0\0\0\x5a\0\0\0\0\0\0\0\x0a\0\0\0\x08\0\0\0\
\x66\0\0\0\0\0\0\0\x01\0\0\0\x31\0\0\0\x74\0\0\0\0\0\0\0\x0a\0\0\0\x09\0\0\0\
\x7b\0\0\0\0\0\0\0\x01\0\0\0\x29\0\0\0\x89\0\0\0\0\0\0\0\x0a\0\0\0\x16\0\0\0\
\x94\0\0\0\0\0\0\0\x0a\0\0\0\x0a\0\0\0\xa0\0\0\0\0\0\0\0\x01\0\0\0\x2a\0\0\0\
\xa9\0\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\xad\0\0\0\0\0\0\0\x0a\0\0\0\x19\0\0\0\
\xbb\0\0\0\0\0\0\0\x0a\0\0\0\x17\0\0\0\xc6\0\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\
\xca\0\0\0\0\0\0\0\x0a\0\0\0\x25\0\0\0\xd5\0\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\
\xd9\0\0\0\0\0\0\0\x0a\0\0\0\x1c\0\0\0\xe4\0\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\
\xe8\0\0\0\0\0\0\0\x0a\0\0\0\x26\0\0\0\xf3\0\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\
\xf7\0\0\0\0\0\0\0\x0a\0\0\0\x27\0\0\0\x02\x01\0\0\0\0\0\0\x0a\0\0\0\x2b\0\0\0\
\x06\x01\0\0\0\0\0\0\x0a\0\0\0\x1f\0\0\0\x11\x01\0\0\0\0\0\0\x0a\0\0\0\x2d\0\0\
\0\x19\x01\0\0\0\0\0\0\x0a\0\0\0\x18\0\0\0\x37\x01\0\0\0\0\0\0\x0a\0\0\0\x0b\0\
\0\0\x5d\x01\0\0\0\0\0\0\x0a\0\0\0\x0c\0\0\0\x69\x01\0\0\0\0\0\0\x0a\0\0\0\x0e\
\0\0\0\x70\x01\0\0\0\0\0\0\x0a\0\0\0\x0d\0\0\0\x7d\x01\0\0\0\0\0\0\x0a\0\0\0\
\x0f\0\0\0\x97\x01\0\0\0\0\0\0\x0a\0\0\0\x11\0\0\0\x9e\x01\0\0\0\0\0\0\x0a\0\0\
\0\x10\0\0\0\xa5\x01\0\0\0\0\0\0\x0a\0\0\0\x12\0\0\0\xd9\x01\0\0\0\0\0\0\x0a\0\
\0\0\x14\0\0\0\xe0\x01\0\0\0\0\0\0\x0a\0\0\0\x13\0\0\0\xf3\x01\0\0\0\0\0\0\x0a\
\0\0\0\x15\0\0\0\x18\x02\0\0\0\0\0\0\x0a\0\0\0\x24\0\0\0\x21\x02\0\0\0\0\0\0\
\x0a\0\0\0\x1a\0\0\0\x2e\x02\0\0\0\0\0\0\x0a\0\0\0\x21\0\0\0\x3b\x02\0\0\0\0\0\
\0\x0a\0\0\0\x22\0\0\0\x48\x02\0\0\0\0\0\0\x0a\0\0\0\x23\0\0\0\x56\x02\0\0\0\0\
\0\0\x0a\0\0\0\x20\0\0\0\x5f\x02\0\0\0\0\0\0\x0a\0\0\0\x1b\0\0\0\x6c\x02\0\0\0\
\0\0\0\x0a\0\0\0\x1c\0\0\0\x79\x02\0\0\0\0\0\0\x0a\0\0\0\x1e\0\0\0\x86\x02\0\0\
\0\0\0\0\x0a\0\0\0\x1f\0\0\0\x94\x02\0\0\0\0\0\0\x0a\0\0\0\x1d\0\0\0\xe4\x01\0\
\0\0\0\0\0\x0a\0\0\0\x31\0\0\0\xf0\x01\0\0\0\0\0\0\x0a\0\0\0\x2a\0\0\0\x08\x02\
\0\0\0\0\0\0\0\0\0\0\x30\0\0\0\x2c\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x40\0\0\0\0\
\0\0\0\0\0\0\0\x29\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x60\0\0\0\0\0\0\0\
\0\0\0\0\x29\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\
\0\x29\0\0\0\x90\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\x29\
\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\
\xd0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\xf0\0\
\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x10\x01\0\0\
\0\0\0\0\0\0\0\0\x29\0\0\0\x20\x01\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x30\x01\0\0\0\
\0\0\0\0\0\0\0\x29\0\0\0\x40\x01\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x5c\x01\0\0\0\0\
\0\0\0\0\0\0\x29\0\0\0\x6c\x01\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x7c\x01\0\0\0\0\0\
\0\0\0\0\0\x29\0\0\0\x8c\x01\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x14\0\0\0\0\0\0\0\
\x0a\0\0\0\x2e\0\0\0\x18\0\0\0\0\0\0\0\x01\0\0\0\x29\0\0\0\x7a\0\0\0\0\0\0\0\
\x01\0\0\0\x29\0\0\0\x32\x30\x28\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\x62\x72\
\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\
\x74\0\x69\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x5f\x5f\x73\x79\x73\x63\x61\
\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\
\x61\x74\x2e\x5f\x5f\x5f\x66\x6d\x74\0\x69\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\
\x74\x5f\x5f\x73\x79\x73\x63\x61\x6c\x6c\x73\x5f\x5f\x73\x79\x73\x5f\x65\x6e\
\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x2e\x72\x65\x6c\x74\x72\x61\x63\x65\
\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\x73\x79\x73\x5f\
\x65\x6e\x74\x65\x72\x5f\x6f\x70\x65\x6e\x61\x74\0\x2e\x64\x65\x62\x75\x67\x5f\
\x72\x61\x6e\x67\x65\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x72\
\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x6c\x6c\x76\x6d\x5f\
\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\
\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x2e\x64\x65\x62\x75\x67\x5f\x6c\x6f\x63\0\
\x6f\x70\x65\x6e\x61\x74\x2e\x62\x70\x66\x2e\x63\0\x2e\x73\x74\x72\x74\x61\x62\
\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x50\x41\x54\x48\
\x5f\x4d\x41\x58\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\
\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\x01\0\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb3\x1a\0\0\0\0\0\0\x4c\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7d\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x40\0\0\0\0\0\0\0\xf8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x79\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x15\0\0\0\
\0\0\0\x10\0\0\0\0\0\0\0\x16\0\0\0\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\xd9\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x01\0\0\0\0\0\0\
\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x2a\x01\0\
\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x48\x01\0\0\0\0\0\0\x5d\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\0\0\0\x01\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa5\x01\0\0\0\0\0\0\xd9\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x02\x01\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x7e\x03\0\0\0\0\0\0\xeb\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x69\x04\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xbf\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x81\
\x05\0\0\0\0\0\0\xa7\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xbb\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x15\0\0\0\0\0\
\0\x60\x03\0\0\0\0\0\0\x16\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\xa2\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x28\x08\0\0\0\0\0\0\x50\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3f\x01\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x78\x08\0\0\0\0\0\0\xa5\x05\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x3b\x01\0\0\x09\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xf0\x18\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x16\0\0\0\x0d\
\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x1d\x0e\0\0\0\0\0\0\x9c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x15\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x20\x19\0\0\0\0\0\0\x60\x01\0\0\0\0\0\0\x16\0\0\0\x0f\0\0\0\x08\0\0\0\0\0\0\
\0\x10\0\0\0\0\0\0\0\xf5\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc0\
\x0f\0\0\0\0\0\0\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xf1\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x1a\0\0\0\0\0\0\
\x20\0\0\0\0\0\0\0\x16\0\0\0\x11\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xe5\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x0f\0\0\0\0\0\0\xcf\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe1\0\0\0\x09\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x1a\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x16\0\0\
\0\x13\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xcb\0\0\0\x03\x4c\xff\x6f\0\0\
\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x1a\0\0\0\0\0\0\x03\0\0\0\0\0\0\0\x16\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xb8\x10\0\0\0\0\0\0\xc8\x04\0\0\0\0\0\0\x01\0\0\0\x30\0\0\0\
\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0";
}

#ifdef __cplusplus
struct openat_bpf *openat_bpf::open(const struct bpf_object_open_opts *opts) { return openat_bpf__open_opts(opts); }
struct openat_bpf *openat_bpf::open_and_load() { return openat_bpf__open_and_load(); }
int openat_bpf::load(struct openat_bpf *skel) { return openat_bpf__load(skel); }
int openat_bpf::attach(struct openat_bpf *skel) { return openat_bpf__attach(skel); }
void openat_bpf::detach(struct openat_bpf *skel) { openat_bpf__detach(skel); }
void openat_bpf::destroy(struct openat_bpf *skel) { openat_bpf__destroy(skel); }
const void *openat_bpf::elf_bytes(size_t *sz) { return openat_bpf__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
openat_bpf__assert(struct openat_bpf *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
	_Static_assert(sizeof(s->rodata->PATH_MAX) == 4, "unexpected size of 'PATH_MAX'");
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __OPENAT_BPF_SKEL_H__ */