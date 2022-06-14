// Author : Sachin Patil
// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 sachinp*/

#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>
#include "bpf/libbpf.h"
#include "openat.skel.h"

void read_trace_pipe(void);

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}


static void bump_memlock_rlimit(void)
{
	struct rlimit old_lim;

	if ( getrlimit(RLIMIT_MEMLOCK, &old_lim) == 0) {
    		printf("Old limits -> soft limit= %ld \t"
           	       " hard limit= %ld \n", old_lim.rlim_cur, old_lim.rlim_max);
	} else {
    		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}

	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};


	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}


int main(int argc, char **argv)
{
	struct openat_bpf *skel;
	int err;


	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);


	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();


	/* Open BPF application */
	skel = openat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}


	/* Load & verify BPF programs */
	err = openat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}


	/* Attach tracepoint handler */
	err = openat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	printf("Successfully started!"
	       "Watch '/sys/kernel/debug/tracing/trace_pipe' to see output of the BPF programs.\n");


	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		read_trace_pipe();
		//sleep(1);
	}


cleanup:
	openat_bpf__destroy(skel);
	return -err;
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

	        sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}


