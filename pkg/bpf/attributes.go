package bpf

import (
	"errors"
	"reflect"
	"unsafe"

	"golang.org/x/sys/unix"
)

// struct { /* anonymous struct used by BPF_MAP_CREATE command */
// 	__u32	map_type;	/* one of enum bpf_map_type */
// 	__u32	key_size;	/* size of key in bytes */
// 	__u32	value_size;	/* size of value in bytes */
// 	__u32	max_entries;	/* max number of entries in a map */
// 	__u32	map_flags;	/* BPF_MAP_CREATE related
// 				 * flags defined above.
// 				 */
// 	__u32	inner_map_fd;	/* fd pointing to the inner map */
// 	__u32	numa_node;	/* numa node (effective only if
// 				 * BPF_F_NUMA_NODE is set).
// 				 */
// 	char	map_name[BPF_OBJ_NAME_LEN];
// 	__u32	map_ifindex;	/* ifindex of netdev to create on */
// 	__u32	btf_fd;		/* fd pointing to a BTF type data */
// 	__u32	btf_key_type_id;	/* BTF type_id of the key */
// 	__u32	btf_value_type_id;	/* BTF type_id of the value */
// 	__u32	btf_vmlinux_value_type_id;/* BTF type_id of a kernel-
// 					   * struct stored as the
// 					   * map value
// 					   */
// };

// struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
// 	__u32		map_fd;
// 	__aligned_u64	key;
// 	union {
// 		__aligned_u64 value;
// 		__aligned_u64 next_key;
// 	};
// 	__u64		flags;
// };
type AttributeMapElementOp struct {
	FileDescriptor int
	Key            interface{}
	Value          interface{}
	internal       struct {
		mapFd uint32
		pad0  [4]byte
		key   uint64
		value uint64 // union: value or next_key
		flags uint64
	}
}

func (a *AttributeMapElementOp) fill() error {
	if a.FileDescriptor <= 0 {
		return errors.New("missing file descriptor")
	}
	a.internal.mapFd = uint32(a.FileDescriptor)
	if a.Key == nil {
		return errors.New("missing key")
	}
	a.internal.key = uint64(reflect.ValueOf(a.Key).Pointer())
	if a.Value == nil {
		return errors.New("missing value")
	}
	a.internal.value = uint64(reflect.ValueOf(a.Value).Pointer())
	return nil
}

func (a *AttributeMapElementOp) Pointer() (uintptr, error) {
	if err := a.fill(); err != nil {
		return 0, err
	}
	return uintptr(unsafe.Pointer(&a.internal)), nil
}
func (a *AttributeMapElementOp) Size() uintptr {
	return unsafe.Sizeof(a.internal)
}

// struct { /* struct used by BPF_MAP_*_BATCH commands */
// 	__aligned_u64	in_batch;	/* start batch,
// 					 * NULL to start from beginning
// 					 */
// 	__aligned_u64	out_batch;	/* output: next start batch */
// 	__aligned_u64	keys;
// 	__aligned_u64	values;
// 	__u32		count;		/* input/output:
// 					 * input: # of key/value
// 					 * elements
// 					 * output: # of filled elements
// 					 */
// 	__u32		map_fd;
// 	__u64		elem_flags;
// 	__u64		flags;
// } batch;

// struct { /* anonymous struct used by BPF_PROG_LOAD command */
// 	__u32		prog_type;	/* one of enum bpf_prog_type */
// 	__u32		insn_cnt;
// 	__aligned_u64	insns;
// 	__aligned_u64	license;
// 	__u32		log_level;	/* verbosity level of verifier */
// 	__u32		log_size;	/* size of user buffer */
// 	__aligned_u64	log_buf;	/* user supplied buffer */
// 	__u32		kern_version;	/* not used */
// 	__u32		prog_flags;
// 	char		prog_name[BPF_OBJ_NAME_LEN];
// 	__u32		prog_ifindex;	/* ifindex of netdev to prep for */
// 	/* For some prog types expected attach type must be known at
// 	 * load time to verify attach type specific parts of prog
// 	 * (context accesses, allowed helpers, etc).
// 	 */
// 	__u32		expected_attach_type;
// 	__u32		prog_btf_fd;	/* fd pointing to BTF type data */
// 	__u32		func_info_rec_size;	/* userspace bpf_func_info size */
// 	__aligned_u64	func_info;	/* func info */
// 	__u32		func_info_cnt;	/* number of bpf_func_info records */
// 	__u32		line_info_rec_size;	/* userspace bpf_line_info size */
// 	__aligned_u64	line_info;	/* line info */
// 	__u32		line_info_cnt;	/* number of bpf_line_info records */
// 	__u32		attach_btf_id;	/* in-kernel BTF type id to attach to */
// 	__u32		attach_prog_fd; /* 0 to attach to vmlinux */
// };

// struct { /* anonymous struct used by BPF_OBJ_* commands */
// 	__aligned_u64	pathname;
// 	__u32		bpf_fd;
// 	__u32		file_flags;
// };
type AttributeObjOp struct {
	PathName       string
	FileDescriptor int
	internal       struct {
		pathname uint64
		fd       uint32
		pad0     [4]byte
	}
}

func (a *AttributeObjOp) fill() error {
	if a.PathName != "" {
		pathStr, err := unix.BytePtrFromString(a.PathName)
		if err != nil {
			return err
		}
		a.internal.pathname = uint64(uintptr(unsafe.Pointer(pathStr)))
	}
	if a.FileDescriptor > 0 {
		a.internal.fd = uint32(a.FileDescriptor)
	}
	return nil
}

func (a *AttributeObjOp) Pointer() (uintptr, error) {
	if err := a.fill(); err != nil {
		return 0, err
	}
	return uintptr(unsafe.Pointer(&a.internal)), nil
}
func (a *AttributeObjOp) Size() uintptr {
	return unsafe.Sizeof(a.internal)
}

// struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
// 	__u32		target_fd;	/* container object to attach to */
// 	__u32		attach_bpf_fd;	/* eBPF program to attach */
// 	__u32		attach_type;
// 	__u32		attach_flags;
// 	__u32		replace_bpf_fd;	/* previously attached eBPF
// 					 * program to replace if
// 					 * BPF_F_REPLACE is used
// 					 */
// };

// struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
// 	__u32		prog_fd;
// 	__u32		retval;
// 	__u32		data_size_in;	/* input: len of data_in */
// 	__u32		data_size_out;	/* input/output: len of data_out
// 					 *   returns ENOSPC if data_out
// 					 *   is too small.
// 					 */
// 	__aligned_u64	data_in;
// 	__aligned_u64	data_out;
// 	__u32		repeat;
// 	__u32		duration;
// 	__u32		ctx_size_in;	/* input: len of ctx_in */
// 	__u32		ctx_size_out;	/* input/output: len of ctx_out
// 					 *   returns ENOSPC if ctx_out
// 					 *   is too small.
// 					 */
// 	__aligned_u64	ctx_in;
// 	__aligned_u64	ctx_out;
// 	__u32		flags;
// 	__u32		cpu;
// } test;

// struct { /* anonymous struct used by BPF_*_GET_*_ID */
// 	union {
// 		__u32		start_id;
// 		__u32		prog_id;
// 		__u32		map_id;
// 		__u32		btf_id;
// 		__u32		link_id;
// 	};
// 	__u32		next_id;
// 	__u32		open_flags;
// };

// struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
// 	__u32		bpf_fd;
// 	__u32		info_len;
// 	__aligned_u64	info;
// } info;

// struct { /* anonymous struct used by BPF_PROG_QUERY command */
// 	__u32		target_fd;	/* container object to query */
// 	__u32		attach_type;
// 	__u32		query_flags;
// 	__u32		attach_flags;
// 	__aligned_u64	prog_ids;
// 	__u32		prog_cnt;
// } query;

// struct { /* anonymous struct used by BPF_RAW_TRACEPOINT_OPEN command */
// 	__u64 name;
// 	__u32 prog_fd;
// } raw_tracepoint;

// struct { /* anonymous struct for BPF_BTF_LOAD */
// 	__aligned_u64	btf;
// 	__aligned_u64	btf_log_buf;
// 	__u32		btf_size;
// 	__u32		btf_log_size;
// 	__u32		btf_log_level;
// };

// struct {
// 	__u32		pid;		/* input: pid */
// 	__u32		fd;		/* input: fd */
// 	__u32		flags;		/* input: flags */
// 	__u32		buf_len;	/* input/output: buf len */
// 	__aligned_u64	buf;		/* input/output:
// 					 *   tp_name for tracepoint
// 					 *   symbol for kprobe
// 					 *   filename for uprobe
// 					 */
// 	__u32		prog_id;	/* output: prod_id */
// 	__u32		fd_type;	/* output: BPF_FD_TYPE_* */
// 	__u64		probe_offset;	/* output: probe_offset */
// 	__u64		probe_addr;	/* output: probe_addr */
// } task_fd_query;

// struct { /* struct used by BPF_LINK_CREATE command */
// 	__u32		prog_fd;	/* eBPF program to attach */
// 	union {
// 		__u32		target_fd;	/* object to attach to */
// 		__u32		target_ifindex; /* target ifindex */
// 	};
// 	__u32		attach_type;	/* attach type */
// 	__u32		flags;		/* extra flags */
// 	union {
// 		__u32		target_btf_id;	/* btf_id of target to attach to */
// 		struct {
// 			__aligned_u64	iter_info;	/* extra bpf_iter_link_info */
// 			__u32		iter_info_len;	/* iter_info length */
// 		};
// 	};
// } link_create;

// struct { /* struct used by BPF_LINK_UPDATE command */
// 	__u32		link_fd;	/* link fd */
// 	/* new program fd to update link with */
// 	__u32		new_prog_fd;
// 	__u32		flags;		/* extra flags */
// 	/* expected link's program fd; is specified only if
// 	 * BPF_F_REPLACE flag is set in flags */
// 	__u32		old_prog_fd;
// } link_update;

// struct {
// 	__u32		link_fd;
// } link_detach;

// struct { /* struct used by BPF_ENABLE_STATS command */
// 	__u32		type;
// } enable_stats;

// struct { /* struct used by BPF_ITER_CREATE command */
// 	__u32		link_fd;
// 	__u32		flags;
// } iter_create;

// struct { /* struct used by BPF_PROG_BIND_MAP command */
// 	__u32		prog_fd;
// 	__u32		map_fd;
// 	__u32		flags;		/* extra flags */
// } prog_bind_map;
