package bpf

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Command int

const (
	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	MAP_CREATE          = Command(0)
	MAP_LOOKUP_ELEM     = Command(1)
	MAP_UPDATE_ELEM     = Command(2)
	MAP_DELETE_ELEM     = Command(3)
	MAP_GET_NEXT_KEY    = Command(4)
	PROG_LOAD           = Command(5)
	OBJ_PIN             = Command(6)
	OBJ_GET             = Command(7)
	PROG_ATTACH         = Command(8)
	PROG_DETACH         = Command(9)
	PROG_TEST_RUN       = Command(10)
	PROG_GET_NEXT_ID    = Command(11)
	MAP_GET_NEXT_ID     = Command(12)
	PROG_GET_FD_BY_ID   = Command(13)
	MAP_GET_FD_BY_ID    = Command(14)
	OBJ_GET_INFO_BY_FD  = Command(15)
	PROG_QUERY          = Command(16)
	RAW_TRACEPOINT_OPEN = Command(17)
	BTF_LOAD            = Command(18)
	BTF_GET_FD_BY_ID    = Command(19)
	TASK_FD_QUERY       = Command(20)

	// BPF syscall attach types
	BPF_CGROUP_INET_INGRESS      = 0
	BPF_CGROUP_INET_EGRESS       = 1
	BPF_CGROUP_INET_SOCK_CREATE  = 2
	BPF_CGROUP_SOCK_OPS          = 3
	BPF_SK_SKB_STREAM_PARSER     = 4
	BPF_SK_SKB_STREAM_VERDICT    = 5
	BPF_CGROUP_DEVICE            = 6
	BPF_SK_MSG_VERDICT           = 7
	BPF_CGROUP_INET4_BIND        = 8
	BPF_CGROUP_INET6_BIND        = 9
	BPF_CGROUP_INET4_CONNECT     = 10
	BPF_CGROUP_INET6_CONNECT     = 11
	BPF_CGROUP_INET4_POST_BIND   = 12
	BPF_CGROUP_INET6_POST_BIND   = 13
	BPF_CGROUP_UDP4_SENDMSG      = 14
	BPF_CGROUP_UDP6_SENDMSG      = 15
	BPF_LIRC_MODE2               = 16
	BPF_FLOW_DISSECTOR           = 17
	BPF_CGROUP_SYSCTL            = 18
	BPF_CGROUP_UDP4_RECVMSG      = 19
	BPF_CGROUP_UDP6_RECVMSG      = 20
	BPF_CGROUP_INET4_GETPEERNAME = 29
	BPF_CGROUP_INET6_GETPEERNAME = 30
	BPF_CGROUP_INET4_GETSOCKNAME = 31
	BPF_CGROUP_INET6_GETSOCKNAME = 32

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2

	// Flags for BPF_PROG_QUERY
	BPF_F_QUERY_EFFECTVE = 1 << 0

	// Flags for accessing BPF object
	BPF_F_RDONLY = 1 << 3
	BPF_F_WRONLY = 1 << 4

	// Flag for stack_map, store build_id+offset instead of pointer
	BPF_F_STACK_BUILD_ID = 1 << 5
)

const (
	BPF_MAP_LOOKUP_ELEM = 1
	BPF_OBJ_GET         = 7
)

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_OBJ_*_ commands
type bpfAttrObjOp struct {
	pathname uint64
	fd       uint32
	pad0     [4]byte
}

type attribute interface {
	Pointer() (uintptr, error)
	Size() uintptr
}

/*
static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}
*/
func sysBPF(command Command, attr attribute) (int, error) {
	ptr, err := attr.Pointer()
	if err != nil {
		return 0, fmt.Errorf("invalid syscall attributes %w", err)
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(command), ptr, attr.Size())
	if errno != 0 {
		err := unix.ErrnoName(errno)
		return 0, fmt.Errorf("syscall failed %s", err)
	}
	return int(fd), nil
}

/*
int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.pathname = ptr_to_u64((void *)pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}
*/

// ObjGet reads the pathname and returns the map's fd read.
func ObjGet(pathname string) (int, error) {
	// pathStr, err := unix.BytePtrFromString(pathname)
	// if err != nil {
	// 	return 0, fmt.Errorf("Unable to convert pathname %q to byte pointer: %w", pathname, err)
	// }
	// uba := bpfAttrObjOp{
	// 	pathname: uint64(uintptr(unsafe.Pointer(pathStr))),
	// }
	// fd, _, errno := unix.Syscall(
	// 	unix.SYS_BPF,
	// 	BPF_OBJ_GET,
	// 	uintptr(unsafe.Pointer(&uba)),
	// 	unsafe.Sizeof(uba),
	// )
	// runtime.KeepAlive(pathStr)
	// runtime.KeepAlive(&uba)

	// if fd == 0 || errno != 0 {
	// 	return 0, &os.PathError{
	// 		Op:   "Unable to get object",
	// 		Err:  errno,
	// 		Path: pathname,
	// 	}
	// }

	// return int(fd), nil
	attr := AttributeObjOp{
		PathName: pathname,
	}
	return sysBPF(OBJ_GET, &attr)
}

// This struct must be in sync with union bpf_attr's anonymous struct used by
// BPF_MAP_*_ELEM commands
type bpfAttrMapOpElem struct {
	mapFd uint32
	pad0  [4]byte
	key   uint64
	value uint64 // union: value or next_key
	flags uint64
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
// Deprecated, use LookupElementFromPointers
// func LookupElement(fd int, key, value unsafe.Pointer) error {
// 	uba := bpfAttrMapOpElem{
// 		mapFd: uint32(fd),
// 		key:   uint64(uintptr(key)),
// 		value: uint64(uintptr(value)),
// 	}

// 	ret := LookupElementFromPointers(fd, unsafe.Pointer(&uba), unsafe.Sizeof(uba))
// 	runtime.KeepAlive(key)
// 	runtime.KeepAlive(value)
// 	return ret
// }

func LookupElement(fd int, key, value interface{}) (err error) {
	attr := AttributeMapElementOp{
		FileDescriptor: fd,
		Key:            key,
		Value:          value,
	}
	_, err = sysBPF(MAP_LOOKUP_ELEM, &attr)
	return
}

// LookupElement looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElementFromPointers(fd int, structPtr unsafe.Pointer, sizeOfStruct uintptr) error {
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_LOOKUP_ELEM,
		uintptr(structPtr),
		sizeOfStruct,
	)
	runtime.KeepAlive(structPtr)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element in map with file descriptor %d: %s", fd, err)
	}

	return nil
}
