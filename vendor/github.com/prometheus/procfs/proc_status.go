package procfs

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

// signalNames is a mapping of signal numbers to names. Note that is is based
// on the glibc definitions where SIGRTMIN = 34.
//
// Generated with:  kill -l | tr "\t" "\n" | sed 's/) /: "/g' | sed 's/$/",/g'
var signalNames = map[int]string{
	1:  "SIGHUP",
	2:  "SIGINT",
	3:  "SIGQUIT",
	4:  "SIGILL",
	5:  "SIGTRAP",
	6:  "SIGABRT",
	7:  "SIGBUS",
	8:  "SIGFPE",
	9:  "SIGKILL",
	10: "SIGUSR1",
	11: "SIGSEGV",
	12: "SIGUSR2",
	13: "SIGPIPE",
	14: "SIGALRM",
	15: "SIGTERM",
	16: "SIGSTKFLT",
	17: "SIGCHLD",
	18: "SIGCONT",
	19: "SIGSTOP",
	20: "SIGTSTP",
	21: "SIGTTIN",
	22: "SIGTTOU",
	23: "SIGURG",
	24: "SIGXCPU",
	25: "SIGXFSZ",
	26: "SIGVTALRM",
	27: "SIGPROF",
	28: "SIGWINCH",
	29: "SIGIO",
	30: "SIGPWR",
	31: "SIGSYS",
	32: "SIGRTMIN-2",
	33: "SIGRTMIN-1",
	34: "SIGRTMIN",
	35: "SIGRTMIN+1",
	36: "SIGRTMIN+2",
	37: "SIGRTMIN+3",
	38: "SIGRTMIN+4",
	39: "SIGRTMIN+5",
	40: "SIGRTMIN+6",
	41: "SIGRTMIN+7",
	42: "SIGRTMIN+8",
	43: "SIGRTMIN+9",
	44: "SIGRTMIN+10",
	45: "SIGRTMIN+11",
	46: "SIGRTMIN+12",
	47: "SIGRTMIN+13",
	48: "SIGRTMIN+14",
	49: "SIGRTMIN+15",
	50: "SIGRTMAX-14",
	51: "SIGRTMAX-13",
	52: "SIGRTMAX-12",
	53: "SIGRTMAX-11",
	54: "SIGRTMAX-10",
	55: "SIGRTMAX-9",
	56: "SIGRTMAX-8",
	57: "SIGRTMAX-7",
	58: "SIGRTMAX-6",
	59: "SIGRTMAX-5",
	60: "SIGRTMAX-4",
	61: "SIGRTMAX-3",
	62: "SIGRTMAX-2",
	63: "SIGRTMAX-1",
	64: "SIGRTMAX",
}

// capabilityNames is mapping of capability constant values to names.
//
// Generated with:
//   curl -s https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/capability.h | \
//   grep -P '^#define CAP_\w+\s+\d+' | perl -pe 's/#define (\w+)\s+(\d+)/\2: "\1",/g'
var capabilityNames = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
}

// ProcStatus provides status information about the process read from
// /proc/[pid]/status. There is some overlap with the data from
// /proc/[pid]/stat and /proc/[pid]/statm but there is some additional data.
type ProcStatus struct {
	// Filename of the executable.
	Name string
	// Process umask.
	Umask os.FileMode
	// Current state of the process.  One of "R (running)", "S (sleeping)",
	// "D (disk sleep)", "T (stopped)", "T (tracing stop)", "Z (zombie)",  or
	// "X (dead)".
	State string
	// Thread group ID.
	TGID uint32
	// NUMA group ID (0 if none; since Linux 3.13).
	NGID uint32
	// Process ID.
	PID uint32
	// Process ID of the parent process.
	PPID uint32
	// PID of process tracing this process (0 if not being traced).
	TracerPID uint32
	// Real UID.
	UID uint32
	// Real GID.
	GID uint32
	// Number of file descriptor slots currently allocated.
	FDSize uint64
	// Supplementary group ID list.
	Groups []uint32
	// Thread group ID (i.e., PID) in each of the PID namespaces of which [pid]
	// is a member.  The leftmost entry shows the value with respect to the PID
	// namespace of the reading process, followed by the value in successively
	// nested inner namespaces.  (Since Linux 4.1.)
	NamespaceTGID []uint32
	// Thread ID in each of the PID namespaces of which [pid] is a member.
	// The fields are ordered as for NStgid. (Since Linux 4.1.)
	NamespacePID []uint32
	// Process group ID in each of the PID namespaces of which [pid] is a
	// member.  The fields are ordered as for NStgid.  (Since Linux 4.1.)
	NamespacePGID []uint32
	// Session ID hierarchy in each of the PID namespaces of which [pid] is a
	// member. The fields are ordered as for NStgid.  (Since Linux 4.1.)
	NamespaceSID []uint32
	// Peak virtual memory size in bytes.
	VirtualMemPeakSize uint64
	// Virtual memory size in bytes.
	VirtualMemSize uint64
	// Locked memory size in bytes (see mlock(3)).
	VirtualMemLockedSize uint64
	// Pinned memory size in bytes (since Linux 3.2).  These are pages that can't be
	// moved because something needs to directly access physical memory.
	VirtualMemPinnedSize uint64
	// Peak resident set size in bytes ("high water mark").
	VirtualMemHighWaterMarkSize uint64
	// Resident set size in bytes.  Note that the value here is the sum of RSSAnonSize,
	// RSSFileSize, and RSSShmemSize.
	VirtualMemRSSSize uint64
	// Size in bytes of resident anonymous memory.  (since Linux 4.5).
	RSSAnonSize uint64
	// Size in bytes of resident file mappings.  (since Linux 4.5).
	RSSFileSize uint64
	// Size in bytes of resident shared memory (includes System V shared memory,
	// mappings from tmpfs(5), and shared anonymous mappings).  (since Linux 4.5).
	RSSShmemSize uint64
	// Size in bytes of the data segment.
	VirtualMemDataSize uint64
	// Size in bytes of the stack segment.
	VirtualMemStackSize uint64
	// Size in bytes of the text segment.
	VirtualMemExeSize uint64
	// Shared library code size in bytes.
	VirtualMemLibSize uint64
	// Page table entries size in bytes (since Linux 2.6.10).
	VirtualMemPageTableEntriesSize uint64
	// Size in bytes of second-level page tables (since Linux 4.0).
	VirtualMemPMDSize uint64
	// Swapped-out virtual memory size in bytes by anonymous private pages;
	// shmem swap usage is not included (since Linux 2.6.34).
	VirtualMemSwapSize uint64
	// Size in bytes of hugetlb memory portions.  (since Linux 4.4).
	HugetlbPagesSize uint64
	// Number of threads in process containing this thread.
	Threads uint64
	// Number of currently queued signals for this real user ID.
	SignalsQueued uint64
	// Resource limit on the number of queued signals for this process (see
	// the description of RLIMIT_SIGPENDING in getrlimit(2)).
	MaxSignalsQueued uint64
	// Pending signals for the thread.
	SignalsPending []string
	// Shared pending signals for the process.
	SignalsSharedPending []string
	// Blocked signals.
	SignalsBlocked []string
	// Ignored signals.
	SignalsIgnored []string
	// Caught signals.
	SignalsCaught []string
	// Inheritable capabilities.
	CapabilitiesInheritable []string
	// Permitted capabilities.
	CapabilitiesPermitted []string
	// Effective capabilities.
	CapabilitiesEffective []string
	// Capability bounding set (since Linux 2.6.26).
	CapabilitiesBounding []string
	// Ambient capability set (since Linux 4.3).
	CapabilitiesAmbient []string
	// Value of the no_new_privs bit (since Linux 4.10).
	NoNewPrivs uint64
	// Seccomp mode of the process (since Linux 3.8). This field is provided
	// only if the kernel was built with the CONFIG_SECCOMP kernel configuration
	// option enabled.
	// 0 means SECCOMP_MODE_DISABLED
	// 1 means SECCOMP_MODE_STRICT
	// 2 means SECCOMP_MODE_FILTER
	Seccomp uint32
	// Same as previous, but in "list format"
	CPUsAllowedList string
	// Same as previous, but in "list format"
	MemsAllowedList string
	// Number of voluntary context switches (since Linux 2.6.23).
	VoluntaryContextSwitches uint64
	// Number of non-voluntary context switches (since Linux 2.6.23).
	NonVoluntaryContextSwitches uint64

	fs FS
}

// NewStatus returns the current status information of the process.
// See https://www.kernel.org/doc/Documentation/filesystems/proc.txt.
func (p Proc) NewStatus() (ProcStatus, error) {
	f, err := os.Open(p.path("status"))
	if err != nil {
		return ProcStatus{}, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return ProcStatus{}, err
	}

	fields := make(map[string]string, 60)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := bytes.SplitN(sc.Bytes(), []byte(":"), 2)
		if len(parts) != 2 {
			return ProcStatus{}, fmt.Errorf("unexpected line format for '%v'", sc.Text())
		}

		key := string(parts[0])
		value := string(bytes.TrimSpace(parts[1]))
		fields[key] = value
	}

	return newProcStatus(fields)
}

func newProcStatus(data map[string]string) (ProcStatus, error) {
	var s ProcStatus
	for k, v := range data {
		var err error

		// Cases generated using https://play.golang.org/p/4zfmlF-p8-
		switch k {
		case "Name":
			s.Name = v
		case "Umask":
			umask, err := parseUint32(v)
			if err != nil {
				break
			}
			s.Umask = os.FileMode(umask)
		case "State":
			s.State = v
		case "Tgid":
			s.TGID, err = parseUint32(v)
		case "Ngid":
			s.NGID, err = parseUint32(v)
		case "Pid":
			s.PID, err = parseUint32(v)
		case "PPid":
			s.PPID, err = parseUint32(v)
		case "TracerPid":
			s.TracerPID, err = parseUint32(v)
		case "Uid":
			ids := strings.Fields(v)
			s.UID, err = parseUint32(ids[0])
		case "Gid":
			ids := strings.Fields(v)
			s.GID, err = parseUint32(ids[0])
		case "FDSize":
			s.FDSize, err = parseUint64(v)
		case "Groups":
			s.Groups, err = parseUint32List(v)
		case "NStgid":
			s.NamespaceTGID, err = parseUint32List(v)
		case "NSpid":
			s.NamespacePID, err = parseUint32List(v)
		case "NSpgid":
			s.NamespacePGID, err = parseUint32List(v)
		case "NSsid":
			s.NamespaceSID, err = parseUint32List(v)
		case "VmPeak":
			s.VirtualMemPeakSize, err = parseKilobytes(v)
		case "VmSize":
			s.VirtualMemSize, err = parseKilobytes(v)
		case "VmLck":
			s.VirtualMemLockedSize, err = parseKilobytes(v)
		case "VmPin":
			s.VirtualMemPinnedSize, err = parseKilobytes(v)
		case "VmHWM":
			s.VirtualMemHighWaterMarkSize, err = parseKilobytes(v)
		case "VmRSS":
			s.VirtualMemRSSSize, err = parseKilobytes(v)
		case "RssAnon":
			s.RSSAnonSize, err = parseKilobytes(v)
		case "RssFile":
			s.RSSFileSize, err = parseKilobytes(v)
		case "RssShmem":
			s.RSSShmemSize, err = parseKilobytes(v)
		case "VmData":
			s.VirtualMemDataSize, err = parseKilobytes(v)
		case "VmStk":
			s.VirtualMemStackSize, err = parseKilobytes(v)
		case "VmExe":
			s.VirtualMemExeSize, err = parseKilobytes(v)
		case "VmLib":
			s.VirtualMemLibSize, err = parseKilobytes(v)
		case "VmPTE":
			s.VirtualMemPageTableEntriesSize, err = parseKilobytes(v)
		case "VmPMD":
			s.VirtualMemPMDSize, err = parseKilobytes(v)
		case "VmSwap":
			s.VirtualMemSwapSize, err = parseKilobytes(v)
		case "HugetlbPages":
			s.HugetlbPagesSize, err = parseKilobytes(v)
		case "Threads":
			s.Threads, err = parseUint64(v)
		case "SigQ":
			parts := strings.SplitN(v, "/", 2)
			if len(parts) != 2 {
				err = errors.New("unexpected value")
				break
			}
			s.SignalsQueued, err = parseUint64(parts[0])
			if err != nil {
				break
			}
			s.MaxSignalsQueued, err = parseUint64(parts[1])
		case "SigPnd":
			s.SignalsPending, err = decodeBitMap(v, signalName)
		case "ShdPnd":
			s.SignalsSharedPending, err = decodeBitMap(v, signalName)
		case "SigBlk":
			s.SignalsBlocked, err = decodeBitMap(v, signalName)
		case "SigIgn":
			s.SignalsIgnored, err = decodeBitMap(v, signalName)
		case "SigCgt":
			s.SignalsCaught, err = decodeBitMap(v, signalName)
		case "CapInh":
			s.CapabilitiesInheritable, err = decodeBitMap(v, capabilityName)
		case "CapPrm":
			s.CapabilitiesPermitted, err = decodeBitMap(v, capabilityName)
		case "CapEff":
			s.CapabilitiesEffective, err = decodeBitMap(v, capabilityName)
		case "CapBnd":
			s.CapabilitiesBounding, err = decodeBitMap(v, capabilityName)
		case "CapAmb":
			s.CapabilitiesAmbient, err = decodeBitMap(v, capabilityName)
		case "NoNewPrivs":
			s.NoNewPrivs, err = parseUint64(v)
		case "Seccomp":
			s.Seccomp, err = parseUint32(v)
		case "Cpus_allowed_list":
			s.CPUsAllowedList = v
		case "Mems_allowed_list":
			s.MemsAllowedList = v
		case "voluntary_ctxt_switches":
			s.VoluntaryContextSwitches, err = parseUint64(v)
		case "nonvoluntary_ctxt_switches":
			s.NonVoluntaryContextSwitches, err = parseUint64(v)
		}

		if err != nil {
			return ProcStatus{}, fmt.Errorf("failed to parse %v value '%v': %v", k, v, err)
		}
	}

	return s, nil
}

func parseUint32List(s string) ([]uint32, error) {
	var values []uint32
	numbers := strings.Fields(s)
	for _, num := range numbers {
		v, err := parseUint32(num)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

func parseUint32(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err
}

func parseUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

func parseHexUint64(s string) (uint64, error) {
	return strconv.ParseUint(s, 16, 64)
}

func parseKilobytes(s string) (uint64, error) {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0, fmt.Errorf("unexpected value '%v'", s)
	}

	sizeKb, err := parseUint64(parts[0])
	if err != nil {
		return 0, err
	}

	return sizeKb * 1024, nil
}

func decodeBitMap(s string, lookupName func(int) string) ([]string, error) {
	mask, err := parseHexUint64(s)
	if err != nil {
		return nil, err
	}

	var names []string
	for i := 0; i < 64; i++ {
		bit := mask & (1 << uint(i))
		if bit > 0 {
			names = append(names, lookupName(i))
		}
	}

	return names, nil
}

func signalName(num int) string {
	signalNumber := num + 1

	name, found := signalNames[signalNumber]
	if found {
		return name
	}

	return strconv.Itoa(signalNumber)
}

func capabilityName(num int) string {
	name, found := capabilityNames[num]
	if found {
		return name
	}

	return strconv.Itoa(num)
}
