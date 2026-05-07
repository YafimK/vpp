package overlayclient

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	interface_types "github.com/yafimk/vpp-overlay/dev/go-overlay/interface_types"
	ip_types "github.com/yafimk/vpp-overlay/dev/go-overlay/ip_types"
	overlayapi "github.com/yafimk/vpp-overlay/dev/go-overlay/overlay"
)

const (
	defaultAPISock = "/run/vpp/api.sock"
	defaultCLISock = "/tmp/vpp.sock"
)

func apiSock() string {
	if v := os.Getenv("VPP_API_SOCK"); v != "" {
		return v
	}
	return defaultAPISock
}

func cliSock() string {
	if v := os.Getenv("VPP_CLI_SOCK"); v != "" {
		return v
	}
	return defaultCLISock
}

func vppctl(t *testing.T, args ...string) string {
	t.Helper()
	cmd := append([]string{"-s", cliSock()}, args...)
	out, err := exec.Command("vppctl", cmd...).CombinedOutput()
	if err != nil {
		t.Fatalf("vppctl %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// createLoopback creates a fresh loopback and returns its sw_if_index.
func createLoopback(t *testing.T) uint32 {
	t.Helper()
	pre := listLoopbacks(t)
	vppctl(t, "create", "loopback", "interface")
	post := listLoopbacks(t)
	for name, idx := range post {
		if _, ok := pre[name]; !ok {
			t.Cleanup(func() {
				vppctl(t, "delete", "loopback", "interface", "intfc", name)
			})
			return idx
		}
	}
	t.Fatal("could not find newly created loopback")
	return 0
}

// listLoopbacks returns map name -> sw_if_index for all loopback interfaces.
func listLoopbacks(t *testing.T) map[string]uint32 {
	t.Helper()
	out := vppctl(t, "show", "interface")
	res := map[string]uint32{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "loop") {
			continue
		}
		idx, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		res[fields[0]] = uint32(idx)
	}
	return res
}

func resetState(t *testing.T) {
	t.Helper()
	c, err := New(apiSock())
	if err != nil {
		t.Fatalf("connect %q: %v", apiSock(), err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	all, err := c.DumpAll(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	for _, st := range all {
		for _, ifx := range st.ArmedInterfaces {
			_ = c.Disarm(ctx, ifx)
		}
	}
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	sock := apiSock()
	c, err := New(sock)
	if err != nil {
		t.Fatalf("connect %q: %v", sock, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

var (
	src      = net.ParseIP("fd00:cafe::1")
	prefix   = net.ParseIP("fd00:cafe::")
	prefix2  = net.ParseIP("fd00:beef::")
	prefLen  = uint8(48)
	dstPort  = uint16(6635)
)

func TestArmCreatesTunnel(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: swIdx,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix,
		SrcPrefixLen:   prefLen,
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}

	st, err := c.Dump(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if !st.Configured {
		t.Fatal("expected tunnel to be configured after arm")
	}
	if st.DstPort != dstPort {
		t.Errorf("dst_port: got %d want %d", st.DstPort, dstPort)
	}
	if st.SrcPrefixLen != prefLen {
		t.Errorf("prefix_len: got %d want %d", st.SrcPrefixLen, prefLen)
	}
	if len(st.ArmedInterfaces) != 1 || st.ArmedInterfaces[0] != swIdx {
		t.Errorf("armed_ifs: got %v want [%d]", st.ArmedInterfaces, swIdx)
	}

	// cleanup
	if err := c.Disarm(ctx, swIdx); err != nil {
		t.Fatalf("disarm: %v", err)
	}
}

func TestArmIdempotent(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	p := ArmParams{
		IfaceSwIfIndex: swIdx,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix,
		SrcPrefixLen:   prefLen,
	}
	if err := c.Arm(ctx, p); err != nil {
		t.Fatalf("arm 1: %v", err)
	}
	if err := c.Arm(ctx, p); err != nil {
		t.Fatalf("arm 2 (should be idempotent): %v", err)
	}
	st, _ := c.Dump(ctx)
	if len(st.ArmedInterfaces) != 1 {
		t.Errorf("expected exactly 1 armed iface, got %v", st.ArmedInterfaces)
	}
	_ = c.Disarm(ctx, swIdx)
}

// Slice B: arming two NICs with different src_prefix on the same dst_port
// is now supported (tenant separation). DumpAll must return two tunnels.
func TestArmDifferentSrcPrefixCreatesSecondTunnel(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	a := createLoopback(t)
	b := createLoopback(t)
	ctx := context.Background()

	if err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: a,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix,
		SrcPrefixLen:   prefLen,
	}); err != nil {
		t.Fatalf("arm a: %v", err)
	}
	if err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: b,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix2,
		SrcPrefixLen:   prefLen,
	}); err != nil {
		t.Fatalf("arm b (different src_prefix, same port): %v", err)
	}

	all, err := c.DumpAll(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 tunnels, got %d: %+v", len(all), all)
	}
	_ = c.Disarm(ctx, a)
	_ = c.Disarm(ctx, b)
}

// Different dst_port on the same VPP instance is rejected — there is one
// UDP port per VPP. Maps to ErrPortConflict.
func TestArmPortConflict(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	a := createLoopback(t)
	b := createLoopback(t)
	ctx := context.Background()

	if err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: a,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix,
		SrcPrefixLen:   prefLen,
	}); err != nil {
		t.Fatalf("arm a: %v", err)
	}
	err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: b,
		Src:            src,
		DstPort:        dstPort + 1,
		SrcPrefix:      prefix2,
		SrcPrefixLen:   prefLen,
	})
	if !errors.Is(err, ErrPortConflict) {
		t.Errorf("expected ErrPortConflict, got %v", err)
	}
	_ = c.Disarm(ctx, a)
}

// TestArmRejectsIPv4Src bypasses the client-side IPv6 check by calling the
// RPC directly with an IPv4 vl_api_address_t. The plugin must reject this
// with INVALID_ARGUMENT (mapped to ErrInvalidArgument).
func TestArmRejectsIPv4Src(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	v4 := ip_types.NewAddress(net.ParseIP("10.0.0.1"))
	pfx := ip_types.NewIP6Address(net.ParseIP("fd00:cafe::"))
	_, err := c.rpc.OverlayArmV1(ctx, &overlayapi.OverlayArmV1{
		IfaceSwIfIndex: interface_types.InterfaceIndex(swIdx),
		Enable:         true,
		Src:            v4,
		DstPort:        dstPort,
		SrcPrefix:      pfx,
		SrcPrefixLen:   prefLen,
	})
	if err == nil {
		t.Fatal("expected error for IPv4 src, got nil")
		_ = c.Disarm(ctx, swIdx)
	}
	if !errors.Is(mapErr(err), ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestDisarmLastNICDestroysTunnel(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	if err := c.Arm(ctx, ArmParams{
		IfaceSwIfIndex: swIdx,
		Src:            src,
		DstPort:        dstPort,
		SrcPrefix:      prefix,
		SrcPrefixLen:   prefLen,
	}); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if err := c.Disarm(ctx, swIdx); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	st, err := c.Dump(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if st.Configured {
		t.Errorf("expected no tunnel after last disarm, got %+v", st)
	}
}
