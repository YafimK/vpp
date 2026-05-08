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
	nics, err := c.DumpNICs(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	for _, n := range nics {
		_ = c.Disable(ctx, n.SwIfIndex, true)
	}
}

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(apiSock())
	if err != nil {
		t.Fatalf("connect %q: %v", apiSock(), err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

var (
	prefix  = net.ParseIP("fd00:cafe::")
	prefix2 = net.ParseIP("fd00:beef::")
	prefLen = uint8(48)
	dstPort = uint16(6635)
)

func TestEnableCreatesEntry(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Enable(ctx, swIdx, dstPort); err != nil {
		t.Fatalf("enable: %v", err)
	}

	nics, err := c.DumpNICs(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if len(nics) != 1 {
		t.Fatalf("expected 1 enabled NIC, got %d: %+v", len(nics), nics)
	}
	if nics[0].SwIfIndex != swIdx {
		t.Errorf("sw_if_index: got %d want %d", nics[0].SwIfIndex, swIdx)
	}
	if nics[0].DstPort != dstPort {
		t.Errorf("dst_port: got %d want %d", nics[0].DstPort, dstPort)
	}
	if nics[0].NMatchers != 0 {
		t.Errorf("n_matchers: got %d want 0", nics[0].NMatchers)
	}

	if err := c.Disable(ctx, swIdx, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
}

func TestEnableIdempotent(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	if err := c.Enable(ctx, swIdx, dstPort); err != nil {
		t.Fatalf("enable 1: %v", err)
	}
	if err := c.Enable(ctx, swIdx, dstPort); err != nil {
		t.Fatalf("enable 2 (should be idempotent): %v", err)
	}
	nics, _ := c.DumpNICs(ctx)
	if len(nics) != 1 {
		t.Errorf("expected exactly 1 enabled NIC, got %d", len(nics))
	}
	_ = c.Disable(ctx, swIdx, false)
}

func TestMatcherAddDelTwoNICs(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	a := createLoopback(t)
	b := createLoopback(t)
	ctx := context.Background()

	if err := c.Enable(ctx, a, dstPort); err != nil {
		t.Fatalf("enable a: %v", err)
	}
	if err := c.Enable(ctx, b, dstPort); err != nil {
		t.Fatalf("enable b: %v", err)
	}
	if err := c.MatcherAdd(ctx, prefix, prefLen, []uint32{a, b}); err != nil {
		t.Fatalf("matcher add a,b: %v", err)
	}

	matchers, err := c.DumpMatchers(ctx)
	if err != nil {
		t.Fatalf("dump matchers: %v", err)
	}
	if len(matchers) != 1 {
		t.Fatalf("expected 1 matcher group, got %d: %+v", len(matchers), matchers)
	}
	if matchers[0].PrefixLen != prefLen {
		t.Errorf("prefix_len: got %d want %d", matchers[0].PrefixLen, prefLen)
	}
	if len(matchers[0].NICs) != 2 {
		t.Errorf("expected 2 NICs in matcher group, got %v", matchers[0].NICs)
	}

	if err := c.MatcherDel(ctx, prefix, prefLen, []uint32{a, b}); err != nil {
		t.Fatalf("matcher del: %v", err)
	}
	matchers, _ = c.DumpMatchers(ctx)
	if len(matchers) != 0 {
		t.Errorf("expected 0 matchers after del, got %+v", matchers)
	}

	_ = c.Disable(ctx, a, true)
	_ = c.Disable(ctx, b, true)
}

func TestEnablePortConflict(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	a := createLoopback(t)
	b := createLoopback(t)
	ctx := context.Background()

	if err := c.Enable(ctx, a, dstPort); err != nil {
		t.Fatalf("enable a: %v", err)
	}
	err := c.Enable(ctx, b, dstPort+1)
	if !errors.Is(err, ErrPortConflict) {
		t.Errorf("expected ErrPortConflict, got %v", err)
	}
	_ = c.Disable(ctx, a, false)
}

func TestDisableLastNICClearsState(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	if err := c.Enable(ctx, swIdx, dstPort); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := c.Disable(ctx, swIdx, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	nics, err := c.DumpNICs(ctx)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if len(nics) != 0 {
		t.Errorf("expected 0 enabled NICs after last disable, got %+v", nics)
	}
}

func TestMatcherAddOnUnenabledNICRejected(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	a := createLoopback(t)
	ctx := context.Background()
	// `a` is intentionally NOT enabled.
	err := c.MatcherAdd(ctx, prefix2, prefLen, []uint32{a})
	if err == nil {
		t.Fatal("expected error adding matcher to unenabled NIC")
	}
}

func TestDisableWithMatchersRequiresForce(t *testing.T) {
	resetState(t)
	c := newTestClient(t)
	swIdx := createLoopback(t)
	ctx := context.Background()

	if err := c.Enable(ctx, swIdx, dstPort); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := c.MatcherAdd(ctx, prefix, prefLen, []uint32{swIdx}); err != nil {
		t.Fatalf("matcher add: %v", err)
	}
	if err := c.Disable(ctx, swIdx, false); err == nil {
		t.Fatal("expected disable without force to error when matchers exist")
	}
	if err := c.Disable(ctx, swIdx, true); err != nil {
		t.Fatalf("disable force: %v", err)
	}
	nics, _ := c.DumpNICs(ctx)
	if len(nics) != 0 {
		t.Errorf("expected 0 enabled NICs after force disable, got %+v", nics)
	}
}
