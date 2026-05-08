// Package overlayclient provides a typed Go client for the VPP overlay
// plugin's binary API (Slice C-2: enable / disable / matcher add / del).
package overlayclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"

	interface_types "github.com/yafimk/vpp-overlay/dev/go-overlay/interface_types"
	ip_types "github.com/yafimk/vpp-overlay/dev/go-overlay/ip_types"
	overlayapi "github.com/yafimk/vpp-overlay/dev/go-overlay/overlay"
)

// Typed errors mapping from VPP API retvals.
var (
	ErrNICNotArmed      = errors.New("nic not armed")
	ErrPortConflict     = errors.New("dst-port conflicts with existing overlay tunnel")
	ErrInvalidInterface = errors.New("invalid interface")
	ErrInvalidArgument  = errors.New("invalid argument")
)

// VPP API error retval constants — must match VNET_API_ERROR_* used by
// overlay_rc_to_api() in overlay.c.
const (
	apiErrInvalidArgument  = -73
	apiErrInvalidValue     = -7
	apiErrNoSuchEntry      = -6 // VNET_API_ERROR_NO_SUCH_ENTRY
	apiErrInvalidSwIfIndex = -14
)

// Client is a thin typed wrapper around govpp's connection for the
// overlay plugin.
type Client struct {
	conn *core.Connection
	rpc  overlayapi.RPCService
}

// New connects to the binary API socket and returns a Client.
// The caller must Close() it.
func New(socketPath string) (*Client, error) {
	conn, err := govpp.Connect(socketPath)
	if err != nil {
		return nil, fmt.Errorf("govpp connect %q: %w", socketPath, err)
	}
	return &Client{
		conn: conn,
		rpc:  overlayapi.NewServiceClient(conn),
	}, nil
}

var (
	_                = time.Second
	_ api.Connection = (*core.Connection)(nil)
)

// Close disconnects from VPP.
func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Disconnect()
	}
	return nil
}

func ip6FromNetIP(ip net.IP) (ip_types.IP6Address, error) {
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return ip_types.IP6Address{}, fmt.Errorf("not an IPv6 address: %v", ip)
	}
	return ip_types.NewIP6Address(ip), nil
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var apiErr api.VPPApiError
	if errors.As(err, &apiErr) {
		switch int(apiErr) {
		case apiErrInvalidSwIfIndex:
			return ErrInvalidInterface
		case apiErrInvalidValue:
			return ErrPortConflict
		case apiErrNoSuchEntry:
			return ErrNICNotArmed
		case apiErrInvalidArgument:
			return ErrInvalidArgument
		}
	}
	return err
}

// Enable arms overlay encap+bypass on `swIfIndex` with the given UDP
// destination port. Idempotent on identical dst_port.
func (c *Client) Enable(ctx context.Context, swIfIndex uint32, dstPort uint16) error {
	_, err := c.rpc.OverlayEnable(ctx, &overlayapi.OverlayEnable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		DstPort:   dstPort,
		Enable:    true,
		Force:     false,
	})
	return mapErr(err)
}

// Disable detaches overlay encap+bypass from `swIfIndex`. If `force` is
// false and the NIC still owns matchers, the call fails.
func (c *Client) Disable(ctx context.Context, swIfIndex uint32, force bool) error {
	_, err := c.rpc.OverlayEnable(ctx, &overlayapi.OverlayEnable{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Enable:    false,
		Force:     force,
	})
	return mapErr(err)
}

// MatcherAdd attaches the (srcPrefix, prefixLen) matcher to every NIC in
// `nicSwIfs`. Atomic across NICs: nothing is mutated unless every NIC is
// enabled and below the cap.
func (c *Client) MatcherAdd(ctx context.Context, srcPrefix net.IP, prefixLen uint8, nicSwIfs []uint32) error {
	pfx, err := ip6FromNetIP(srcPrefix)
	if err != nil {
		return err
	}
	nics := make([]interface_types.InterfaceIndex, len(nicSwIfs))
	for i, x := range nicSwIfs {
		nics[i] = interface_types.InterfaceIndex(x)
	}
	_, err = c.rpc.OverlayMatcherAdd(ctx, &overlayapi.OverlayMatcherAdd{
		SrcPrefix: ip_types.IP6Prefix{Address: pfx, Len: prefixLen},
		NNicSwIfs: uint32(len(nics)),
		NicSwIfs:  nics,
	})
	return mapErr(err)
}

// MatcherDel removes the (srcPrefix, prefixLen) matcher from every NIC in
// `nicSwIfs`. Atomic.
func (c *Client) MatcherDel(ctx context.Context, srcPrefix net.IP, prefixLen uint8, nicSwIfs []uint32) error {
	pfx, err := ip6FromNetIP(srcPrefix)
	if err != nil {
		return err
	}
	nics := make([]interface_types.InterfaceIndex, len(nicSwIfs))
	for i, x := range nicSwIfs {
		nics[i] = interface_types.InterfaceIndex(x)
	}
	_, err = c.rpc.OverlayMatcherDel(ctx, &overlayapi.OverlayMatcherDel{
		SrcPrefix: ip_types.IP6Prefix{Address: pfx, Len: prefixLen},
		NNicSwIfs: uint32(len(nics)),
		NicSwIfs:  nics,
	})
	return mapErr(err)
}

// EnabledNIC mirrors a single overlay_details message.
type EnabledNIC struct {
	SwIfIndex uint32
	DstPort   uint16
	NMatchers uint8
}

// DumpNICs returns one entry per enabled NIC.
func (c *Client) DumpNICs(ctx context.Context) ([]EnabledNIC, error) {
	stream, err := c.rpc.OverlayDump(ctx, &overlayapi.OverlayDump{})
	if err != nil {
		return nil, err
	}
	var out []EnabledNIC
	for {
		d, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		out = append(out, EnabledNIC{
			SwIfIndex: uint32(d.SwIfIndex),
			DstPort:   d.DstPort,
			NMatchers: d.NMatchers,
		})
	}
	return out, nil
}

// Matcher mirrors a single overlay_matcher_details message.
type Matcher struct {
	SrcPrefix net.IP
	PrefixLen uint8
	NICs      []uint32
}

// DumpMatchers returns one entry per (prefix, NIC-list) tuple.
func (c *Client) DumpMatchers(ctx context.Context) ([]Matcher, error) {
	stream, err := c.rpc.OverlayMatcherDump(ctx, &overlayapi.OverlayMatcherDump{})
	if err != nil {
		return nil, err
	}
	var out []Matcher
	for {
		d, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
		m := Matcher{
			SrcPrefix: net.IP(d.SrcPrefix.Address[:]),
			PrefixLen: d.SrcPrefix.Len,
		}
		for _, ifx := range d.NicSwIfs {
			m.NICs = append(m.NICs, uint32(ifx))
		}
		out = append(out, m)
	}
	return out, nil
}
