// Package overlayclient provides a typed Go client for the VPP overlay
// plugin's binary API.
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
	ErrNICNotArmed         = errors.New("nic not armed")
	ErrTunnelParamMismatch = errors.New("tunnel param mismatch")
	ErrInvalidInterface    = errors.New("invalid interface")
	ErrInvalidArgument     = errors.New("invalid argument")
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
	_ = time.Second
	_ api.Connection = (*core.Connection)(nil)
)

// Close disconnects from VPP.
func (c *Client) Close() error {
	if c.conn != nil {
		c.conn.Disconnect()
	}
	return nil
}

// ArmParams describes the per-NIC arming request.
type ArmParams struct {
	IfaceSwIfIndex uint32
	Src            net.IP
	DstPort        uint16
	SrcPrefix      net.IP
	SrcPrefixLen   uint8
}

// State mirrors a single overlay_v1_details message.
type State struct {
	Configured       bool
	Src              net.IP
	DstPort          uint16
	SrcPrefix        net.IP
	SrcPrefixLen     uint8
	OverlaySwIfIndex uint32
	ArmedInterfaces  []uint32
}

func ip6FromNetIP(ip net.IP) (ip_types.IP6Address, error) {
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return ip_types.IP6Address{}, fmt.Errorf("not an IPv6 address: %v", ip)
	}
	return ip_types.NewIP6Address(ip), nil
}

func addrFromNetIP(ip net.IP) (ip_types.Address, error) {
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return ip_types.Address{}, fmt.Errorf("not an IPv6 address: %v", ip)
	}
	return ip_types.NewAddress(ip), nil
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
			return ErrTunnelParamMismatch
		case apiErrNoSuchEntry:
			return ErrNICNotArmed
		case apiErrInvalidArgument:
			return ErrInvalidArgument
		}
	}
	return err
}

// Arm calls overlay_arm_v1 with enable=true.
func (c *Client) Arm(ctx context.Context, p ArmParams) error {
	src, err := addrFromNetIP(p.Src)
	if err != nil {
		return err
	}
	pfx, err := ip6FromNetIP(p.SrcPrefix)
	if err != nil {
		return err
	}
	_, err = c.rpc.OverlayArmV1(ctx, &overlayapi.OverlayArmV1{
		IfaceSwIfIndex: interface_types.InterfaceIndex(p.IfaceSwIfIndex),
		Enable:         true,
		Src:            src,
		DstPort:        p.DstPort,
		SrcPrefix:      pfx,
		SrcPrefixLen:   p.SrcPrefixLen,
	})
	return mapErr(err)
}

// Disarm calls overlay_arm_v1 with enable=false.
func (c *Client) Disarm(ctx context.Context, ifaceSwIfIndex uint32) error {
	_, err := c.rpc.OverlayArmV1(ctx, &overlayapi.OverlayArmV1{
		IfaceSwIfIndex: interface_types.InterfaceIndex(ifaceSwIfIndex),
		Enable:         false,
		Src:            ip_types.Address{},
		SrcPrefix:      ip_types.IP6Address{},
	})
	return mapErr(err)
}

// Dump fetches the (0-or-1-entry) tunnel state.
func (c *Client) Dump(ctx context.Context) (State, error) {
	var st State
	stream, err := c.rpc.OverlayV1Dump(ctx, &overlayapi.OverlayV1Dump{})
	if err != nil {
		return st, err
	}
	for {
		d, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return st, err
		}
		st.Configured = true
		// src is vl_api_address_t; expect IP6
		if d.Src.Af == ip_types.ADDRESS_IP6 {
			v6 := d.Src.Un.GetIP6()
			st.Src = net.IP(v6[:])
		}
		st.DstPort = d.DstPort
		st.SrcPrefix = net.IP(d.SrcPrefix[:])
		st.SrcPrefixLen = d.SrcPrefixLen
		st.OverlaySwIfIndex = uint32(d.OverlaySwIfIndex)
		st.ArmedInterfaces = nil
		for _, ifx := range d.ArmedInterfaces {
			st.ArmedInterfaces = append(st.ArmedInterfaces, uint32(ifx))
		}
	}
	return st, nil
}
