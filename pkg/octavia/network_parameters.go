package octavia

import (
	"encoding/json"
	"fmt"
	"net/netip"

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
)

// NetworkParameters - Parameters for the Octavia networks, based on the config of the NAD
type NetworkParameters struct {
	ProviderCIDR            netip.Prefix
	ProviderAllocationStart netip.Addr
	ProviderAllocationEnd   netip.Addr
	ProviderGateway         netip.Addr
	TenantCIDR              netip.Prefix
	TenantAllocationStart   netip.Addr
	TenantAllocationEnd     netip.Addr
}

// NADConfig - IPAM parameters of the NAD
type NADConfig struct {
	IPAM NADIpam `json:"ipam"`
}

type NADIpam struct {
	CIDR       netip.Prefix `json:"range"`
	RangeStart netip.Addr   `json:"range_start"`
	RangeEnd   netip.Addr   `json:"range_end"`

	Routes []NADRoute `json:"routes"`
}

type NADRoute struct {
	Gateway     netip.Addr   `json:"gw"`
	Destination netip.Prefix `json:"dst"`
}

func getConfigFromNAD(
	nad *networkv1.NetworkAttachmentDefinition,
) (*NADConfig, error) {
	nadConfig := &NADConfig{}
	jsonDoc := []byte(nad.Spec.Config)
	err := json.Unmarshal(jsonDoc, nadConfig)
	if err != nil {
		return nil, err
	}

	return nadConfig, nil
}

func getRangeFromCIDR(
	cidr netip.Prefix,
) (start netip.Addr, end netip.Addr) {
	addr := cidr.Addr()
	if addr.Is6() {
		addrBytes := addr.As16()
		for i := 8; i < 15; i++ {
			addrBytes[i] = 0
		}
		addrBytes[15] = 5
		start = netip.AddrFrom16(addrBytes)
		for i := 8; i < 15; i++ {
			addrBytes[i] = 0xff
		}
		addrBytes[15] = 0xfe
		end = netip.AddrFrom16(addrBytes)
	} else {
		addrBytes := addr.As4()
		addrBytes[2] = 0
		addrBytes[3] = 5
		start = netip.AddrFrom4(addrBytes)
		addrBytes[2] = 0xff
		addrBytes[3] = 0xfe
		end = netip.AddrFrom4(addrBytes)
	}
	return
}

func GetNetworkParametersFromNAD(
	nad *networkv1.NetworkAttachmentDefinition,
) (*NetworkParameters, error) {
	networkParameters := &NetworkParameters{}

	nadConfig, err := getConfigFromNAD(nad)
	if err != nil {
		return nil, fmt.Errorf("cannot read network parameters: %w", err)
	}

	// Provider subnet parameters
	networkParameters.ProviderCIDR = nadConfig.IPAM.CIDR

	networkParameters.ProviderAllocationStart = nadConfig.IPAM.RangeEnd.Next()
	end := networkParameters.ProviderAllocationStart
	for i := 0; i < LbProvSubnetPoolSize; i++ {
		if !networkParameters.ProviderCIDR.Contains(end) {
			return nil, fmt.Errorf("cannot allocate %d IP addresses in %s", LbProvSubnetPoolSize, networkParameters.ProviderCIDR)
		}
		end = end.Next()
	}
	networkParameters.ProviderAllocationEnd = end
	if len(nadConfig.IPAM.Routes) > 0 {
		networkParameters.ProviderGateway = nadConfig.IPAM.Routes[0].Gateway
	} else {
		return nil, fmt.Errorf("cannot find gateway information in network attachment")
	}

	// Tenant subnet parameters
	networkParameters.TenantCIDR = nadConfig.IPAM.Routes[0].Destination
	var bitlen int
	if networkParameters.TenantCIDR.Addr().Is6() {
		bitlen = 64
	} else {
		bitlen = 16
	}

	if networkParameters.TenantCIDR.Bits() != bitlen {
		return nil, fmt.Errorf("the tenant CIDR is /%d, it should be /%d", networkParameters.TenantCIDR.Bits(), bitlen)
	}

	start, end := getRangeFromCIDR(networkParameters.TenantCIDR)
	networkParameters.TenantAllocationStart = start
	networkParameters.TenantAllocationEnd = end

	return networkParameters, err
}
