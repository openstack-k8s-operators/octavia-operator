package octavia

import (
	"encoding/json"
	"fmt"
	"net/netip"

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
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

// GetRangeFromCIDR - compute a IP address range from a CIDR
func GetRangeFromCIDR(
	cidr netip.Prefix,
) (start netip.Addr, end netip.Addr) {
	// For IPv6, a /64 is expected, if the CIDR is aaaa:bbbb:cccc:dddd::/64,
	// the range is aaaa:bbbb:cccc:dddd::5 - aaaa:bbbb:cccc:dddd:ffff:ffff:ffff:fffe
	// For IPv4, a /16 is expected, if the CIDR is a.b.0.0/16
	// the range is a.b.0.5 - a.b.255.254
	// IPs from from 1 to 5 are reserved for later user
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

// GetNetworkParametersFromNAD - Extract network information from the Network Attachment Definition
func GetNetworkParametersFromNAD(
	nad *networkv1.NetworkAttachmentDefinition,
	instance *octaviav1.Octavia,
) (*NetworkParameters, error) {
	networkParameters := &NetworkParameters{}

	nadConfig, err := getConfigFromNAD(nad)
	if err != nil {
		return nil, fmt.Errorf("cannot read network parameters: %w", err)
	}

	// Provider subnet parameters
	// These are the parameters for octavia-provider-net/subnet
	networkParameters.ProviderCIDR = nadConfig.IPAM.CIDR

	// OpenShift allocates IP addresses from IPAM.RangeStart to IPAM.RangeEnd
	// for the pods.
	// We're going to use a range of 25 IP addresses that are assigned to
	// the Neutron allocation pool, the range starts right after OpenShift
	// RangeEnd.
	networkParameters.ProviderAllocationStart = nadConfig.IPAM.RangeEnd.Next()
	end := networkParameters.ProviderAllocationStart
	for i := 0; i < LbProvSubnetPoolSize; i++ {
		if !networkParameters.ProviderCIDR.Contains(end) {
			return nil, fmt.Errorf("cannot allocate %d IP addresses in %s", LbProvSubnetPoolSize, networkParameters.ProviderCIDR)
		}
		end = end.Next()
	}
	networkParameters.ProviderAllocationEnd = end

	// The default gateway of the provider network is the gateway of our route
	if len(nadConfig.IPAM.Routes) > 0 {
		networkParameters.ProviderGateway = nadConfig.IPAM.Routes[0].Gateway
	} else if instance.Spec.LbMgmtNetworks.LbMgmtRouterGateway != "" {
		networkParameters.ProviderGateway, err = netip.ParseAddr(instance.Spec.LbMgmtNetworks.LbMgmtRouterGateway)
		if err != nil {
			return nil, fmt.Errorf("cannot parse gateway information: %w", err)
		}
	} else {
		return nil, fmt.Errorf("cannot find gateway information in network attachment")
	}

	// Tenant subnet parameters - parameters for lb-mgmt-net/subnet
	// The NAD must contain one route to the Octavia Tenant Management network,
	// the gateway is an IP address of the provider network and the destination
	// is the CIDR of the Tenant network.
	if len(nadConfig.IPAM.Routes) > 0 {
		networkParameters.TenantCIDR = nadConfig.IPAM.Routes[0].Destination

		// For IPv4, we require a /16 subnet, for IPv6 a /64
		var bitlen int
		if networkParameters.TenantCIDR.Addr().Is6() {
			bitlen = 64
		} else {
			bitlen = 16
		}

		if networkParameters.TenantCIDR.Bits() != bitlen {
			return nil, fmt.Errorf("the tenant CIDR is /%d, it should be /%d", networkParameters.TenantCIDR.Bits(), bitlen)
		}

		// Compute an allocation range based on the CIDR
		start, end := GetRangeFromCIDR(networkParameters.TenantCIDR)
		networkParameters.TenantAllocationStart = start
		networkParameters.TenantAllocationEnd = end
	}

	return networkParameters, err
}
