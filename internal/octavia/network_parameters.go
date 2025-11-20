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

// NADIpam represents the IPAM configuration for Network Attachment Definitions
type NADIpam struct {
	CIDR       netip.Prefix `json:"range"`
	RangeStart netip.Addr   `json:"range_start"`
	RangeEnd   netip.Addr   `json:"range_end"`

	Routes []NADRoute `json:"routes"`
}

// NADRoute represents a network route configuration in Network Attachment Definitions
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
	// start is the 5th address of the Cidr
	start = cidr.Masked().Addr()
	for range 5 {
		start = start.Next()
	}

	bits := cidr.Bits()
	if start.Is4() {
		// Padding for ipv4 addresses in a [16]bytes table
		bits += 96
	}
	// convert it to a [16]bytes table, set the remaining bits to 1
	addrBytes := start.As16()
	for b := bits; b < 128; b++ {
		addrBytes[b/8] |= 1 << uint(7-(b%8)) // #nosec G115 -- Controlled bit manipulation with small integer values
	}
	// convert the table to an ip address to get the last IP
	// in case of IPv4, the address should be unmapped
	last := netip.AddrFrom16(addrBytes)
	if start.Is4() {
		last = last.Unmap()
	}
	// end is the 2nd last
	end = last.Prev()

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
	for range LbProvSubnetPoolSize {
		if !networkParameters.ProviderCIDR.Contains(end) {
			return nil, fmt.Errorf("%w: %d in %s", ErrCannotAllocateIPAddresses, LbProvSubnetPoolSize, networkParameters.ProviderCIDR)
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
	} else if !instance.Spec.LbMgmtNetworks.ManageLbMgmtNetworks {
		return networkParameters, nil
	} else {
		return nil, ErrCannotFindGatewayInfo
	}

	// Tenant subnet parameters - parameters for lb-mgmt-net/subnet
	// The NAD must contain one route to the Octavia Tenant Management network,
	// the gateway is an IP address of the provider network and the destination
	// is the CIDR of the Tenant network.
	if len(nadConfig.IPAM.Routes) > 0 {
		networkParameters.TenantCIDR = nadConfig.IPAM.Routes[0].Destination

		// Compute an allocation range based on the CIDR
		start, end := GetRangeFromCIDR(networkParameters.TenantCIDR)
		networkParameters.TenantAllocationStart = start
		networkParameters.TenantAllocationEnd = end
	}

	return networkParameters, err
}
