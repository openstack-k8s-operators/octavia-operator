package octavia

import (
	"encoding/json"
	"fmt"
	"net/netip"

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
)

// NetworkParameters - Parameters for the Octavia networks, based on the config of the NAD
type NetworkParameters struct {
	CIDR            netip.Prefix
	AllocationStart netip.Addr
	AllocationEnd   netip.Addr
	Gateway         netip.Addr
	RouterIPAddress netip.Addr
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
	Gateway netip.Addr `json:"gw"`
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

func GetNetworkParametersFromNAD(
	nad *networkv1.NetworkAttachmentDefinition,
) (*NetworkParameters, error) {
	networkParameters := &NetworkParameters{}

	nadConfig, err := getConfigFromNAD(nad)
	if err != nil {
		return nil, fmt.Errorf("cannot read network parameters: %w", err)
	}

	networkParameters.CIDR = nadConfig.IPAM.CIDR

	networkParameters.AllocationStart = nadConfig.IPAM.RangeEnd.Next()
	end := networkParameters.AllocationStart
	for i := 0; i < LbProvSubnetPoolSize; i++ {
		if !networkParameters.CIDR.Contains(end) {
			return nil, fmt.Errorf("cannot allocate %d IP addresses in %s", LbProvSubnetPoolSize, networkParameters.CIDR)
		}
		end = end.Next()
	}
	networkParameters.AllocationEnd = end
	// TODO(gthiemonge) Remove routes from NAD, manage them in the operator
	if len(nadConfig.IPAM.Routes) > 0 {
		networkParameters.RouterIPAddress = nadConfig.IPAM.Routes[0].Gateway
	} else {
		return nil, fmt.Errorf("cannot find gateway information in network attachment")
	}
	// Gateway is currently unset

	return networkParameters, err
}
