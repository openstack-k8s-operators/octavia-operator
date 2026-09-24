package octavia

import (
	"testing"

	octaviav1 "github.com/openstack-k8s-operators/octavia-operator/api/v1beta1"
)

func TestProviderSegment(t *testing.T) {
	tests := []struct {
		name        string
		netDetails  *octaviav1.OctaviaLbMgmtNetworks
		wantErr     bool
		wantType    string
		wantPhysnet string
		wantSegID   int
	}{
		{
			name:        "defaults to flat on octavia physnet",
			netDetails:  &octaviav1.OctaviaLbMgmtNetworks{},
			wantType:    "flat",
			wantPhysnet: LbProvPhysicalNet,
			wantSegID:   0,
		},
		{
			name: "vlan with segmentation id",
			netDetails: &octaviav1.OctaviaLbMgmtNetworks{
				ProviderNetworkType:     "vlan",
				ProviderPhysicalNetwork: "datacentre",
				ProviderSegmentationID:  23,
			},
			wantType:    "vlan",
			wantPhysnet: "datacentre",
			wantSegID:   23,
		},
		{
			name: "vlan without segmentation id is an error",
			netDetails: &octaviav1.OctaviaLbMgmtNetworks{
				ProviderNetworkType: "vlan",
			},
			wantErr: true,
		},
		{
			name: "explicit flat keeps custom physnet and ignores segmentation id",
			netDetails: &octaviav1.OctaviaLbMgmtNetworks{
				ProviderNetworkType:     "flat",
				ProviderPhysicalNetwork: "custompn",
				ProviderSegmentationID:  99,
			},
			wantType:    "flat",
			wantPhysnet: "custompn",
			wantSegID:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			segments, err := providerSegment(tt.netDetails)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(segments) != 1 {
				t.Fatalf("expected 1 segment, got %d", len(segments))
			}
			seg := segments[0]
			if seg.NetworkType != tt.wantType {
				t.Errorf("NetworkType = %q, want %q", seg.NetworkType, tt.wantType)
			}
			if seg.PhysicalNetwork != tt.wantPhysnet {
				t.Errorf("PhysicalNetwork = %q, want %q", seg.PhysicalNetwork, tt.wantPhysnet)
			}
			if seg.SegmentationID != tt.wantSegID {
				t.Errorf("SegmentationID = %d, want %d", seg.SegmentationID, tt.wantSegID)
			}
		})
	}
}
