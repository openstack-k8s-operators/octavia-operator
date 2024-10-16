# Octavia DCN

## Octavia in DCN deployments

The deployment of the Octavia services in DCN differs from standard
deployments.
While it supports using only one Octavia management network across the
Availability Zones for communication between the control plane and the Amphora
instances, admins might want to isolate the network traffic and use one
management network per AZ.

In this case, they must configure the octavia-operator to define specific
settings for those AZs.

## Configuration of the Neutron AZs

When deploying DCN, each compute node is assigned to an AZ (example: az[1..n]),
the default AZ created for the control plane (az0 in this document) is not used
by the compute nodes.
It means that the `lb-mgmt-net` network created by the octavia-operator for the
default AZ is not required.
It can be (optionally) disabled by removing the route from the octavia Network
Attachment Definition:

Example:

```shell
oc edit network-attachment-definitions.k8s.cni.cncf.io octavia
```

```yaml
spec:
  config: |
    {
      "cniVersion": "0.3.1",
      "name": "octavia",
      "type": "bridge",
      "bridge": "octbr",
      "ipam": {
        "type": "whereabouts",
        "range": "172.23.0.0/24",
        "range_start": "172.23.0.30",
        "range_end": "172.23.0.70"
      }
    }
```

The `lbMgmtNetwork.availabilityZones` spec of the Octavia Kind must contain the
AZ of the control plane.

The `lbMgmtNetwork.createDefaultLbMgmtNetwork` spec can be optionaly set to
`false` to prevent the operator to create the default `lb-mgmt-net` network for
default AZ.
In this case, they should set `lbMgmtNetwork.lbMgmtRouterGateway` to an IP
address of the octavia NAD, this address should be selected in a range that
starts after the `ipam.range_end` IP address.

Then `lbMgmtNetwork.availabilityZonesCIDRs` spec should define a different CIDR
for each AZ. The octavia-operator will ensure that those CIDRs are routable from
the Octavia service through a Neutron router.

```shell
oc patch openstackcontrolplane openstack-galera-network-isolation --type=merge --patch='
    spec:
      octavia:
        template:
          lbMgmtNetwork:
            createDefaultLbMgmtNetwork: false
            lbMgmtRouterGateway: 172.23.0.150
            availabilityZones:
            - az0
            availabilityZoneCIDRs:
              az1: 172.34.0.0/16
              az2: 172.44.0.0/16
'
```

With those settings, the octavia-operator will create:

* a `lb-mgmt-az1-net` network with a `lb-mgmt-az1-subnet` subnet (CIDR
  `172.34.0.0/16`) with availability_hints `az1`
* a `lb-mgmt-az2-net` network with a `lb-mgmt-az2-subnet` subnet (CIDR
  `172.44.0.0/16`) with availability_hints `az2`
* an `octavia-provider-net` network with an `octavia-provider-subnet` subnet
  (CIDR `172.23.0.0/24`)
* an `octavia-link-router` router in `az0`, `az1` and `az2`,
  `octavia-provider-subnet` is plugged into this router through a port with the
  IP address `172.23.0.150`, `lb-mgmt-az1-subnet` and `lb-mgmt-az2-subnet` are
  also plugged into the router

## Creating Octavia Availability Zone Profiles and Availability Zones

When creating a Load Balancer for a specific AZ in Octavia, some metadata must
be passed to the Octavia service, to indicate which compute AZ and management network it should use to create Amphora VMs.

Those metadata are stored in Octavia Availability Zone Profile and Availability
Zones. They can be created by admins:

```shell
oc rsh openstackclient
network_id=$(openstack network show -c id -f value lb-mgmt-az1-net)
openstack loadbalancer availabilityzoneprofile create \
    --provider amphora \
    --availability-zone-data '{"compute_zone": "az1", "management_network": "'$network_id'"}' \
    --name azp1
openstack loadbalancer availabilityzone create \
    --availabilityzoneprofile azp1 \
    --name az1
```

```shell
oc rsh openstackclient
network_id=$(openstack network show -c id -f value lb-mgmt-az2-net)
openstack loadbalancer availabilityzoneprofile create \
    --provider amphora \
    --availability-zone-data '{"compute_zone": "az2", "management_network": "'$network_id'"}' \
    --name azp2
openstack loadbalancer availabilityzone create \
    --availabilityzoneprofile azp2 \
    --name az2
```

A user can then pass an `availability-zone` parameter to the Octavia API when
creating a Load Balancer

```shell
openstack loadbalancer create \
    --availability-zone az2 \
    --vip-subnet-id public-subnet \
    --name lb1
```
