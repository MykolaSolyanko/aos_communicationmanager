// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2023 Renesas Electronics Corporation.
// Copyright (C) 2023 EPAM Systems, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package networkmanager provides set of API to configure network

package networkmanager

import (
	"net"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/apparentlymart/go-cidr/cidr"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type subnetwork struct {
	ipNet *net.IPNet
	ips   []net.IP
}

type ipSubnet struct {
	sync.Mutex
	predefinedPrivateNetworks []*net.IPNet
	usedIPSubnetNetworks      map[string]subnetwork
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func newIPam() (ipam *ipSubnet, err error) {
	log.Debug("Create ipam allocator")

	ipam = &ipSubnet{}

	if ipam.predefinedPrivateNetworks, err = makeNetPools(); err != nil {
		return nil, err
	}

	ipam.usedIPSubnetNetworks = make(map[string]subnetwork)

	return ipam, nil
}

func (ipam *ipSubnet) tryToGetExistIPNetFromPool(networkID string) (*net.IPNet, bool) {
	subnet, ok := ipam.usedIPSubnetNetworks[networkID]
	if ok {
		return subnet.ipNet, ok
	}

	return nil, false
}

func (ipam *ipSubnet) requestIPNetPool(networkID string) (allocIPNet *net.IPNet, usedIPNet bool, err error) {
	if len(ipam.predefinedPrivateNetworks) == 0 {
		return nil, usedIPNet, aoserrors.Errorf("IP subnet pool is empty")
	}

	allocIPNet, err = ipam.findUnusedIPSubnet()
	if err != nil {
		return nil, usedIPNet, err
	}

	ipam.usedIPSubnetNetworks[networkID] = subnetwork{
		ipNet: allocIPNet,
		ips:   generateSubnetIPs(allocIPNet),
	}

	return allocIPNet, usedIPNet, nil
}

func (ipam *ipSubnet) findAvailableIP(networkID string) (ip net.IP, err error) {
	subnet, ok := ipam.usedIPSubnetNetworks[networkID]
	if !ok {
		return ip, aoserrors.Errorf("incorrect subnet %s", networkID)
	}

	if len(subnet.ips) == 0 {
		return ip, aoserrors.Errorf("no available ip")
	}

	ip, subnet.ips = subnet.ips[0], subnet.ips[1:]

	ipam.usedIPSubnetNetworks[networkID] = subnet

	return ip, nil
}

func (ipam *ipSubnet) releaseIPToSubnet(networkID string, ip net.IP) {
	ipam.Lock()
	defer ipam.Unlock()

	subnet, exist := ipam.usedIPSubnetNetworks[networkID]
	if !exist {
		return
	}

	subnet.ips = append(subnet.ips, ip)

	ipam.usedIPSubnetNetworks[networkID] = subnet
}

func (ipam *ipSubnet) releaseIPNetPool(networkID string) {
	ipam.Lock()
	defer ipam.Unlock()

	subnet, exist := ipam.usedIPSubnetNetworks[networkID]
	if !exist {
		return
	}

	delete(ipam.usedIPSubnetNetworks, networkID)

	ipam.predefinedPrivateNetworks = append(ipam.predefinedPrivateNetworks, subnet.ipNet)
}

func (ipam *ipSubnet) findUnusedIPSubnet() (unusedIPNet *net.IPNet, err error) {
	networks, err := getNetworkRoutes()
	if err != nil {
		return nil, err
	}

	for i, nw := range ipam.predefinedPrivateNetworks {
		if !checkRouteOverlaps(nw, networks) {
			ipam.predefinedPrivateNetworks = append(
				ipam.predefinedPrivateNetworks[:i], ipam.predefinedPrivateNetworks[i+1:]...)
			return nw, nil
		}
	}

	return nil, aoserrors.Errorf("no available network")
}

func (ipam *ipSubnet) prepareSubnet(networkID string) (allocIPNet *net.IPNet, ip net.IP, err error) {
	ipam.Lock()
	defer ipam.Unlock()

	ipSubnet, exist := ipam.tryToGetExistIPNetFromPool(networkID)
	if !exist {
		if ipSubnet, _, err = ipam.requestIPNetPool(networkID); err != nil {
			return nil, ip, err
		}
	}

	ip, err = ipam.findAvailableIP(networkID)
	if err != nil {
		return nil, ip, err
	}

	return ipSubnet, ip, err
}

func generateSubnetIPs(ipNet *net.IPNet) []net.IP {
	minIPRange, _ := cidr.AddressRange(ipNet)

	// Two is subtracted because the first and last IP addresses
	// are not taken into account(first IP for bridge interface).
	addressCount := cidr.AddressCount(ipNet) - 2

	ips := make([]net.IP, addressCount)

	ip := cidr.Inc(minIPRange)

	for i := uint64(0); i < addressCount; i++ {
		ips[i] = ip
		ip = cidr.Inc(ip)
	}

	return ips
}
