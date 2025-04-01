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
	"syscall"

	"github.com/aosedge/aos_common/aoserrors"
	"github.com/vishvananda/netlink"

	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func getNetworkRoutes() (routeIPList []netlink.Route, err error) {
	initNl, err := netlink.NewHandle(syscall.NETLINK_ROUTE, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, aoserrors.Errorf("could not create netlink handle on initial namespace: %v", err)
	}
	defer initNl.Delete()

	routeIPList, err = initNl.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return routeIPList, nil
}

func checkRouteOverlaps(toCheck *net.IPNet, networks []netlink.Route) (overlapsIPs bool) {
	for _, network := range networks {
		log.Infof("network: %s", network.String())
		log.Infof("toCheck: %s", toCheck.String())

		if network.Dst == nil {
			log.Infof("network.Dst: nil")

			continue
		}

		log.Infof("network.Dst: %s", network.Dst.String())
		log.Infof("network.Dst.IP: %s", network.Dst.IP.String())
		log.Infof("toCheck.IP: %s", toCheck.IP.String())

		if network.Dst.String() == "0.0.0.0/0" {
			if network.Gw != nil && toCheck.Contains(network.Gw) {
				log.Infof("Default route with gateway %s is inside network %s", network.Gw.String(), toCheck.String())

				return true
			}
		} else if toCheck.Contains(network.Dst.IP) || network.Dst.Contains(toCheck.IP) {
			log.Infof("Network overlap detected")

			return true
		}
	}

	return false
}
