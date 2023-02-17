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
	"github.com/aoscloud/aos_common/aostypes"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Storage provides API to create, remove or access information from DB.
type Storage interface {
	AddNetworkInstanceInfo(NetworkInfo) error
	RemoveNetworkInstanceInfo(aostypes.InstanceIdent) error
	GetNetworkInstancesInfo() ([]NetworkInfo, error)
}

// NetworkManager networks manager instance.
type NetworkManager struct {
	sync.RWMutex
	instancesData map[string]map[aostypes.InstanceIdent]aostypes.NetworkParameters
	ipamSubnet    *ipSubnet
	storage       Storage
}

// NetworkInfo represents network info for instance.
type NetworkInfo struct {
	aostypes.InstanceIdent
	aostypes.NetworkParameters
	NetworkID string
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// These global variable is used to be able to mocking the functionality of networking in tests.
// nolint:gochecknoglobals
var (
	GetIPSubnet func(networkID string) (allocIPNet *net.IPNet, ip net.IP, err error)
)

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates network manager instance.
func New(storage Storage) (*NetworkManager, error) {
	log.Debug("Create network manager")

	ipamSubnet, err := newIPam()
	if err != nil {
		return nil, err
	}

	if GetIPSubnet == nil {
		GetIPSubnet = ipamSubnet.prepareSubnet
	}

	networkManager := &NetworkManager{
		instancesData: make(map[string]map[aostypes.InstanceIdent]aostypes.NetworkParameters),
		ipamSubnet:    ipamSubnet,
		storage:       storage,
	}

	networkInfos, err := storage.GetNetworkInstancesInfo()
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, networkInfo := range networkInfos {
		if len(networkManager.instancesData[networkInfo.NetworkID]) == 0 {
			networkManager.instancesData[networkInfo.NetworkID] = make(
				map[aostypes.InstanceIdent]aostypes.NetworkParameters)
		}

		networkManager.instancesData[networkInfo.NetworkID][networkInfo.InstanceIdent] = networkInfo.NetworkParameters
	}

	return networkManager, nil
}

// RemoveInstanceNetworkConf removes stored instance network parameters.
func (manager *NetworkManager) RemoveInstanceNetworkParameters(networkID string, instanceIdent aostypes.InstanceIdent) {
	networkParameters, err := manager.tryGetNetParametersFromCache(networkID, instanceIdent)
	if err != nil {
		return
	}

	manager.deleteNetworkParametersFromCache(networkID, instanceIdent, net.ParseIP(networkParameters.IP))

	if err := manager.storage.RemoveNetworkInstanceInfo(instanceIdent); err != nil {
		log.Errorf("Can't remove network info: %v", err)
	}
}

// GetInstances gets instances.
func (manager *NetworkManager) GetInstances(networkID string) (instances []aostypes.InstanceIdent) {
	instances = make([]aostypes.InstanceIdent, 0, len(manager.instancesData[networkID]))

	for instanceIdent := range manager.instancesData[networkID] {
		instances = append(instances, instanceIdent)
	}

	return instances
}

// PrepareInstanceNetworkParameters prepares network parameters for instance.
func (manager *NetworkManager) PrepareInstanceNetworkParameters(
	networkID string, instanceIdent aostypes.InstanceIdent,
) (aostypes.NetworkParameters, error) {
	networkParameters, err := manager.tryGetNetParametersFromCache(networkID, instanceIdent)
	if err == nil {
		return networkParameters, nil
	}

	var (
		ip     net.IP
		subnet *net.IPNet
	)

	defer func() {
		if err != nil {
			manager.deleteNetworkParametersFromCache(networkID, instanceIdent, ip)
		}
	}()

	subnet, ip, err = GetIPSubnet(networkID)
	if err != nil {
		return networkParameters, err
	}

	if err := manager.storage.AddNetworkInstanceInfo(NetworkInfo{
		InstanceIdent: instanceIdent,
		NetworkID:     networkID,
		NetworkParameters: aostypes.NetworkParameters{
			IP:     ip.String(),
			Subnet: subnet.String(),
		},
	}); err != nil {
		return networkParameters, aoserrors.Wrap(err)
	}

	networkParameters.IP = ip.String()
	networkParameters.Subnet = subnet.String()

	manager.addNetworkParametersToCache(networkID, instanceIdent, networkParameters)

	return networkParameters, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (manager *NetworkManager) deleteNetworkParametersFromCache(
	networkID string, instanceIdent aostypes.InstanceIdent, ip net.IP,
) {
	delete(manager.instancesData[networkID], instanceIdent)

	if len(manager.instancesData[networkID]) == 0 {
		manager.ipamSubnet.releaseIPNetPool(networkID)

		return
	}

	manager.ipamSubnet.releaseIPToSubnet(networkID, ip)
}

func (manager *NetworkManager) addNetworkParametersToCache(
	networkID string, instanceIdent aostypes.InstanceIdent, networkParameters aostypes.NetworkParameters,
) {
	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.instancesData[networkID]; !ok {
		manager.instancesData[networkID] = make(map[aostypes.InstanceIdent]aostypes.NetworkParameters)
	}

	manager.instancesData[networkID][instanceIdent] = networkParameters
}

func (manager *NetworkManager) tryGetNetParametersFromCache(
	networkID string, instanceIdent aostypes.InstanceIdent,
) (aostypes.NetworkParameters, error) {
	manager.RLock()
	defer manager.RUnlock()

	if instances, ok := manager.instancesData[networkID]; ok {
		if networkParameter, ok := instances[instanceIdent]; ok {
			return networkParameter, nil
		}
	}

	return aostypes.NetworkParameters{}, aoserrors.Errorf("not found")
}
