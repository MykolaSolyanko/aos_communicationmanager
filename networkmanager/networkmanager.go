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
	"encoding/json"
	"net"
	"strings"
	"sync"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	bridgePrefix                  = "br-"
	cniVersion                    = "0.4.0"
	adminChainPrefix              = "INSTANCE_"
	exposePortConfigExpectedLen   = 2
	allowedConnectionsExpectedLen = 3
	burstLen                      = uint64(12800)
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
	instancesData map[string]map[aostypes.InstanceIdent]netConf
	ipamSubnet    *ipSubnet
	storage       Storage
}

// NetworkParams represents network parameters for instance.
type NetworkParams struct {
	IngressKbit        uint64
	EgressKbit         uint64
	ExposedPorts       []string
	AllowedConnections []string
	UploadLimit        uint64
	DownloadLimit      uint64
}

// NetworkInfo represents network info for instance.
type NetworkInfo struct {
	aostypes.InstanceIdent
	NetworkID string
	IP        string
	Config    []byte
}

type netConf struct {
	conf []byte
	ip   net.IP
}

type cniNetwork struct {
	Name       string            `json:"name"`
	CNIVersion string            `json:"cniVersion"`
	Plugins    []json.RawMessage `json:"plugins"`
}

type bridgeNetConf struct {
	Type             string               `json:"type"`
	Bridge           string               `json:"bridge"`
	IsGateway        bool                 `json:"isGateway"`
	IsDefaultGateway bool                 `json:"isDefaultGateway,omitempty"`
	ForceAddress     bool                 `json:"forceAddress,omitempty"`
	IPMasq           bool                 `json:"ipMasq"`
	MTU              int                  `json:"mtu,omitempty"`
	HairpinMode      bool                 `json:"hairpinMode"`
	PromiscMode      bool                 `json:"promiscMode,omitempty"`
	Vlan             int                  `json:"vlan,omitempty"`
	IPAM             allocator.IPAMConfig `json:"ipam"`
}

type inputAccessConfig struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type outputAccessConfig struct {
	UUID     string `json:"uuid"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type aosFirewallNetConf struct {
	Type                   string               `json:"type"`
	UUID                   string               `json:"uuid"`
	IptablesAdminChainName string               `json:"iptablesAdminChainName"`
	AllowPublicConnections bool                 `json:"allowPublicConnections"`
	InputAccess            []inputAccessConfig  `json:"inputAccess,omitempty"`
	OutputAccess           []outputAccessConfig `json:"outputAccess,omitempty"`
}

type bandwidthNetConf struct {
	Type         string `json:"type,omitempty"`
	IngressRate  uint64 `json:"ingressRate,omitempty"`
	IngressBurst uint64 `json:"ingressBurst,omitempty"`
	EgressRate   uint64 `json:"egressRate,omitempty"`
	EgressBurst  uint64 `json:"egressBurst,omitempty"`
}

type aosDNSNetConf struct {
	Type         string          `json:"type"`
	MultiDomain  bool            `json:"multiDomain,omitempty"`
	DomainName   string          `json:"domainName,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

// These global variable is used to be able to mocking the functionality of networking in tests.
// nolint:gochecknoglobals
var (
	GetIPSubnet func(networkID string) (allocIPNet *net.IPNet, ip net.IP, err error)
	UUIDGen     = UUIDGenerate
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
		instancesData: make(map[string]map[aostypes.InstanceIdent]netConf),
		ipamSubnet:    ipamSubnet,
		storage:       storage,
	}

	networkInfos, err := storage.GetNetworkInstancesInfo()
	if err != nil {
		return nil, aoserrors.Wrap(err)
	}

	for _, networkInfo := range networkInfos {
		if len(networkManager.instancesData[networkInfo.NetworkID]) == 0 {
			networkManager.instancesData[networkInfo.NetworkID] = make(map[aostypes.InstanceIdent]netConf)
		}

		networkManager.instancesData[networkInfo.NetworkID][networkInfo.InstanceIdent] = netConf{
			conf: networkInfo.Config,
			ip:   net.ParseIP(networkInfo.IP),
		}
	}

	return networkManager, nil
}

// RemoveInstanceNetworkConf removes instance network configuration.
func (manager *NetworkManager) RemoveInstanceNetworkConf(networkID string, instanceIdent aostypes.InstanceIdent) {
	config, err := manager.tryGetNetConfFromCache(networkID, instanceIdent)
	if err != nil {
		return
	}

	manager.deleteInstanceNetworkFromCache(networkID, instanceIdent, config.ip)

	if err := manager.storage.RemoveNetworkInstanceInfo(instanceIdent); err != nil {
		log.Errorf("Can't remove network info: %v", err)
	}
}

// GetInstances gets instances network configuration.
func (manager *NetworkManager) GetInstances(networkID string) (instances []aostypes.InstanceIdent) {
	instances = make([]aostypes.InstanceIdent, 0, len(manager.instancesData[networkID]))

	for instanceIdent := range manager.instancesData[networkID] {
		instances = append(instances, instanceIdent)
	}

	return instances
}

// PrepareInstanceNetworkConf prepares network configuration for instance.
func (manager *NetworkManager) PrepareInstanceNetworkConf(
	networkID string, instanceIdent aostypes.InstanceIdent, params NetworkParams,
) (conf []byte, err error) {
	config, err := manager.tryGetNetConfFromCache(networkID, instanceIdent)
	if err == nil {
		return config.conf, nil
	}

	var (
		ip     net.IP
		subnet *net.IPNet
	)

	defer func() {
		if err != nil {
			manager.deleteInstanceNetworkFromCache(networkID, instanceIdent, ip)
		}
	}()

	subnet, ip, err = GetIPSubnet(networkID)
	if err != nil {
		return nil, err
	}

	if config, err = manager.prepareCNIConfig(UUIDGen(), networkID, params, subnet, ip); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	if err := manager.storage.AddNetworkInstanceInfo(NetworkInfo{
		InstanceIdent: instanceIdent,
		NetworkID:     networkID,
		IP:            ip.String(),
		Config:        config.conf,
	}); err != nil {
		log.Errorf("Can't remove network info: %v", err)
	}

	manager.addInstanceNetworkToCache(networkID, instanceIdent, config)

	return config.conf, nil
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (manager *NetworkManager) deleteInstanceNetworkFromCache(
	networkID string, instanceIdent aostypes.InstanceIdent, ip net.IP,
) {
	delete(manager.instancesData[networkID], instanceIdent)

	if len(manager.instancesData[networkID]) == 0 {
		manager.ipamSubnet.releaseIPNetPool(networkID)

		return
	}

	manager.ipamSubnet.releaseIPToSubnet(networkID, ip)
}

func (manager *NetworkManager) addInstanceNetworkToCache(
	networkID string, instanceIdent aostypes.InstanceIdent, conf netConf,
) {
	manager.Lock()
	defer manager.Unlock()

	if _, ok := manager.instancesData[networkID]; !ok {
		manager.instancesData[networkID] = make(map[aostypes.InstanceIdent]netConf)
	}

	manager.instancesData[networkID][instanceIdent] = conf
}

func (manager *NetworkManager) tryGetNetConfFromCache(
	networkID string, instanceIdent aostypes.InstanceIdent,
) (config netConf, err error) {
	manager.RLock()
	defer manager.RUnlock()

	if instances, ok := manager.instancesData[networkID]; ok {
		if config, ok = instances[instanceIdent]; ok {
			return config, nil
		}
	}

	return config, aoserrors.Errorf("not found")
}

func (manager *NetworkManager) prepareCNIConfig(
	instanceID, networkID string, params NetworkParams, subnet *net.IPNet, ip net.IP,
) (config netConf, err error) {
	networkConfig := cniNetwork{Name: networkID, CNIVersion: cniVersion}

	// Bridge

	bridgeConfig, err := manager.getBridgePluginConfig(networkID, subnet, ip)
	if err != nil {
		return config, err
	}

	networkConfig.Plugins = append(networkConfig.Plugins, bridgeConfig)

	// Firewall

	firewallConfig, err := getFirewallPluginConfig(instanceID, params.ExposedPorts, params.AllowedConnections)
	if err != nil {
		return config, err
	}

	networkConfig.Plugins = append(networkConfig.Plugins, firewallConfig)

	// Bandwidth

	if params.IngressKbit > 0 || params.EgressKbit > 0 {
		bandwidthConfig, err := getBandwidthPluginConfig(params.IngressKbit, params.EgressKbit)
		if err != nil {
			return config, err
		}

		networkConfig.Plugins = append(networkConfig.Plugins, bandwidthConfig)
	}

	// DNS

	dnsConfig, err := getDNSPluginConfig(networkID)
	if err != nil {
		return config, err
	}

	networkConfig.Plugins = append(networkConfig.Plugins, dnsConfig)

	cniNetworkConfig, err := json.Marshal(networkConfig)
	if err != nil {
		return config, aoserrors.Wrap(err)
	}

	return netConf{
		conf: cniNetworkConfig,
		ip:   ip,
	}, nil
}

func getDNSPluginConfig(networkID string) (config json.RawMessage, err error) {
	configDNS := &aosDNSNetConf{
		Type:         "dnsname",
		MultiDomain:  true,
		DomainName:   networkID,
		Capabilities: map[string]bool{"aliases": true},
	}

	if config, err = json.Marshal(configDNS); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return config, nil
}

func getBandwidthPluginConfig(ingressKbit, egressKbit uint64) (config json.RawMessage, err error) {
	bandwidth := &bandwidthNetConf{
		Type: "bandwidth",
	}

	// the burst argument was selected relative to the mtu network interface

	if ingressKbit > 0 {
		bandwidth.IngressRate = ingressKbit * 1000
		bandwidth.IngressBurst = burstLen
	}

	if egressKbit > 0 {
		bandwidth.EgressRate = egressKbit * 1000
		bandwidth.EgressBurst = burstLen
	}

	if config, err = json.Marshal(bandwidth); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return config, nil
}

func getFirewallPluginConfig(instanceID string, exposedPorts, allowedConnections []string) (
	config json.RawMessage, err error,
) {
	aosFirewall := &aosFirewallNetConf{
		Type:                   "aos-firewall",
		UUID:                   instanceID,
		IptablesAdminChainName: adminChainPrefix + instanceID,
		AllowPublicConnections: true,
	}

	// ExposedPorts format port/protocol
	for _, exposePort := range exposedPorts {
		portConfig := strings.Split(exposePort, "/")
		if len(portConfig) > exposePortConfigExpectedLen || len(portConfig) == 0 {
			return nil, aoserrors.Errorf("unsupported ExposedPorts format %s", exposePort)
		}

		input := inputAccessConfig{Port: portConfig[0], Protocol: "tcp"}
		if len(portConfig) == exposePortConfigExpectedLen {
			input.Protocol = portConfig[1]
		}

		aosFirewall.InputAccess = append(aosFirewall.InputAccess, input)
	}

	// AllowedConnections format instance-UUID/port/protocol
	for _, allowConn := range allowedConnections {
		connConf := strings.Split(allowConn, "/")
		if len(connConf) > allowedConnectionsExpectedLen || len(connConf) < 2 {
			return nil, aoserrors.Errorf("unsupported AllowedConnections format %s", connConf)
		}

		output := outputAccessConfig{UUID: connConf[0], Port: connConf[1], Protocol: "tcp"}
		if len(connConf) == allowedConnectionsExpectedLen {
			output.Protocol = connConf[2]
		}

		aosFirewall.OutputAccess = append(aosFirewall.OutputAccess, output)
	}

	if config, err = json.Marshal(aosFirewall); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return config, nil
}

func (manager *NetworkManager) getBridgePluginConfig(
	networkID string, subnet *net.IPNet, ip net.IP,
) (config json.RawMessage, err error) {
	_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")

	configBridge := &bridgeNetConf{
		Type:        "bridge",
		Bridge:      bridgePrefix + networkID,
		IsGateway:   true,
		IPMasq:      true,
		HairpinMode: true,
		IPAM: allocator.IPAMConfig{
			Type: "host-local",
			Range: &allocator.Range{
				RangeStart: ip,
				RangeEnd:   ip,
				Subnet:     types.IPNet(*subnet),
			},
			Routes: []*types.Route{
				{
					Dst: *defaultRoute,
				},
			},
		},
	}

	if config, err = json.Marshal(configBridge); err != nil {
		return nil, aoserrors.Wrap(err)
	}

	return config, nil
}

func UUIDGenerate() string {
	return uuid.New().String()
}
