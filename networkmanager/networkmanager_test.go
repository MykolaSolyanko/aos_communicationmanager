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

package networkmanager_test

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	"github.com/aoscloud/aos_communicationmanager/networkmanager"
	"github.com/apparentlymart/go-cidr/cidr"
	log "github.com/sirupsen/logrus"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type ipamTest struct {
	currentIP net.IP
	subnet    net.IPNet
}

type testUUID struct {
	instance int
}

type testStore struct {
	networkInfos map[aostypes.InstanceIdent]networkmanager.NetworkInfo
}

/***********************************************************************************************************************
 * Init
 **********************************************************************************************************************/

func init() {
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: false,
		TimestampFormat:  "2006-01-02 15:04:05.000",
		FullTimestamp:    true,
	})
	log.SetLevel(log.DebugLevel)
	log.SetOutput(os.Stdout)
}

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func TestMain(m *testing.M) {
	ret := m.Run()

	os.Exit(ret)
}

func TestBaseNetwork(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	uuidGen := testUUID{}
	networkmanager.GetIPSubnet = ipam.getIPSubnet
	networkmanager.UUIDGen = uuidGen.generateUUID

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		cniConfig    string
		instance     aostypes.InstanceIdent
		removeConfig bool
	}{
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.2"),
				createFirewallPlugin("uuid1", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.3"),
				createFirewallPlugin("uuid2", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.3"),
				createFirewallPlugin("uuid2", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
		{
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
			removeConfig: true,
		},
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.4"),
				createFirewallPlugin("uuid3", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		if data.removeConfig {
			manager.RemoveInstanceNetworkConf("network1", data.instance)

			continue
		}

		cniConf, err := manager.PrepareInstanceNetworkConf("network1", data.instance, networkmanager.NetworkParams{})
		if err != nil {
			t.Fatalf("Can't prepare instance network configuration: %v", err)
		}

		if string(cniConf) != data.cniConfig {
			t.Errorf("Wrong network config: %s", string(cniConf))
		}
	}

	expectedInstancesIdent := []aostypes.InstanceIdent{
		{
			ServiceID: "service1",
			SubjectID: "subject1",
			Instance:  1,
		},
		{
			ServiceID: "service1",
			SubjectID: "subject1",
			Instance:  2,
		},
	}

	instances := manager.GetInstances("network1")
	if !reflect.DeepEqual(instances, expectedInstancesIdent) {
		t.Error("Unexpected instances ident")
	}
}

func TestFirewallPlugin(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	uuidGen := testUUID{}
	networkmanager.GetIPSubnet = ipam.getIPSubnet
	networkmanager.UUIDGen = uuidGen.generateUUID

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		cniConfig string
		instance  aostypes.InstanceIdent
		params    networkmanager.NetworkParams
	}{
		{
			params: networkmanager.NetworkParams{
				ExposedPorts:       []string{"900"},
				AllowedConnections: []string{"uuid1" + "/900"},
			},
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.2"),
				createFirewallPlugin("uuid1", "900", "900"),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			params: networkmanager.NetworkParams{
				ExposedPorts:       []string{"800"},
				AllowedConnections: []string{"uuid2" + "/800"},
			},
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.3"),
				createFirewallPlugin("uuid2", "800", "800"),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		cniConf, err := manager.PrepareInstanceNetworkConf("network1", data.instance, data.params)
		if err != nil {
			t.Fatalf("Can't prepare instance network configuration: %v", err)
		}

		if string(cniConf) != data.cniConfig {
			t.Errorf("Wrong network config: %s", string(cniConf))
		}
	}
}

func TestBandwithPlugin(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	uuidGen := testUUID{}
	networkmanager.GetIPSubnet = ipam.getIPSubnet
	networkmanager.UUIDGen = uuidGen.generateUUID

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		cniConfig string
		instance  aostypes.InstanceIdent
		params    networkmanager.NetworkParams
	}{
		{
			params: networkmanager.NetworkParams{
				IngressKbit: 1200,
				EgressKbit:  1200,
			},
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.2"),
				createFirewallPlugin("uuid1", "", ""),
				createBandwithPlugin(1200000, 1200000),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			params: networkmanager.NetworkParams{
				IngressKbit: 400,
				EgressKbit:  300,
			},
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.3"),
				createFirewallPlugin("uuid2", "", ""),
				createBandwithPlugin(400000, 300000),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		cniConf, err := manager.PrepareInstanceNetworkConf("network1", data.instance, data.params)
		if err != nil {
			t.Fatalf("Can't prepare instance network configuration: %v", err)
		}

		if string(cniConf) != data.cniConfig {
			t.Errorf("Wrong network config: %s", string(cniConf))
		}
	}
}

func TestNetworkStorage(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	uuidGen := testUUID{}
	networkmanager.GetIPSubnet = ipam.getIPSubnet
	networkmanager.UUIDGen = uuidGen.generateUUID

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		cniConfig string
		instance  aostypes.InstanceIdent
	}{
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.2"),
				createFirewallPlugin("uuid1", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			cniConfig: createPlugins([]string{
				createBridgePlugin("172.17.0.3"),
				createFirewallPlugin("uuid2", "", ""),
				createDNSPlugin(),
			}),
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		if _, err := manager.PrepareInstanceNetworkConf(
			"network1", data.instance, networkmanager.NetworkParams{}); err != nil {
			t.Fatalf("Can't prepare instance network configuration: %v", err)
		}
	}

	manager1, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	expectedInstancesIdent := []aostypes.InstanceIdent{
		{
			ServiceID: "service1",
			SubjectID: "subject1",
			Instance:  1,
		},
		{
			ServiceID: "service1",
			SubjectID: "subject1",
			Instance:  2,
		},
	}

	instances := manager1.GetInstances("network1")
	if !reflect.DeepEqual(instances, expectedInstancesIdent) {
		t.Error("Unexpected instances ident")
	}
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (ipam *ipamTest) init() error {
	ip, ipnet, err := net.ParseCIDR("172.17.0.0/16")
	if err != nil {
		return aoserrors.Wrap(err)
	}

	ipam.currentIP = cidr.Inc(ip)
	ipam.subnet = *ipnet

	return nil
}

func (ipam *ipamTest) getIPSubnet(networkID string) (*net.IPNet, net.IP, error) {
	ipam.currentIP = cidr.Inc(ipam.currentIP)

	return &ipam.subnet, ipam.currentIP, nil
}

func (storage *testStore) AddNetworkInstanceInfo(networkInfo networkmanager.NetworkInfo) error {
	storage.networkInfos[networkInfo.InstanceIdent] = networkInfo

	return nil
}

func (storage *testStore) RemoveNetworkInstanceInfo(instanceIdent aostypes.InstanceIdent) error {
	delete(storage.networkInfos, instanceIdent)

	return nil
}

func (storage *testStore) GetNetworkInstancesInfo() (networkInfos []networkmanager.NetworkInfo, err error) {
	for _, networkInfo := range storage.networkInfos {
		networkInfos = append(networkInfos, networkInfo)
	}

	return networkInfos, err
}

func (uuidGen *testUUID) generateUUID() string {
	uuidGen.instance++

	return fmt.Sprintf("uuid%d", uuidGen.instance)
}

func createPlugins(plugins []string) string {
	networkConfig := `{"name":"network1","cniVersion":"0.4.0","plugins":[`

	for i, plugin := range plugins {
		networkConfig += plugin
		if i != len(plugins)-1 {
			networkConfig += `,`
		}
	}

	return networkConfig + `]}`
}

func createBandwithPlugin(in, out int) string {
	return fmt.Sprintf(
		`{"type":"bandwidth","ingressRate":%d,"ingressBurst":12800,"egressRate":%d,"egressBurst":12800}`, in, out)
}

func createBridgePlugin(ip string) string {
	str := removeSpaces(fmt.Sprintf(`{
		"type": "bridge",
		"bridge": "br-network1",
		"isGateway": true,
		"ipMasq": true,
		"hairpinMode": true,
		"ipam": {
			"rangeStart": "%s",
			"rangeEnd": "%s",
			"subnet": "172.17.0.0/16",
			"Name": "",
			"type": "host-local",
			"routes": [{
				"dst": "0.0.0.0/0"
			}],
			"dataDir": "",
			"resolvConf": "",
			"ranges": null
		}
	}`, ip, ip))

	return str
}

func createFirewallPlugin(instance string, inPort, outPort string) string {
	str := removeSpaces(fmt.Sprintf(`{
		"type": "aos-firewall",
		"uuid": "%s",
		"iptablesAdminChainName": "INSTANCE_%s",
		"allowPublicConnections": true`, instance, instance))

	if inPort != "" {
		str += fmt.Sprintf(`,"inputAccess":[{"port":"%s","protocol":"tcp"}]`, inPort)
	}

	if outPort != "" {
		str += fmt.Sprintf(`,"outputAccess":[{"uuid":"%s","port":"%s","protocol":"tcp"}]`, instance, outPort)
	}

	return str + "}"
}

func createDNSPlugin() string {
	return `{"type":"dnsname","multiDomain":true,"domainName":"network1","capabilities":{"aliases":true}}`
}

func removeSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}

		return r
	}, str)
}
