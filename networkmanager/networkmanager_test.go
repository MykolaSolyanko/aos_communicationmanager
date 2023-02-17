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
	"net"
	"os"
	"reflect"
	"testing"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/aostypes"
	"github.com/apparentlymart/go-cidr/cidr"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_communicationmanager/networkmanager"
)

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

type ipamTest struct {
	currentIP net.IP
	subnet    net.IPNet
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

/***********************************************************************************************************************
 * Main
 **********************************************************************************************************************/

func TestBaseNetwork(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	networkmanager.GetIPSubnet = ipam.getIPSubnet

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		instance          aostypes.InstanceIdent
		removeConfig      bool
		networkParameters aostypes.NetworkParameters
	}{
		{
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.2"),
				Subnet: ("172.17.0.0/16"),
			},
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.3"),
				Subnet: ("172.17.0.0/16"),
			},
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
		{
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.3"),
				Subnet: ("172.17.0.0/16"),
			},
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
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.4"),
				Subnet: ("172.17.0.0/16"),
			},
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		if data.removeConfig {
			manager.RemoveInstanceNetworkParameters("network1", data.instance)

			continue
		}

		networkParameters, err := manager.PrepareInstanceNetworkParameters("network1", data.instance)
		if err != nil {
			t.Fatalf("Can't prepare instance network configuration: %v", err)
		}

		if networkParameters != data.networkParameters {
			t.Errorf("Wrong network parameters: %v", data.networkParameters)
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

func TestNetworkStorage(t *testing.T) {
	ipam := ipamTest{}
	if err := ipam.init(); err != nil {
		t.Fatalf("Can't init ipam management: %v", err)
	}

	networkmanager.GetIPSubnet = ipam.getIPSubnet

	storage := &testStore{
		networkInfos: make(map[aostypes.InstanceIdent]networkmanager.NetworkInfo),
	}

	manager, err := networkmanager.New(storage)
	if err != nil {
		t.Fatalf("Can't create network manager: %v", err)
	}

	testData := []struct {
		networkParameters aostypes.NetworkParameters
		instance          aostypes.InstanceIdent
	}{
		{
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.2"),
				Subnet: ("172.17.0.0/16"),
			},
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  1,
			},
		},
		{
			networkParameters: aostypes.NetworkParameters{
				IP:     ("172.17.0.3"),
				Subnet: ("172.17.0.0/16"),
			},
			instance: aostypes.InstanceIdent{
				ServiceID: "service1",
				SubjectID: "subject1",
				Instance:  2,
			},
		},
	}

	for _, data := range testData {
		if _, err := manager.PrepareInstanceNetworkParameters(
			"network1", data.instance); err != nil {
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
 * Interfaces
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
