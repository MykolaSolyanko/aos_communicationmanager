// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2021 Renesas Electronics Corporation.
// Copyright (C) 2021 EPAM Systems, Inc.
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

package database

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/aoscloud/aos_common/aostypes"
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_communicationmanager/config"
	"github.com/aoscloud/aos_communicationmanager/imagemanager"
	"github.com/aoscloud/aos_communicationmanager/umcontroller"
)

/***********************************************************************************************************************
 * Variables
 **********************************************************************************************************************/

var (
	tmpDir string
	db     *Database
)

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
	var err error

	tmpDir, err = ioutil.TempDir("", "sm_")
	if err != nil {
		log.Fatalf("Error create temporary dir: %s", err)
	}

	db, err = New(&config.Config{
		WorkingDir: tmpDir,
		Migration: config.Migration{
			MigrationPath:       tmpDir,
			MergedMigrationPath: tmpDir,
		},
	})
	if err != nil {
		log.Fatalf("Can't create database: %s", err)
	}

	ret := m.Run()

	if err = os.RemoveAll(tmpDir); err != nil {
		log.Fatalf("Error cleaning up: %s", err)
	}

	db.Close()

	os.Exit(ret)
}

/***********************************************************************************************************************
 * Tests
 **********************************************************************************************************************/

func TestCursor(t *testing.T) {
	setCursor := "cursor123"

	if err := db.SetJournalCursor(setCursor); err != nil {
		t.Fatalf("Can't set logging cursor: %s", err)
	}

	getCursor, err := db.GetJournalCursor()
	if err != nil {
		t.Fatalf("Can't get logger cursor: %s", err)
	}

	if getCursor != setCursor {
		t.Fatalf("Wrong cursor value: %s", getCursor)
	}
}

func TestComponentsUpdateInfo(t *testing.T) {
	testData := []umcontroller.SystemComponent{
		{
			ID: "component1", VendorVersion: "v1", AosVersion: 1,
			Annotations: "Some annotation", URL: "url12", Sha512: []byte{1, 3, 90, 42},
		},
		{ID: "component2", VendorVersion: "v1", AosVersion: 1, URL: "url12", Sha512: []byte{1, 3, 90, 42}},
	}

	if err := db.SetComponentsUpdateInfo(testData); err != nil {
		t.Fatal("Can't set update manager's update info ", err)
	}

	getUpdateInfo, err := db.GetComponentsUpdateInfo()
	if err != nil {
		t.Fatal("Can't get update manager's update info ", err)
	}

	if !reflect.DeepEqual(testData, getUpdateInfo) {
		t.Fatalf("Wrong update info value: %v", getUpdateInfo)
	}

	testData = []umcontroller.SystemComponent{}

	if err := db.SetComponentsUpdateInfo(testData); err != nil {
		t.Fatal("Can't set update manager's update info ", err)
	}

	getUpdateInfo, err = db.GetComponentsUpdateInfo()
	if err != nil {
		t.Fatal("Can't get update manager's update info ", err)
	}

	if len(getUpdateInfo) != 0 {
		t.Fatalf("Wrong count of update elements 0 != %d", len(getUpdateInfo))
	}
}

func TestSotaFotaState(t *testing.T) {
	fotaState := json.RawMessage("fotaState")
	sotaState := json.RawMessage("sotaState")

	if err := db.SetFirmwareUpdateState(fotaState); err != nil {
		t.Fatal("Can't set FOTA state ", err)
	}

	if err := db.SetSoftwareUpdateState(sotaState); err != nil {
		t.Fatal("Can't set SOTA state ", err)
	}

	retFota, err := db.GetFirmwareUpdateState()
	if err != nil {
		t.Fatal("Can't get FOTA state ", err)
	}

	if string(retFota) != string(fotaState) {
		t.Errorf("Incorrect FOTA state %s", string(retFota))
	}

	retSota, err := db.GetSoftwareUpdateState()
	if err != nil {
		t.Fatal("Can't get SOTA state ", err)
	}

	if string(retSota) != string(sotaState) {
		t.Errorf("Incorrect FOTA state %s", string(retSota))
	}
}

func TestMultiThread(t *testing.T) {
	const numIterations = 1000

	var wg sync.WaitGroup

	wg.Add(4)

	go func() {
		defer wg.Done()

		for i := 0; i < numIterations; i++ {
			if err := db.SetJournalCursor(strconv.Itoa(i)); err != nil {
				t.Errorf("Can't set journal cursor: %s", err)
			}
		}
	}()

	go func() {
		defer wg.Done()

		for i := 0; i < numIterations; i++ {
			if _, err := db.GetJournalCursor(); err != nil {
				t.Errorf("Can't get journal cursor: %s", err)
			}
		}
	}()

	go func() {
		defer wg.Done()

		for i := 0; i < numIterations; i++ {
			if err := db.SetComponentsUpdateInfo([]umcontroller.SystemComponent{{AosVersion: uint64(i)}}); err != nil {
				t.Errorf("Can't set journal cursor: %s", err)
			}
		}
	}()

	go func() {
		defer wg.Done()

		for i := 0; i < numIterations; i++ {
			if _, err := db.GetComponentsUpdateInfo(); err != nil {
				t.Errorf("Can't get journal cursor: %s", err)
			}
		}
	}()

	wg.Wait()
}

func TestServiceStore(t *testing.T) {
	cases := []struct {
		service                      imagemanager.ServiceInfo
		expectedServiceVersionsCount int
		expectedServiceCount         int
		serviceErrorAfterRemove      error
	}{
		{
			service: imagemanager.ServiceInfo{
				ID: "service1", AosVersion: 1, LocalURL: "file:///path/service1", RemoteURL: "http://path/service1",
				Path: "/path/service1", Size: 30, Timestamp: time.Now().UTC(), Cached: false, Config: aostypes.ServiceConfig{
					Hostname: allocateString("service1"),
					Author:   "test",
					Quotas: aostypes.ServiceQuotas{
						UploadSpeed:   allocateUint64(1000),
						DownloadSpeed: allocateUint64(1000),
					},
				},
			},
			expectedServiceVersionsCount: 1,
			expectedServiceCount:         1,
			serviceErrorAfterRemove:      imagemanager.ErrNotExist,
		},
		{
			service: imagemanager.ServiceInfo{
				ID: "service2", AosVersion: 1, LocalURL: "file:///path/service2", RemoteURL: "http://path/service2",
				Path: "/path/service2", Size: 60, Timestamp: time.Now().UTC(), Cached: true, Config: aostypes.ServiceConfig{
					Hostname: allocateString("service2"),
					Author:   "test1",
					Quotas: aostypes.ServiceQuotas{
						UploadSpeed:   allocateUint64(500),
						DownloadSpeed: allocateUint64(500),
					},
					Resources: []string{"resource1", "resource2"},
				},
			},
			expectedServiceVersionsCount: 1,
			expectedServiceCount:         2,
			serviceErrorAfterRemove:      nil,
		},
		{
			service: imagemanager.ServiceInfo{
				ID: "service2", AosVersion: 2, LocalURL: "file:///path/service2/new", RemoteURL: "http://path/service2/new",
				Path: "/path/service2/new", Size: 20, Timestamp: time.Now().UTC(),
			},
			expectedServiceVersionsCount: 2,
			expectedServiceCount:         2,
			serviceErrorAfterRemove:      imagemanager.ErrNotExist,
		},
	}

	for _, tCase := range cases {
		if err := db.AddService(tCase.service); err != nil {
			t.Errorf("Can't add service: %v", err)
		}

		service, err := db.GetServiceInfo(tCase.service.ID)
		if err != nil {
			t.Errorf("Can't get service: %v", err)
		}

		if !reflect.DeepEqual(service, tCase.service) {
			t.Errorf("service %s doesn't match stored one", tCase.service.ID)
		}

		serviceVersions, err := db.GetServiceVersions(tCase.service.ID)
		if err != nil {
			t.Errorf("Can't get service versions: %v", err)
		}

		if len(serviceVersions) != tCase.expectedServiceVersionsCount {
			t.Errorf("Incorrect count of service versions: %v", len(serviceVersions))
		}

		services, err := db.GetServicesInfo()
		if err != nil {
			t.Errorf("Can't get services: %v", err)
		}

		if len(services) != tCase.expectedServiceCount {
			t.Errorf("Incorrect count of services: %v", len(services))
		}

		if err := db.SetServiceCached(tCase.service.ID, !tCase.service.Cached); err != nil {
			t.Errorf("Can't set service cached: %v", err)
		}

		if service, err = db.GetServiceInfo(tCase.service.ID); err != nil {
			t.Errorf("Can't get service: %v", err)
		}

		if service.Cached != !tCase.service.Cached {
			t.Error("Unexpected service cached status")
		}
	}

	for _, tCase := range cases {
		if err := db.RemoveService(tCase.service.ID, tCase.service.AosVersion); err != nil {
			t.Errorf("Can't remove service: %v", err)
		}

		if _, err := db.GetServiceInfo(tCase.service.ID); !errors.Is(err, tCase.serviceErrorAfterRemove) {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

func TestLayerStore(t *testing.T) {
	cases := []struct {
		layer              imagemanager.LayerInfo
		expectedLayerCount int
	}{
		{
			layer: imagemanager.LayerInfo{
				ID: "layer1", Digest: "digest1", AosVersion: 1, LocalURL: "file:///path/layer1",
				RemoteURL: "http://path/layer1", Path: "/path/layer1", Size: 30,
				Timestamp: time.Now().UTC(), Cached: false,
			},
			expectedLayerCount: 1,
		},
		{
			layer: imagemanager.LayerInfo{
				ID: "layer2", Digest: "digest2", AosVersion: 1, LocalURL: "file:///path/layer2", RemoteURL: "http://path/layer2",
				Path: "/path/layer2", Size: 60, Timestamp: time.Now().UTC(), Cached: true,
			},
			expectedLayerCount: 2,
		},
	}

	for _, tCase := range cases {
		if err := db.AddLayer(tCase.layer); err != nil {
			t.Errorf("Can't add layer: %v", err)
		}

		layer, err := db.GetLayerInfo(tCase.layer.Digest)
		if err != nil {
			t.Errorf("Can't get layer: %v", err)
		}

		if !reflect.DeepEqual(layer, tCase.layer) {
			t.Errorf("layer %s doesn't match stored one", tCase.layer.ID)
		}

		layers, err := db.GetLayersInfo()
		if err != nil {
			t.Errorf("Can't get layers: %v", err)
		}

		if len(layers) != tCase.expectedLayerCount {
			t.Errorf("Incorrect count of layers: %v", len(layers))
		}

		if err := db.SetLayerCached(tCase.layer.Digest, !tCase.layer.Cached); err != nil {
			t.Errorf("Can't set layer cached: %v", err)
		}

		if layer, err = db.GetLayerInfo(tCase.layer.Digest); err != nil {
			t.Errorf("Can't get layer: %v", err)
		}

		if layer.Cached != !tCase.layer.Cached {
			t.Error("Unexpected layer cached status")
		}
	}

	for _, tCase := range cases {
		if err := db.RemoveLayer(tCase.layer.Digest); err != nil {
			t.Errorf("Can't remove service: %v", err)
		}

		if _, err := db.GetServiceInfo(tCase.layer.Digest); !errors.Is(err, imagemanager.ErrNotExist) {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

func allocateString(value string) *string {
	return &value
}

func allocateUint64(value uint64) *uint64 {
	return &value
}
