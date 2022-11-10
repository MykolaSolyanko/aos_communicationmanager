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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/aoscloud/aos_common/aoserrors"
	"github.com/aoscloud/aos_common/migration"
	_ "github.com/mattn/go-sqlite3" // ignore lint
	log "github.com/sirupsen/logrus"

	"github.com/aoscloud/aos_communicationmanager/config"
	"github.com/aoscloud/aos_communicationmanager/imagemanager"
	"github.com/aoscloud/aos_communicationmanager/umcontroller"
)

/***********************************************************************************************************************
 * Consts
 **********************************************************************************************************************/

const (
	busyTimeout = 60000
	journalMode = "WAL"
	syncMode    = "NORMAL"
)

const dbVersion = 0

const dbFileName = "communicationmanager.db"

/***********************************************************************************************************************
 * Vars
 **********************************************************************************************************************/

var errNotExist = errors.New("entry does not exist")

/***********************************************************************************************************************
 * Types
 **********************************************************************************************************************/

// Database structure with database information.
type Database struct {
	sql *sql.DB
}

/***********************************************************************************************************************
 * Public
 **********************************************************************************************************************/

// New creates new database handle.
func New(config *config.Config) (db *Database, err error) {
	fileName := path.Join(config.WorkingDir, dbFileName)

	log.WithField("fileName", fileName).Debug("Open database")

	if err = os.MkdirAll(filepath.Dir(fileName), 0o755); err != nil {
		return db, aoserrors.Wrap(err)
	}

	if err = migration.MergeMigrationFiles(config.Migration.MigrationPath,
		config.Migration.MergedMigrationPath); err != nil {
		return db, aoserrors.Wrap(err)
	}

	sqlite, err := sql.Open("sqlite3", fmt.Sprintf("%s?_busy_timeout=%d&_journal_mode=%s&_sync=%s",
		fileName, busyTimeout, journalMode, syncMode))
	if err != nil {
		return db, aoserrors.Wrap(err)
	}

	db = &Database{sqlite}

	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	exists, err := db.isTableExist("config")
	if err != nil {
		return db, aoserrors.Wrap(err)
	}

	if !exists {
		// Set database version if database not exist
		if err = migration.SetDatabaseVersion(sqlite, config.Migration.MigrationPath, dbVersion); err != nil {
			return db, aoserrors.Wrap(err)
		}

		if err := db.createConfigTable(); err != nil {
			return db, aoserrors.Wrap(err)
		}
	} else {
		if err = migration.DoMigrate(db.sql, config.Migration.MergedMigrationPath, dbVersion); err != nil {
			return db, aoserrors.Wrap(err)
		}
	}

	if err := db.createServiceTable(); err != nil {
		return db, aoserrors.Wrap(err)
	}

	if err := db.createLayersTable(); err != nil {
		return db, aoserrors.Wrap(err)
	}

	return db, nil
}

// SetJournalCursor stores system logger cursor.
func (db *Database) SetJournalCursor(cursor string) (err error) {
	result, err := db.sql.Exec("UPDATE config SET cursor = ?", cursor)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return aoserrors.Wrap(errNotExist)
	}

	return nil
}

// GetJournalCursor retrieves logger cursor.
func (db *Database) GetJournalCursor() (cursor string, err error) {
	stmt, err := db.sql.Prepare("SELECT cursor FROM config")
	if err != nil {
		return cursor, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	err = stmt.QueryRow().Scan(&cursor)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return cursor, aoserrors.Wrap(errNotExist)
		}

		return cursor, aoserrors.Wrap(err)
	}

	return cursor, nil
}

// SetComponentsUpdateInfo store update data for update managers.
func (db *Database) SetComponentsUpdateInfo(updateInfo []umcontroller.SystemComponent) (err error) {
	dataJSON, err := json.Marshal(&updateInfo)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	result, err := db.sql.Exec("UPDATE config SET componentsUpdateInfo = ?", dataJSON)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return errNotExist
	}

	return nil
}

// GetComponentsUpdateInfo returns update data for system components.
func (db *Database) GetComponentsUpdateInfo() (updateInfo []umcontroller.SystemComponent, err error) {
	stmt, err := db.sql.Prepare("SELECT componentsUpdateInfo FROM config")
	if err != nil {
		return updateInfo, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	var dataJSON []byte

	if err = stmt.QueryRow().Scan(&dataJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return updateInfo, errNotExist
		}

		return updateInfo, aoserrors.Wrap(err)
	}

	if dataJSON == nil {
		return updateInfo, nil
	}

	if len(dataJSON) == 0 {
		return updateInfo, nil
	}

	if err = json.Unmarshal(dataJSON, &updateInfo); err != nil {
		return updateInfo, aoserrors.Wrap(err)
	}

	return updateInfo, nil
}

// SetFirmwareUpdateState sets FOTA update state.
func (db *Database) SetFirmwareUpdateState(state json.RawMessage) (err error) {
	result, err := db.sql.Exec("UPDATE config SET fotaUpdateState = ?", state)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return errNotExist
	}

	return nil
}

// GetFirmwareUpdateState returns FOTA update state.
func (db *Database) GetFirmwareUpdateState() (state json.RawMessage, err error) {
	stmt, err := db.sql.Prepare("SELECT fotaUpdateState FROM config")
	if err != nil {
		return state, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	if err = stmt.QueryRow().Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, errNotExist
		}

		return state, aoserrors.Wrap(err)
	}

	return state, nil
}

// SetSoftwareUpdateState sets SOTA update state.
func (db *Database) SetSoftwareUpdateState(state json.RawMessage) (err error) {
	result, err := db.sql.Exec("UPDATE config SET sotaUpdateState = ?", state)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return errNotExist
	}

	return nil
}

// GetSoftwareUpdateState returns SOTA update state.
func (db *Database) GetSoftwareUpdateState() (state json.RawMessage, err error) {
	stmt, err := db.sql.Prepare("SELECT sotaUpdateState FROM config")
	if err != nil {
		return state, aoserrors.Wrap(err)
	}
	defer stmt.Close()

	if err = stmt.QueryRow().Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return state, errNotExist
		}

		return state, aoserrors.Wrap(err)
	}

	return state, nil
}

// Close closes database.
func (db *Database) Close() {
	db.sql.Close()
}

// GetServicesInfo returns services info.
func (db *Database) GetServicesInfo() ([]imagemanager.ServiceInfo, error) {
	return db.getServicesFromQuery(`SELECT * FROM services WHERE(id, aosVersion)
                                    IN (SELECT id, MAX(aosVersion) FROM services GROUP BY id)`)
}

// GetServiceInfo returns service info by ID.
func (db *Database) GetServiceInfo(serviceID string) (service imagemanager.ServiceInfo, err error) {
	var (
		configJSON []byte
		layers     []byte
	)

	if err = db.getDataFromQuery(
		"SELECT * FROM services WHERE aosVersion = (SELECT MAX(aosVersion) FROM services WHERE id = ?) AND id = ?",
		[]any{serviceID, serviceID},
		&service.ID, &service.AosVersion, &service.LocalURL, &service.RemoteURL, &service.Path,
		&service.Size, &service.Timestamp, &service.Cached, &configJSON, &layers); err != nil {
		if errors.Is(err, errNotExist) {
			return service, imagemanager.ErrNotExist
		}

		return service, err
	}

	if err = json.Unmarshal(configJSON, &service.Config); err != nil {
		return service, aoserrors.Wrap(err)
	}

	if err = json.Unmarshal(layers, &service.Layers); err != nil {
		return service, aoserrors.Wrap(err)
	}

	return service, nil
}

// AddService adds new service.
func (db *Database) AddService(service imagemanager.ServiceInfo) error {
	configJSON, err := json.Marshal(&service.Config)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	layers, err := json.Marshal(&service.Layers)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	return db.executeQuery("INSERT INTO services values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		service.ID, service.AosVersion, service.LocalURL, service.RemoteURL,
		service.Path, service.Size, service.Timestamp, service.Cached, configJSON, layers)
}

// SetServiceCached sets cached status for the service.
func (db *Database) SetServiceCached(serviceID string, cached bool) (err error) {
	if err = db.executeQuery("UPDATE services SET cached = ? WHERE id = ?",
		cached, serviceID); errors.Is(err, errNotExist) {
		return imagemanager.ErrNotExist
	}

	return err
}

// RemoveService removes existing service.
func (db *Database) RemoveService(serviceID string, aosVersion uint64) (err error) {
	if err = db.executeQuery("DELETE FROM services WHERE id = ? AND aosVersion = ?",
		serviceID, aosVersion); errors.Is(err, errNotExist) {
		return nil
	}

	return err
}

// GetAllServiceVersions returns all service versions.
func (db *Database) GetServiceVersions(serviceID string) (services []imagemanager.ServiceInfo, err error) {
	if services, err = db.getServicesFromQuery(
		"SELECT * FROM services WHERE id = ? ORDER BY aosVersion", serviceID); err != nil {
		return nil, err
	}

	if len(services) == 0 {
		return nil, imagemanager.ErrNotExist
	}

	return services, nil
}

// GetLayersInfo returns layers info.
func (db *Database) GetLayersInfo() ([]imagemanager.LayerInfo, error) {
	return db.getLayersFromQuery("SELECT * FROM layers")
}

// GetLayerInfo returns layer info by ID.
func (db *Database) GetLayerInfo(digest string) (layer imagemanager.LayerInfo, err error) {
	if err = db.getDataFromQuery("SELECT * FROM layers WHERE digest = ?",
		[]any{digest}, &layer.Digest, &layer.ID, &layer.AosVersion, &layer.LocalURL, &layer.RemoteURL,
		&layer.Path, &layer.Size, &layer.Timestamp, &layer.Cached); err != nil {
		if errors.Is(err, errNotExist) {
			return layer, imagemanager.ErrNotExist
		}

		return layer, err
	}

	return layer, nil
}

// AddLayer adds new layer.
func (db *Database) AddLayer(layer imagemanager.LayerInfo) error {
	return db.executeQuery("INSERT INTO layers values(?, ?, ?, ?, ?, ?, ?, ?, ?)",
		layer.Digest, layer.ID, layer.AosVersion, layer.LocalURL, layer.RemoteURL,
		layer.Path, layer.Size, layer.Timestamp, layer.Cached)
}

// SetLayerCached sets cached status for the layer.
func (db *Database) SetLayerCached(digest string, cached bool) (err error) {
	if err = db.executeQuery("UPDATE layers SET cached = ? WHERE digest = ?",
		cached, digest); errors.Is(err, errNotExist) {
		return imagemanager.ErrNotExist
	}

	return err
}

// RemoveLayer removes existing layer.
func (db *Database) RemoveLayer(digest string) (err error) {
	if err = db.executeQuery("DELETE FROM layers WHERE digest = ?", digest); errors.Is(err, errNotExist) {
		return nil
	}

	return err
}

/***********************************************************************************************************************
 * Private
 **********************************************************************************************************************/

func (db *Database) isTableExist(name string) (result bool, err error) {
	rows, err := db.sql.Query("SELECT * FROM sqlite_master WHERE name = ? and type='table'", name)
	if err != nil {
		return false, aoserrors.Wrap(err)
	}
	defer rows.Close()

	result = rows.Next()

	return result, aoserrors.Wrap(rows.Err())
}

func (db *Database) createConfigTable() (err error) {
	log.Info("Create config table")

	if _, err = db.sql.Exec(
		`CREATE TABLE config (
			cursor TEXT,
			componentsUpdateInfo BLOB,
			fotaUpdateState BLOB,
			sotaUpdateState BLOB)`); err != nil {
		return aoserrors.Wrap(err)
	}

	if _, err = db.sql.Exec(
		`INSERT INTO config (
			cursor,
			componentsUpdateInfo,
			fotaUpdateState,
			sotaUpdateState) values(?, ?, ?, ?)`, "", "", json.RawMessage{}, json.RawMessage{}); err != nil {
		return aoserrors.Wrap(err)
	}

	return nil
}

func (db *Database) createServiceTable() (err error) {
	log.Info("Create service table")

	_, err = db.sql.Exec(`CREATE TABLE IF NOT EXISTS services (id TEXT NOT NULL ,
                                                               aosVersion INTEGER,
                                                               localURL   TEXT,
                                                               remoteURL  TEXT,
                                                               path TEXT,
                                                               size INTEGER,
                                                               timestamp TIMESTAMP,
                                                               cached INTEGER,
                                                               config BLOB,
                                                               layers BLOB,
                                                               PRIMARY KEY(id, aosVersion))`)

	return aoserrors.Wrap(err)
}

func (db *Database) createLayersTable() (err error) {
	log.Info("Create layers table")

	_, err = db.sql.Exec(`CREATE TABLE IF NOT EXISTS layers (digest TEXT NOT NULL PRIMARY KEY,
                                                             layerId TEXT,
                                                             aosVersion INTEGER,
                                                             localURL   TEXT,
                                                             remoteURL  TEXT,
                                                             Path       TEXT,
                                                             Size       INTEGER,
                                                             Timestamp  TIMESTAMP,
                                                             cached INTEGER)`)

	return aoserrors.Wrap(err)
}

func (db *Database) getDataFromQuery(query string, queryParams []any, result ...interface{}) error {
	stmt, err := db.sql.Prepare(query)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer stmt.Close()

	if err = stmt.QueryRow(queryParams...).Scan(result...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errNotExist
		}

		return aoserrors.Wrap(err)
	}

	return nil
}

func (db *Database) executeQuery(query string, args ...interface{}) error {
	stmt, err := db.sql.Prepare(query)
	if err != nil {
		return aoserrors.Wrap(err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(args...)
	if err != nil {
		return aoserrors.Wrap(err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return aoserrors.Wrap(err)
	}

	if count == 0 {
		return aoserrors.Wrap(errNotExist)
	}

	return nil
}

func (db *Database) getServicesFromQuery(
	query string, args ...interface{},
) (services []imagemanager.ServiceInfo, err error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return services, aoserrors.Wrap(err)
	}
	defer rows.Close()

	if rows.Err() != nil {
		return nil, aoserrors.Wrap(rows.Err())
	}

	for rows.Next() {
		var (
			service    imagemanager.ServiceInfo
			configJSON []byte
			layers     []byte
		)

		if err = rows.Scan(
			&service.ID, &service.AosVersion, &service.LocalURL, &service.RemoteURL, &service.Path,
			&service.Size, &service.Timestamp, &service.Cached, &configJSON, &layers); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = json.Unmarshal(configJSON, &service.Config); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		if err = json.Unmarshal(layers, &service.Layers); err != nil {
			return nil, aoserrors.Wrap(err)
		}

		services = append(services, service)
	}

	return services, nil
}

func (db *Database) getLayersFromQuery(
	query string, args ...interface{},
) (layers []imagemanager.LayerInfo, err error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return layers, aoserrors.Wrap(err)
	}
	defer rows.Close()

	if rows.Err() != nil {
		return nil, aoserrors.Wrap(rows.Err())
	}

	for rows.Next() {
		var layer imagemanager.LayerInfo

		if err = rows.Scan(
			&layer.Digest, &layer.ID, &layer.AosVersion, &layer.LocalURL, &layer.RemoteURL,
			&layer.Path, &layer.Size, &layer.Timestamp, &layer.Cached,
		); err != nil {
			return layers, aoserrors.Wrap(err)
		}

		layers = append(layers, layer)
	}

	return layers, nil
}
