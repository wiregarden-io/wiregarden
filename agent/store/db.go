// Copyright 2020 Cmars Technologies LLC.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

// Package store defines the agent storage backend.
package store

import (
	"crypto/rand"
	"database/sql"
	"os"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/wiregarden-io/wiregarden/api"
	"github.com/wiregarden-io/wiregarden/wireguard"
)

const createSchemaSql = `
create table if not exists iface (
	id integer primary key autoincrement,
	created_at integer,
	updated_at integer,

	api_url text not null,

	net_id text not null,
	net_name text not null,
	net_cidr text not null,

	device_id text not null,
	device_name text not null,
	device_endpoint text not null,
	device_addr text not null,
	public_key text not null,

	listen_port integer
);

create unique index if not exists iface_device_id_unique
on iface(device_id);

create unique index if not exists iface_device_net_name_unique
on iface(net_name, device_name);

create unique index if not exists iface_public_key_unique
on iface(public_key);

create table if not exists peer (
	iface_id integer not null,
	device_id text not null,
	device_name text not null,
	device_endpoint text not null,
	device_addr text not null,
	public_key blob not null,
	foreign key(iface_id) references iface(id)
);

create table if not exists iface_log (
	id integer primary key autoincrement,
	ts integer,
	iface_id integer not null,
	operation text not null,
    state text not null,
	dirty bool not null default false,
    message text not null,
	foreign key(iface_id) references iface(id)
);`

const createSecretSchemaSql = `
create table if not exists secret.iface_secrets (
	iface_id integer primary key,
	key blob not null,
	device_token blob not null
);
`

var zeroKey Key

type secret []byte

func encryptSecret(s []byte, k *Key) (secret, error) {
	if *k == zeroKey {
		return nil, errors.New("missing key")
	}
	var nonce [24]byte
	if _, err := rand.Reader.Read(nonce[:]); err != nil {
		return nil, errors.Wrap(err, "failed to read random bytes")
	}
	return secret(secretbox.Seal(nonce[:], s, &nonce, k)), nil
}

func mustEncryptSecret(s []byte, k *Key) secret {
	sec, err := encryptSecret(s, k)
	if err != nil {
		panic(err)
	}
	return sec
}

func (sv secret) decrypt(k *Key) ([]byte, error) {
	if len(sv) < 24 {
		return nil, errors.New("invalid secret value")
	}
	var nonce [24]byte
	copy(nonce[:], sv[:24])
	decrypted, ok := secretbox.Open(nil, sv[24:], &nonce, k)
	if !ok {
		return nil, errors.New("decrypt failed")
	}
	return decrypted, nil
}

type Store struct {
	db  *sql.DB
	key Key
}

func New(path string, key Key) (*Store, error) {
	secretPath := path + ".secret"
	db, err := ensureDB("file:"+path+"?_fk=true", "file:"+secretPath+"?_fk=true")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to ensure database %q", path)
	}
	_, err = db.Exec(createSchemaSql + createSecretSchemaSql)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create schema")
	}
	err = os.Chmod(path, 0644)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to set permissions on database %q", path)
	}
	err = os.Chmod(secretPath, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to set permissions on database %q", secretPath)
	}
	if err != nil {
		return nil, errors.Wrapf(err, "failed to attach database %q", secretPath)
	}
	return &Store{db: db, key: key}, nil
}

func NewReadOnly(path string) (*Store, error) {
	db, err := ensureDB("file:"+path+"?_fk=true&ro=true", "file::memory:?_fk=true")
	if err != nil {
		return nil, errors.Wrapf(err, "failed to ensure database %q", path)
	}
	_, err = db.Exec(createSecretSchemaSql)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create schema")
	}
	return &Store{db: db}, nil
}

func ensureDB(uri, secretUri string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", uri)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open database %q", uri)
	}
	_, err = db.Exec("attach database ? as secret", secretUri)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to attach database %q", secretUri)
	}
	return db, nil
}

func (st *Store) Close() error {
	return st.db.Close()
}

func (s *Store) EnsureInterface(iface *Interface) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.Wrap(err, "failed to begin transaction")
	}
	defer tx.Rollback()
	err = s.EnsureInterfaceTx(tx, iface)
	if err != nil {
		return errors.WithStack(err)
	}
	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}
	return nil
}

func (s *Store) EnsureInterfaceTx(tx *sql.Tx, iface *Interface) error {
	return backoff.Retry(func() error {
		err := s.ensureInterfaceTx(tx, iface)
		return retryableError(err)
	}, defaultRetryBackOff())
}

func (s *Store) ensureInterfaceTx(tx *sql.Tx, iface *Interface) error {
	now := time.Now().Unix()
	id := sql.NullInt64{}
	if iface.Id > 0 {
		id.Valid = true
		id.Int64 = iface.Id
	} else {
		// Because sqlite only upserts on one conflicting constraint, match
		// the id of any other conflicts ahead of time.
		err := tx.QueryRow(`
select id from iface where public_key = ? or device_id = ? or (net_name = ? and device_name = ?)
`, iface.Device.PublicKey.String(), iface.Device.Id, iface.Network.Name, iface.Device.Name).Scan(&id)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return errors.Wrap(err, "failed to query for existing interfaces")
		}
	}
	result, err := tx.Exec(`
insert into iface (
	id, created_at, updated_at,
	api_url,
	net_id, net_name, net_cidr,
	device_id, device_name, device_endpoint, device_addr, public_key,
	listen_port
)
values (
	?, ?, ?,
	?,
	?, ?, ?,
	?, ?, ?, ?, ?,
	?)
on conflict (id) do update set
	id = excluded.id,
	updated_at = excluded.updated_at,
	api_url = excluded.api_url,
	net_id = excluded.net_id,
	net_name = excluded.net_name,
	net_cidr = excluded.net_cidr,
	device_id = excluded.device_id,
	device_name = excluded.device_name,
	device_endpoint = excluded.device_endpoint,
	device_addr = excluded.device_addr,
	public_key = excluded.public_key,
	listen_port = excluded.listen_port;
`[1:], id, now, now,
		iface.ApiUrl,
		iface.Network.Id, iface.Network.Name, iface.Network.CIDR.String(),
		iface.Device.Id, iface.Device.Name,
		iface.Device.Endpoint, iface.Device.Addr.String(),
		iface.Device.PublicKey.String(),
		iface.ListenPort)
	if err != nil {
		return errors.Wrap(err, "failed to upsert interface")
	}
	if !id.Valid {
		ifaceId, err := result.LastInsertId()
		if err != nil {
			return errors.Wrap(err, "failed to obtain new interface id")
		}
		iface.Id = ifaceId
	} else {
		iface.Id = id.Int64
	}
	_, err = tx.Exec(`
insert into secret.iface_secrets (iface_id, key, device_token)
values (?, ?, ?)
on conflict (iface_id) do update set
	iface_id = excluded.iface_id,
	key = excluded.key,
	device_token = excluded.device_token;
`[1:], iface.Id,
		mustEncryptSecret(iface.Key, &s.key),
		mustEncryptSecret(iface.DeviceToken, &s.key))
	if err != nil {
		return errors.Wrap(err, "failed to upsert interface secrets")
	}
	_, err = tx.Exec(`delete from peer where iface_id = ?`, iface.Id)
	if err != nil {
		return errors.Wrap(err, "failed to replace existing peers")
	}
	for i := range iface.Peers {
		_, err = tx.Exec(`
insert into peer (iface_id, device_id, device_name, device_endpoint, device_addr, public_key)
values (?, ?, ?, ?, ?, ?)`[1:],
			iface.Id, iface.Peers[i].Id, iface.Peers[i].Name, iface.Peers[i].Endpoint,
			iface.Peers[i].Addr.String(), iface.Peers[i].PublicKey.String())
		if err != nil {
			return errors.Wrapf(err, "failed to insert peer %q", iface.Peers[i].Id)
		}
	}
	return nil
}

func (s *Store) Interface(id int64) (*Interface, error) {
	var (
		iface                                      Interface
		netCIDRText, deviceAddrText, publicKeyText string
		keyBytes                                   []byte
		deviceTokenBytes                           []byte
	)
	err := s.db.QueryRow(`
select
	i.api_url,
	i.net_id, i.net_name, i.net_cidr,
	i.device_id, i.device_name, i.device_endpoint, i.device_addr, i.public_key,
	i.listen_port, s.key, s.device_token
from iface i left join secret.iface_secrets s on (i.id = s.iface_id)
where id = ?`[1:], id).Scan(
		&iface.ApiUrl,
		&iface.Network.Id, &iface.Network.Name, &netCIDRText,
		&iface.Device.Id, &iface.Device.Name, &iface.Device.Endpoint, &deviceAddrText, &publicKeyText,
		&iface.ListenPort, &keyBytes, &deviceTokenBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface %q", id)
	}
	iface.Id = id
	// parse net cidr
	netCIDR, err := wireguard.ParseAddress(netCIDRText)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface: invalid network CIDR %q", netCIDRText)
	}
	iface.Network.CIDR = *netCIDR
	// parse device addr
	deviceAddr, err := wireguard.ParseAddress(deviceAddrText)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface: invalid device address %q", deviceAddrText)
	}
	iface.Device.Addr = *deviceAddr
	// parse public key
	publicKey, err := wireguard.ParseKey(publicKeyText)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface: invalid public key %q", publicKeyText)
	}
	iface.Device.PublicKey = publicKey
	if s.key != zeroKey {
		// decrypt key
		keyDecrypted, err := secret(keyBytes).decrypt(&s.key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query interface: failed to decrypt key")
		}
		iface.Key = keyDecrypted
		// decrypt device token
		deviceToken, err := secret(deviceTokenBytes).decrypt(&s.key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query interface: failed to decrypt key")
		}
		iface.DeviceToken = deviceToken
	}

	rows, err := s.db.Query(`
select
	device_id, device_name, device_endpoint, device_addr, public_key
from peer
where iface_id = ?`[1:], iface.Id)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query peers")
	}
	defer rows.Close()
	for rows.Next() {
		var peer api.Device
		var peerAddrText, peerKeyText string
		err := rows.Scan(&peer.Id, &peer.Name, &peer.Endpoint, &peerAddrText, &peerKeyText)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan peer result row")
		}
		peerAddr, err := wireguard.ParseAddress(peerAddrText)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query interface: invalid peer address %q", peerAddrText)
		}
		peer.Addr = *peerAddr
		peerKey, err := wireguard.ParseKey(peerKeyText)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query interface: invalid public key %q", peerKeyText)
		}
		peer.PublicKey = peerKey
		iface.Peers = append(iface.Peers, peer)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to query peers")
	}
	return &iface, nil
}

func (s *Store) InterfaceByDevice(deviceName, networkName string) (*Interface, error) {
	var id int64
	err := s.db.QueryRow(`
select id from iface
where device_name = ? and net_name = ?`[1:], deviceName, networkName).Scan(&id)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface device name %q network name %q", deviceName, networkName)
	}
	iface, err := s.Interface(id)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return iface, nil
}

func (s *Store) WithLog(iface *Interface, f func(tx *sql.Tx, lastLog *InterfaceLog) error) error {
	return backoff.Retry(func() error {
		err := s.withLog(iface, f)
		return retryableError(err)
	}, defaultRetryBackOff())
}

func retryableError(err error) error {
	if err == nil {
		return err
	}
	if cause := errors.Cause(err); cause != nil {
		if sqliteErr, ok := cause.(sqlite3.Error); ok {
			switch sqliteErr.Code {
			case sqlite3.ErrBusy, sqlite3.ErrLocked:
				return err
			}
		}
	}
	return backoff.Permanent(err)
}

func defaultRetryBackOff() backoff.BackOff {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 10 * time.Second
	return b
}

func (s *Store) withLog(iface *Interface, f func(tx *sql.Tx, lastLog *InterfaceLog) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return errors.Wrap(err, "failed to begin transaction")
	}
	defer tx.Rollback()
	lastLog, err := LastLogTx(tx, iface)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lastLog = nil
		} else {
			return errors.Wrapf(err, "failed to query last log for interface %q", iface.Name())
		}
	}
	err = f(tx, lastLog)
	if err != nil {
		return errors.WithStack(err)
	}
	err = tx.Commit()
	if err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}
	return nil
}

func AppendLogTx(tx *sql.Tx, iface *Interface, operation Operation, state State, dirty bool, message string) error {
	_, err := tx.Exec(`
insert into iface_log (ts, iface_id, operation, state, dirty, message)
values (?, ?, ?, ?, ?, ?)`[1:], time.Now().Unix(), iface.Id, operation, state, dirty, message)
	if err != nil {
		return errors.Wrapf(err, "failed to append log for interface %q", iface.Name())
	}
	return nil
}

func (s *Store) LastLogByDevice(deviceName, networkName string) (*InterfaceWithLog, error) {
	var l InterfaceLog
	var ifaceId, ts int64
	err := s.db.QueryRow(`
select
	l.id, l.ts,
	l.operation, l.state, l.dirty, l.message,
	i.id
from iface_log l join iface i on (i.id = l.iface_id)
where i.device_name = ? and i.net_name = ?
order by l.id desc
limit 1`[1:], deviceName, networkName).Scan(
		&l.Id, &ts,
		&l.Operation, &l.State, &l.Dirty, &l.Message,
		&ifaceId)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query interface last log")
	}
	l.Timestamp = time.Unix(ts, 0)
	iface, err := s.Interface(ifaceId)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query interface %d", ifaceId)
	}
	return &InterfaceWithLog{Interface: *iface, Log: l}, nil
}

func (s *Store) Interfaces() ([]InterfaceWithLog, error) {
	var ifaceIds []int64
	rows, err := s.db.Query(`select id from iface`)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query interfaces")
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		err := rows.Scan(&id)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan interface id")
		}
		ifaceIds = append(ifaceIds, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate over interface ids")
	}
	result := make([]InterfaceWithLog, len(ifaceIds))
	for i := range ifaceIds {
		iface, err := s.Interface(ifaceIds[i])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query interface %d", ifaceIds[i])
		}
		result[i] = InterfaceWithLog{Interface: *iface}
		lastLog, err := s.LastLog(iface)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to query last log for interface %d", ifaceIds[i])
		}
		result[i].Log = *lastLog
	}
	return result, nil
}

func (s *Store) LastLog(iface *Interface) (*InterfaceLog, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, errors.Wrap(err, "failed to begin transaction")
	}
	defer tx.Rollback()
	l, err := LastLogTx(tx, iface)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get last log for interface %d", iface.Id)
	}
	return l, nil
}

func LastLogTx(tx *sql.Tx, iface *Interface) (*InterfaceLog, error) {
	var lastLog InterfaceLog
	var ts int64
	err := tx.QueryRow(`
select
	id, ts,
	operation, state, dirty, message
from iface_log
where iface_id = ?
order by id desc
limit 1`[1:], iface.Id).Scan(
		&lastLog.Id, &ts,
		&lastLog.Operation, &lastLog.State, &lastLog.Dirty, &lastLog.Message)
	if err != nil {
		return nil, errors.Wrap(err, "failed to query interface last log")
	}
	lastLog.Timestamp = time.Unix(ts, 0)
	return &lastLog, nil
}
