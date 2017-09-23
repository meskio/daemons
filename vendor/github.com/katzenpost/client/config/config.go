// config.go - mixnet client configuration
// Copyright (C) 2017  David Anthony Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package provides mixnet client configuration utilities
package config

import (
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/client/crypto/vault"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/op/go-logging"
	"github.com/pelletier/go-toml"
)

var log = logging.MustGetLogger("mixclient")

// Account is used to deserialize the account sections
// of the configuration file.
type Account struct {
	// Name is the first part of an e-mail address
	// before the @-sign.
	Name string
	// Provider is the second part of an e-mail address
	// after the @-sign.
	Provider string
}

// ProviderPinning is used to deserialize the
// provider pinning sections of the configuration file
type ProviderPinning struct {
	// PublicKeyFile is the file path of the key file
	PublicKeyFile string
	// Name is the name of the Provider
	Name string
}

// Proxy is used to deserialize the proxy
// configuration sections of the configuration
// for the SMTP and POP3 proxies.
type Proxy struct {
	// Network is the transport type e.g. "tcp"
	Network string
	// Address is the transport address
	Address string
}

// Config is used to deserialize the configuration file
type Config struct {
	// Account is the list of accounts represented by this client configuration
	Account []Account
	// ProviderPinning is an optional list of pinned Provider public keys
	ProviderPinning []ProviderPinning
	// SMTPProxy is the transport configuration of the SMTP submission proxy
	SMTPProxy Proxy
	// POP3Proxy is the transport configuration of the POP3 receive proxy
	POP3Proxy Proxy
}

// AccountsMap map of email to user private key
// for each account that is used
type AccountsMap map[string]*ecdh.PrivateKey

// GetIdentityKey returns a private key corresponding to the
// given lower cased identity/email
func (a *AccountsMap) GetIdentityKey(email string) (*ecdh.PrivateKey, error) {
	key, ok := (*a)[strings.ToLower(email)]
	if ok {
		return key, nil
	}
	return nil, errors.New("identity key not found")
}

// CreateKeyFileName composes a filename given several arguments
// arguments:
// * keysDir - a filepath to the directory containing the key files.
//   must not end in a forward slash /.
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * name - name of the account, first section of an e-mail address before the @-sign.
// * provider - the Provider name, the second section of an e-mail address after the @-sign.
// * keyStatus - indicates weather the key is public or private and should be set to
//   on of the following constants:
//   * constants.KeyStatusPrivate
//   * constants.KeyStatusPublic
func CreateKeyFileName(keysDir, keyType, name, provider, keyStatus string) string {
	return fmt.Sprintf("%s/%s_%s@%s.%s.pem", keysDir, keyType, name, provider, keyStatus)
}

// GetAccountKey decrypts and returns a private key material or an error
// arguments:
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * account - an instance of the Account struct
// * keysDir - a filepath to the directory containing the key files.
//   must not end in a forward slash /.
// * passphrase - a secret passphrase which is used to decrypt keys on disk
func (c *Config) GetAccountKey(keyType string, account Account, keysDir, passphrase string) (*ecdh.PrivateKey, error) {
	privateKeyFile := CreateKeyFileName(keysDir, keyType, account.Name, account.Provider, constants.KeyStatusPrivate)
	email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
	v := vault.Vault{
		Type:       constants.KeyStatusPrivate,
		Email:      email,
		Passphrase: passphrase,
		Path:       privateKeyFile,
	}
	plaintext, err := v.Open()
	if err != nil {
		return nil, err
	}
	key := ecdh.PrivateKey{}
	key.FromBytes(plaintext)
	return &key, nil
}

// AccountsMap returns an Accounts struct which contains
// a map of email to private key for each account
// arguments:
// * keyType - indicates weather the key is used for end to end crypto or
//   wire protocol link layer crypto and should be set to one of the following:
//   * constants.EndToEndKeyType
//   * constants.LinkLayerKeyType
// * keysDir - a filepath to the directory containing the key files.
//   must not end in a forward slash /.
// * passphrase - a secret passphrase which is used to decrypt keys on disk
func (c *Config) AccountsMap(keyType, keysDir, passphrase string) (*AccountsMap, error) {
	accounts := make(AccountsMap)
	for _, account := range c.Account {
		email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
		privateKey, err := c.GetAccountKey(keyType, account, keysDir, passphrase)
		if err != nil {
			return nil, err
		}
		accounts[strings.ToLower(email)] = privateKey
	}
	return &accounts, nil
}

// AccountIdentities returns a list of e-mail addresses or
// account identities which the user has configured
func (c *Config) AccountIdentities() []string {
	accounts := []string{}
	for _, account := range c.Account {
		email := fmt.Sprintf("%s@%s", account.Name, account.Provider)
		accounts = append(accounts, email)
	}
	return accounts
}

// writeKey generates and encrypts a key to disk
func writeKey(keysDir, prefix, name, provider, passphrase string) error {
	privateKeyFile := CreateKeyFileName(keysDir, prefix, name, provider, constants.KeyStatusPrivate)
	_, err := os.Stat(privateKeyFile)
	if os.IsNotExist(err) {
		privateKey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		email := fmt.Sprintf("%s@%s", name, provider)
		v := vault.Vault{
			Type:       constants.KeyStatusPrivate,
			Email:      email,
			Passphrase: passphrase,
			Path:       privateKeyFile,
		}
		log.Notice("performing key stretching computation")
		err = v.Seal(privateKey.Bytes())
		if err != nil {
			return err
		}
		return nil
	} else {
		return errors.New("key file already exists. aborting")
	}
}

func SplitEmail(email string) (string, string, error) {
	fields := strings.Split(email, "@")
	if len(fields) != 2 {
		return "", "", errors.New("splitEmail: email format invalid")
	}
	return fields[0], fields[1], nil
}

func FromFile(fileName string) (*Config, error) {
	config := Config{}
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	err = toml.Unmarshal([]byte(fileData), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// GenerateKeys creates the key files necessary to use the client
func (c *Config) GenerateKeys(keysDir, passphrase string) error {
	var err error
	for i := 0; i < len(c.Account); i++ {
		name := c.Account[i].Name
		provider := c.Account[i].Provider
		if name != "" && provider != "" {
			err = writeKey(keysDir, constants.LinkLayerKeyType, name, provider, passphrase)
			if err != nil {
				return err
			}
			err = writeKey(keysDir, constants.EndToEndKeyType, name, provider, passphrase)
			if err != nil {
				return err
			}
		} else {
			return errors.New("received nil Account name or provider")
		}
	}
	return nil
}

// GetProviderPins returns a mapping of
// identity string to public key
func (c *Config) GetProviderPinnedKeys() (map[[255]byte]*ecdh.PublicKey, error) {
	pinnings := c.ProviderPinning
	keysMap := make(map[[255]byte]*ecdh.PublicKey)
	for i := 0; i < len(pinnings); i++ {
		name := pinnings[i].Name
		pemPayload, err := ioutil.ReadFile(pinnings[i].PublicKeyFile)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(pemPayload)
		if block == nil {
			return nil, err
		}
		publicKey := new(ecdh.PublicKey)
		publicKey.FromBytes(block.Bytes)
		nameField := [255]byte{}
		copy(nameField[:], name)
		keysMap[nameField] = publicKey
	}
	return keysMap, nil
}
