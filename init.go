package openid

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"

	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chassis/go-archaius"
	"github.com/go-chassis/openlog"
)

const (
	AuthenticationNeedAuth     = "servicecomb.authentication.access.needAuth"
	AuthenticationSignKeyStore = "servicecomb.authentication.sign.keyStore"
	AuthenticationSignKeyCert  = "servicecomb.authentication.sign.cert"
)

var (
	pvtKey *rsa.PrivateKey
	pubKey *rsa.PublicKey
)

func MustAuth() bool {
	return archaius.GetBool(AuthenticationNeedAuth, false)
}

func GetPublicKey() *rsa.PublicKey {
	return pubKey
}

func Init() error {
	var err error
	var pvtKeyPath, pubKeyPath string
	var buf []byte
	if !MustAuth() {
		return nil
	}
	keyStoreValue := archaius.GetValue(AuthenticationSignKeyStore)
	if pvtKeyPath, err = keyStoreValue.ToString(); err != nil {
		openlog.Warn("", openlog.WithErr(err))
	} else {
		if buf, err = ioutil.ReadFile(pvtKeyPath); err != nil {
			openlog.Warn("", openlog.WithErr(err))
			return err
		}
		if pvtKey, err = goJwt.ParseRSAPrivateKeyFromPEM(buf); err != nil {
			openlog.Warn("", openlog.WithErr(err))
			return err
		}
		fmt.Printf("KeyStore: %+v\n", pvtKey)
	}
	certValue := archaius.GetValue(AuthenticationSignKeyCert)
	if pubKeyPath, err = certValue.ToString(); err != nil {
		openlog.Warn("", openlog.WithErr(err))
	} else {
		if buf, err = ioutil.ReadFile(pubKeyPath); err != nil {
			openlog.Warn("", openlog.WithErr(err))
			return err
		}
		if pubKey, err = goJwt.ParseRSAPublicKeyFromPEM(buf); err != nil {
			openlog.Warn("", openlog.WithErr(err))
			return err
		}
		fmt.Printf("Cert: %+v\n", pubKey)
	}
	return nil
}
