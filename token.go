package openid

import (
	"encoding/json"
	"errors"

	goJwt "github.com/dgrijalva/jwt-go"
	"github.com/go-chassis/go-chassis/v2/security/token"
	"github.com/go-chassis/openlog"
)

var openidTokenManager *OpenIDTokenManager

//TokenResponse 查询 ID_TOKEN 的响应信息, 对标 Authentication-Server 实现的 OpenIDToken
type TokenResponse struct {
	TokenType    string        `json:"tokenType"`
	AccessToken  *SessionToken `json:"accessToken"`
	Refreshtoken *SessionToken `json:"refreshToken"`
	IDToken      *JWTToken     `json:"idToken"`
	Scope        []string      `json:"scope"`
}

type SessionToken struct {
	Value                 string                 `json:"value"`
	IssueAt               int64                  `json:"issueAt"`
	ExpiresIn             int64                  `json:"expiresIn"`
	NotBefore             int64                  `json:"notBefore"`
	Username              string                 `json:"username"`
	AdditionalInformation map[string]interface{} `json:"additionalInformation"`
}

type JWTToken struct {
	Claims *JWTClaims `json:"claims"`
	Value  string     `json:"value"`
}

type JWTClaims struct {
	goJwt.StandardClaims

	Authorities           []string               `json:"authorities"`
	AdditionalInformation map[string]interface{} `json:"additionalInformation"`
	Scope                 []string               `json:"scope"`
}

func (r *TokenResponse) Decode(data []byte) error {
	if err := json.Unmarshal(data, r); err != nil {
		return err
	}
	return nil
}

type OpenIDTokenManager struct {
}

func (r *OpenIDTokenManager) Sign(claims map[string]interface{}, secret interface{}, option ...token.Option) (string, error) {
	return "", nil
}

func (r *OpenIDTokenManager) Verify(tokenString string, f token.SecretFunc, opts ...token.Option) (map[string]interface{}, error) {
	o := &token.Options{}
	for _, opt := range opts {
		opt(o)
	}
	idtoken, err := goJwt.Parse(tokenString, func(idtoken *goJwt.Token) (interface{}, error) {
		sm := token.HS256
		if m, ok := idtoken.Method.(*goJwt.SigningMethodRSA); ok {
			if m.Name == "HS256" {
				sm = token.HS256
			} else if m.Name == "RS512" {
				sm = token.RS512
			} else if m.Name == "RS256" {
				sm = token.RS256
			}
		}
		return f(idtoken.Claims, sm)
	})
	if err != nil {
		return nil, err
	}

	var ve *goJwt.ValidationError
	if claims, ok := idtoken.Claims.(goJwt.MapClaims); ok && idtoken.Valid {
		return claims, nil
	} else if ok := errors.As(err, ve); ok {
		if ve.Errors&goJwt.ValidationErrorMalformed != 0 {
			openlog.Error("not a valid jwt")
			return nil, err
		} else if ve.Errors&(goJwt.ValidationErrorExpired|goJwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			openlog.Error("token expired")
			return nil, err
		} else {
			openlog.Error("parse token err:" + err.Error())
			return nil, err
		}
	} else {
		openlog.Error("parse token err:" + err.Error())
		return nil, err
	}
}
