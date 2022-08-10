package openid

import (
	"net/http"
	"time"

	"github.com/go-chassis/go-chassis/v2/security/token"
	"github.com/go-chassis/openlog"
)

const (
	// HeaderAuthorizationType        = "Authorization-Type"
	// AuthorizationTypeIDToken       = "ID_TOKEN"
	// AuthorizationTypeAccessToken   = "ACCESS_TOKEN"
	// TokenTypeBearer                = "Bearer"
	ContextHeaderAuthorizationType = "Authorization-TYPE"
	AuthorizationTypeIDToken       = "ID_TOKEN"
	AuthorizationTypeAccessToken   = "ACCESS_TOKEN"
	TokenTypeBearer                = "Bearer"
)

var auth *Auth

//Auth should implement auth logic
//it is singleton
type Auth struct {
	SecretFunc token.SecretFunc //required
	Expire     time.Duration
	Realm      string //required

	//optional. Authorize check whether this request could access some resource or API based on json claims.
	//Typically, this method should communicate with a RBAC, ABAC system
	Authorize func(payload map[string]interface{}, req *http.Request) error

	//optional.
	// this function control whether a request should be validate or not
	// if this func is nil, validate all requests.
	MustAuth func(req *http.Request) bool
}

//Use put a custom auth logic
//then register handler to chassis
func Use(middleware *Auth) {
	auth = middleware
	if auth.Expire == 0 {
		openlog.Warn("token issued by service will not expire")
	}
	if auth.MustAuth == nil {
		openlog.Info("auth all requests")
	} else {
		openlog.Warn("under some condition, no auth")
	}
}

//SetExpire reset the expire time
func SetExpire(duration time.Duration) {
	auth.Expire = duration
}
