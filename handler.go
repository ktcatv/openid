package openid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chassis/foundation/httputil"
	"github.com/go-chassis/go-chassis/v2/core"
	"github.com/go-chassis/go-chassis/v2/core/common"
	"github.com/go-chassis/go-chassis/v2/core/handler"
	"github.com/go-chassis/go-chassis/v2/core/invocation"
	"github.com/go-chassis/go-chassis/v2/core/status"
	"github.com/go-chassis/go-chassis/v2/server/restful"
	"github.com/go-chassis/openlog"
	"github.com/ktcatv/openid/iam"
	"github.com/ktcatv/openid/restfulext"
)

//errors
var (
	ErrNoHeader    = errors.New("no authorization in header")
	ErrInvalidAuth = errors.New("invalid authentication")
)

//Handler is is a openid interceptor
type Handler struct {
}

//Handle intercept unauthorized request
// TODO: 似乎应重定向到登录界面
func (h *Handler) Handle(chain *handler.Chain, i *invocation.Invocation, cb invocation.ResponseCallBack) {
	var err error
	if auth == nil {
		//openid is not initialized, then skip authentication, do not report error
		chain.Next(i, cb)
		return
	}
	//=====================================================================
	req, route, err := restfulext.GetRoute(i)
	if err != nil {
		openlog.Error(fmt.Sprintf("take route of invocation failed, %s", err.Error()))
		chain.Next(i, cb)
		return
	}
	if route == nil {
		// 可能出现这样情况 resfulext 版本发生重大变化, 不再匹配
		openlog.Error("restful version of go-chassis has major changes")
		handler.WriteBackErr(err, status.Status(i.Protocol, status.ServiceUnavailable), cb)
		return
	}
	if !mustAuth(req) {
		openlog.Error("skip auth", openlog.WithTags(openlog.Tags{"request": req}))
		chain.Next(i, cb)
		return
	}
	var ai = restfulext.GetAuthItem(route)
	if ai == nil {
		ai = &iam.AuthItem{
			SRO:         strings.Join([]string{i.MicroServiceName, i.SchemaID, i.OperationID}, ":"),
			Description: route.Doc,
		}
	}
	// i.SetHeader("X-SRO", ai.SRO)
	if ignoreAuth, ok := route.Metadata["ignoreAuth"]; ok {
		if ignoreAuth.(bool) {
			chain.Next(i, cb)
			return
		}
	}
	//=====================================================================
	var authorization, tokenType string
	authorization = common.GetXCSEContext(restful.HeaderAuth, req)
	tokenType = common.GetXCSEContext(ContextHeaderAuthorizationType, req)
	if authorization == "" {
		// 处理无授权直接请求(不通过 Edge-Service 代理)
		handler.WriteBackErr(ErrNoHeader, status.Status(i.Protocol, status.Unauthorized), cb)
		return
	}
	var tokenValue string
	if tokenValue, err = handleBearer(authorization); err != nil {
		handler.WriteBackErr(ErrInvalidAuth, status.Status(i.Protocol, status.Unauthorized), cb)
		return
	}
	var idToken *JWTToken
	if idToken, err = verifyToken(tokenType, tokenValue); err != nil {
		handler.WriteBackErr(err, status.Status(i.Protocol, status.Unauthorized), cb)
		return
	}
	// FIXME: Subject为登录用户标识,在账户-密码登录模式下与用户名相同
	// TODO: 验证用户是否存在
	if !isAuthorized(i, idToken) {
		// return
		// handler.WriteBackErr(ErrInvalidAuth, status.Status(i.Protocol, status.Unauthorized), cb)
	}
	i.SetHeader("x-kt-user-id", idToken.Claims.Subject)
	chain.Next(i, cb)
}

func verifySubjectExist(subject string) bool {
	// var err error
	var req *http.Request = &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Path: "/v1/token/query",
		},
		Header: http.Header{},
	}
	req.Header.Add("accept", "*/*")
	req.Header.Add("accept-encoding", "gzip, deflate, br")
	req.Header.Add("connection", "keep-alive")
	// req.Header.Add("content-length", "0")
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1
	buf, err := json.Marshal(map[string]string{
		"subject": subject,
	})
	if err != nil {
		return false
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(buf))

	reply := &http.Response{}

	err = core.NewRPCInvoker().Invoke(
		context.Background(),
		"authentication-server",
		"TokenEndpoint",
		"VERIFY-SUBJECT-EXISTS-FUNCTION",
		req,
		reply,
		core.WithProtocol("rest"),
	)
	if err != nil {
		openlog.Error("do request failed.")
		return false
	}
	defer reply.Body.Close()
	replyByte := httputil.ReadBody(reply)
	if replyByte == nil {
		return false
	}
	// TODO:
	return true
}

func isAuthorized(i *invocation.Invocation, idToken *JWTToken) bool {
	// verifySubjectExist(idToken.Claims.Subject)
	return verifySubjectExist(idToken.Claims.Subject)
}

func verifyToken(tokenType, tokenValue string) (*JWTToken, error) {
	var err error
	if tokenType == AuthorizationTypeAccessToken {
		// 处理使用 ACCESS_TOKEN 直接请求或代理(含透传)访问, 查询 ID_TOKEN
		var data []byte
		if data, err = queryTokenByAccessToken(tokenValue); err != nil {
			return nil, ErrInvalidAuth
		}
		var response *TokenResponse = &TokenResponse{}
		if err = response.Decode(data); err != nil {
			return nil, ErrInvalidAuth
		}
		return response.IDToken, nil
	}
	if tokenType == AuthorizationTypeIDToken {
		// 处理使用 ID_TOKEN 直接请求或代理(含透传)访问, Token 存在签名, 需要验证
		idToken := &JWTToken{}
		idToken.Value = tokenValue
		var claims map[string]interface{}
		if claims, err = openidTokenManager.Verify(tokenValue, auth.SecretFunc); err != nil {
			return nil, ErrInvalidAuth
		}
		buf, _ := json.Marshal(claims)
		if err = json.Unmarshal(buf, &idToken.Claims); err != nil {
			return nil, ErrInvalidAuth
		}
		return idToken, nil
	}
	// 未知授权类型
	return nil, ErrInvalidAuth
}

func handleBearer(tokenValue string) (string, error) {
	if tokens := strings.Split(tokenValue, " "); len(tokens) == 2 {
		if tokens[0] == TokenTypeBearer {
			return tokens[1], nil
		} else {
			return "", ErrInvalidAuth
		}
	} else {
		// 被代理移除 Bearer
		return tokenValue, nil
	}
}

func queryTokenByAccessToken(accessToken string) ([]byte, error) {
	var err error
	var req *http.Request = &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Path:     "/v1/token/query",
			RawQuery: "access_token=" + accessToken,
		},
		Header: http.Header{},
	}
	req.Header.Add("accept", "*/*")
	req.Header.Add("accept-encoding", "gzip, deflate, br")
	req.Header.Add("connection", "keep-alive")
	req.Header.Add("content-length", "0")
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	var reply *http.Response = &http.Response{}
	err = core.NewRPCInvoker().Invoke(context.Background(),
		"authentication-server", "TokenEndpoint", "queryToken",
		req, reply, core.WithProtocol("rest"))
	if err != nil {
		openlog.Error("do request failed.")
		return nil, err
	}
	defer reply.Body.Close()
	message := httputil.ReadBody(reply)
	return message, nil
}

// Name returns the router string
func (h *Handler) Name() string {
	return "openid"
}

func newHandler() handler.Handler {
	return &Handler{}
}

func mustAuth(req *http.Request) bool {
	if auth.MustAuth == nil {
		return true
	}
	return auth.MustAuth(req)
}

func init() {
	err := handler.RegisterHandler("openid", newHandler)
	if err != nil {
		openlog.Error(err.Error())
	}
}
