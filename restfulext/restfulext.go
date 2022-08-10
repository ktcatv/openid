package restfulext

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"unsafe"

	"github.com/emicklei/go-restful"
	"github.com/go-chassis/go-chassis/v2/core/invocation"
	"github.com/go-chassis/go-chassis/v2/core/server"
	_ "github.com/go-chassis/go-chassis/v2/server/restful"
	"github.com/ktcatv/openid/iam"
)

var routeMap sync.Map

// TODO: go-chassis 的可扩展性有待改进, 为了获取自定义元数据, 费时又耗油

// Container holds a collection of WebServices and a http.ServeMux to dispatch http requests.
// The requests are further dispatched to routes of WebServices using a RouteSelector
type Container struct {
	webServicesLock        sync.RWMutex
	webServices            []*restful.WebService
	ServeMux               *http.ServeMux
	isRegisteredOnRoot     bool
	containerFilters       []restful.FilterFunction
	doNotRecover           bool // default is true
	recoverHandleFunc      restful.RecoverHandleFunction
	serviceErrorHandleFunc restful.ServiceErrorHandleFunction
	router                 restful.RouteSelector // default is a CurlyRouter (RouterJSR311 is a slower alternative)
	contentEncodingEnabled bool                  // default is false
}

func GetRoute(i *invocation.Invocation) (*http.Request, *restful.Route, error) {
	var err error
	var req *http.Request
	if r, ok := i.Args.(*http.Request); ok {
		req = r
	} else if r, ok := i.Args.(*restful.Request); ok {
		req = r.Request
	} else {
		return nil, nil, fmt.Errorf("this handler only works for http request, wrong type: %t", i.Args)
	}
	val, ok := routeMap.Load(i.OperationID)
	if ok {
		return req, val.(*restful.Route), nil
	}
	var svr server.ProtocolServer
	svr, err = server.GetServer(i.Protocol)
	if err != nil {
		return req, nil, err
	}
	con := (*Container)(unsafe.Pointer(reflect.ValueOf(svr).Elem().FieldByName("container").Pointer()))
	// Find best match Route ; err is non nil if no match was found
	var route *restful.Route
	func() {
		defer func() {
			con.webServicesLock.RUnlock()
			if r := recover(); r != nil {
				err = fmt.Errorf("restful version mismatch, important validated!")
			}
		}()
		con.webServicesLock.RLock()
		if _, ok := con.router.(restful.RouteSelector); ok {
			_, route, err = con.router.SelectRoute(con.webServices, req)
		}
	}()
	if err != nil {
		return req, nil, err
	}
	routeMap.Store(i.OperationID, route)
	return req, route, nil
}

func GetAuthItem(route *restful.Route) *iam.AuthItem {
	var v interface{}
	var ok bool
	if v, ok = route.Metadata[iam.MetaKeyAuthItemTag]; ok {
		if v != nil {
			ai := (*iam.AuthItem)(unsafe.Pointer(reflect.ValueOf(v).Pointer()))
			return ai
		}
	}
	return nil
}

func GetLogFilter(route *restful.Route) *iam.LogFilter {
	var v interface{}
	var ok bool
	if v, ok = route.Metadata[iam.MetaKeyParamFilterTag]; ok {
		if v != nil {
			pf := (*iam.LogFilter)(unsafe.Pointer(reflect.ValueOf(v).Pointer()))
			return pf
		}
	}
	return nil
}
