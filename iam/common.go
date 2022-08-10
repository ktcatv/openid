package iam

const (
	MetaKeyAuthItemTag    = "AuthItem" // 元键: 授权项标签
	MetaKeyParamFilterTag = "ParamFilter"
)

type AuthItem struct {
	//ServiceName  string // 服务名
	//ResourceType string // 资源类型
	//Operation    string // 操作
	SRO         string // 服务名:资源类型:操作
	Description string // 描述
}

type LogFilter struct {
	Params     []Field
	ReqFields  []Field
	RespFields []Field
}

type Field struct {
	Orign string // 原始字段名
	Key   string // JSON关键字
}
