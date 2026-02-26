package ldap

import (
	"context"
	"crypto/tls"
	"time"
)

// Client knows how to interact with an LDAP server
type Client interface {
	Start()
	StartTLS(*tls.Config) error
	Close()
	IsClosing() bool
	SetTimeout(time.Duration)
	TLSConnectionState() (tls.ConnectionState, bool)

	Bind(username, password string) error
	BindContext(ctx context.Context, username, password string) error
	SimpleBind(*SimpleBindRequest) (*SimpleBindResult, error)
	SimpleBindContext(ctx context.Context, req *SimpleBindRequest) (*SimpleBindResult, error)
	Unbind() error
}
