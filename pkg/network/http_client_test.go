package network

import (
	"context"

	"testing"

	"github.com/openimsdk/openim-sdk-core/v3/pkg/ccontext"
	"github.com/openimsdk/openim-sdk-core/v3/sdk_struct"
)

func TestName(t *testing.T) {
	conf := ccontext.GlobalConfig{
		IMConfig: &sdk_struct.IMConfig{ApiAddr: "http://127.0.0.1:8080"},
	}
	ctx := ccontext.WithInfo(context.Background(), &conf)
	ctx = ccontext.WithOperationID(ctx, "123456")
	var resp any
	if err := ApiPost(ctx, "/test", map[string]any{}, &resp); err != nil {
		t.Log(err)
		return
	}
	t.Log("success")
}
