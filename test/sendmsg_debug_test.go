// Copyright © 2023 OpenIM SDK. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/openimsdk/openim-sdk-core/v3/open_im_sdk"
)

// DebugSendMsgCallback implements SendMsgCallBack for debugging
type DebugSendMsgCallback struct {
	t *testing.T
}

func (d *DebugSendMsgCallback) OnSuccess(data string) {
	d.t.Logf("✅ SendMessage SUCCESS: %s", data)
}

func (d *DebugSendMsgCallback) OnError(code int32, msg string) {
	d.t.Logf("❌ SendMessage ERROR: code=%d, msg=%s", code, msg)
}

func (d *DebugSendMsgCallback) OnProgress(progress int) {
	d.t.Logf("📤 SendMessage PROGRESS: %d%%", progress)
}

// Test_DebugSendTextMessage - Debug sending a text message
func Test_DebugSendTextMessage(t *testing.T) {
	// Set up callback in context
	callback := &DebugSendMsgCallback{t: t}
	debugCtx := context.WithValue(ctx, "callback", callback)

	// Create text message
	t.Log("📝 Creating text message...")
	msg, err := open_im_sdk.IMUserContext.Conversation().CreateTextMessage(debugCtx, "Hello, this is a debug test message!")
	if err != nil {
		t.Fatalf("Failed to create text message: %v", err)
	}
	t.Logf("📝 Message created: ClientMsgID=%s, ContentType=%d", msg.ClientMsgID, msg.ContentType)

	// Target user ID (change this to a valid user)
	targetUserID := "3411008330" // Change to your target user ID

	// Send message
	t.Logf("📤 Sending message to user: %s", targetUserID)
	result, err := open_im_sdk.IMUserContext.Conversation().SendMessage(debugCtx, msg, targetUserID, "", nil, false)
	if err != nil {
		t.Logf("❌ SendMessage returned error: %v", err)
	} else {
		t.Logf("✅ SendMessage returned: ServerMsgID=%s, SendTime=%d, Status=%d", 
			result.ServerMsgID, result.SendTime, result.Status)
	}

	// Wait for async operations
	time.Sleep(time.Second * 3)
}

// Test_DebugSendGroupMessage - Debug sending a group message
func Test_DebugSendGroupMessage(t *testing.T) {
	callback := &DebugSendMsgCallback{t: t}
	debugCtx := context.WithValue(ctx, "callback", callback)

	// Create text message
	t.Log("📝 Creating group text message...")
	msg, err := open_im_sdk.IMUserContext.Conversation().CreateTextMessage(debugCtx, "Hello group, this is a debug test!")
	if err != nil {
		t.Fatalf("Failed to create text message: %v", err)
	}

	// Target group ID (change this to a valid group)
	targetGroupID := "your-group-id" // Change to your target group ID

	// Send message
	t.Logf("📤 Sending message to group: %s", targetGroupID)
	result, err := open_im_sdk.IMUserContext.Conversation().SendMessage(debugCtx, msg, "", targetGroupID, nil, false)
	if err != nil {
		t.Logf("❌ SendMessage returned error: %v", err)
	} else {
		t.Logf("✅ SendMessage returned: ServerMsgID=%s, SendTime=%d", result.ServerMsgID, result.SendTime)
	}

	time.Sleep(time.Second * 3)
}

// Test_DebugSendOnlineOnlyMessage - Debug online-only message (not stored)
func Test_DebugSendOnlineOnlyMessage(t *testing.T) {
	callback := &DebugSendMsgCallback{t: t}
	debugCtx := context.WithValue(ctx, "callback", callback)

	msg, err := open_im_sdk.IMUserContext.Conversation().CreateTextMessage(debugCtx, "Online-only message (not stored)")
	if err != nil {
		t.Fatalf("Failed to create text message: %v", err)
	}

	targetUserID := "3411008330" // Change to your target user ID

	t.Logf("📤 Sending ONLINE-ONLY message to user: %s", targetUserID)
	result, err := open_im_sdk.IMUserContext.Conversation().SendMessage(debugCtx, msg, targetUserID, "", nil, true) // isOnlineOnly = true
	if err != nil {
		t.Logf("❌ SendMessage returned error: %v", err)
	} else {
		t.Logf("✅ SendMessage returned: ServerMsgID=%s, Status=%d", result.ServerMsgID, result.Status)
	}

	time.Sleep(time.Second * 2)
}

// Test_PrintMessageFlow - Print the message sending flow
func Test_PrintMessageFlow(t *testing.T) {
	fmt.Println(`
=== SendMessage Flow ===

1. open_im_sdk.SendMessage() [open_im_sdk/conversation_msg.go:136]
   ↓ calls messageCall() which wraps the function
   
2. messageCall() [open_im_sdk/caller.go:361]
   ↓ sets up context with SendMsgCallBack
   ↓ calls the actual function via reflection
   
3. Conversation.SendMessage() [internal/conversation_msg/api.go:274]
   ↓ checkID() - validates recvID/groupID, builds conversation
   ↓ InsertMessage() - saves to local DB (if !isOnlineOnly)
   ↓ Media upload (if Picture/Sound/Video/File)
   ↓ calls sendMessageToServer()
   
4. sendMessageToServer() [internal/conversation_msg/api.go:626]
   ↓ sets message options
   ↓ converts MsgStruct to sdkws.MsgData (protobuf)
   ↓ calls sendMsg()
   
5. sendMsg() [internal/conversation_msg/api.go:693]
   ↓ calls LongConnMgr.SendReqWaitResp()
   
6. LongConnMgr.SendReqWaitResp() [internal/interaction/long_conn_mgr.go:151]
   ↓ marshals message to protobuf
   ↓ sends to WebSocket send channel
   ↓ waits for response
   
7. writePump() [internal/interaction/long_conn_mgr.go:261]
   ↓ reads from send channel
   ↓ calls sendAndWaitResp()
   
8. Server receives message via WebSocket
   ↓ processes and stores message
   ↓ sends response back
   
9. Response received
   ↓ updateMsgStatusAndTriggerConversation() - updates local DB
   ↓ callback.OnSuccess() called`)
}

