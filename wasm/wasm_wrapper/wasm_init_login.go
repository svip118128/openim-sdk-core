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

//go:build js && wasm
// +build js,wasm

package wasm_wrapper

import (
	"errors"
	"syscall/js"

	"github.com/openimsdk/openim-sdk-core/v3/open_im_sdk"
	"github.com/openimsdk/openim-sdk-core/v3/pkg/utils"
	"github.com/openimsdk/openim-sdk-core/v3/wasm/event_listener"
)

const COMMONEVENTFUNC = "commonEventFunc"

var ErrArgsLength = errors.New("from javascript args length err")
var ErrFunNameNotSet = errors.New("reflect func not to set")

type SetListener struct {
	*WrapperCommon
}

func NewSetListener(wrapperCommon *WrapperCommon) *SetListener {
	return &SetListener{WrapperCommon: wrapperCommon}
}

func (s *SetListener) setConversationListener() {
	callback := event_listener.NewConversationCallback(s.commonFunc)
	open_im_sdk.SetConversationListener(callback)
}
func (s *SetListener) setAdvancedMsgListener() {
	callback := event_listener.NewAdvancedMsgCallback(s.commonFunc)
	open_im_sdk.SetAdvancedMsgListener(callback)
}

func (s *SetListener) setFriendListener() {
	callback := event_listener.NewFriendCallback(s.commonFunc)
	open_im_sdk.SetFriendListener(callback)
}

func (s *SetListener) setGroupListener() {
	callback := event_listener.NewGroupCallback(s.commonFunc)
	open_im_sdk.SetGroupListener(callback)
}

func (s *SetListener) setUserListener() {
	callback := event_listener.NewUserCallback(s.commonFunc)
	open_im_sdk.SetUserListener(callback)
}

func (s *SetListener) setSignalingListener() {
	//callback := event_listener.NewSignalingCallback(s.commonFunc)
	//open_im_sdk.SetSignalingListener(callback)
}
func (s *SetListener) setCustomBusinessListener() {
	callback := event_listener.NewCustomBusinessCallback(s.commonFunc)
	open_im_sdk.SetCustomBusinessListener(callback)
}

func (s *SetListener) SetAllListener() {
	s.setConversationListener()
	s.setAdvancedMsgListener()
	s.setFriendListener()
	s.setGroupListener()
	s.setUserListener()
	s.setSignalingListener()
	s.setCustomBusinessListener()
}

type WrapperCommon struct {
	commonFunc *js.Value
}

func NewWrapperCommon() *WrapperCommon {
	return &WrapperCommon{}
}
func (w *WrapperCommon) CommonEventFunc(_ js.Value, args []js.Value) interface{} {
	if len(args) >= 1 {
		w.commonFunc = &args[len(args)-1]
		return js.ValueOf(true)
	} else {
		return js.ValueOf(false)
	}
}

type WrapperInitLogin struct {
	*WrapperCommon
}

func NewWrapperInitLogin(wrapperCommon *WrapperCommon) *WrapperInitLogin {
	return &WrapperInitLogin{WrapperCommon: wrapperCommon}
}
func (w *WrapperInitLogin) InitSDK(_ js.Value, args []js.Value) interface{} {
	callback := event_listener.NewConnCallback(utils.FirstLower(utils.GetSelfFuncName()), w.commonFunc)
	return js.ValueOf(event_listener.NewCaller(open_im_sdk.InitSDK, callback, &args).SyncCall())
}
func (w *WrapperInitLogin) Login(_ js.Value, args []js.Value) interface{} {
	listener := NewSetListener(w.WrapperCommon)
	listener.SetAllListener()
	callback := event_listener.NewBaseCallback(utils.FirstLower(utils.GetSelfFuncName()), w.commonFunc)
	return event_listener.NewCaller(open_im_sdk.Login, callback, &args).AsyncCallWithCallback()
}
func (w *WrapperInitLogin) Logout(_ js.Value, args []js.Value) interface{} {
	callback := event_listener.NewBaseCallback(utils.FirstLower(utils.GetSelfFuncName()), w.commonFunc)
	return event_listener.NewCaller(open_im_sdk.Logout, callback, &args).AsyncCallWithCallback()
}

func (w *WrapperInitLogin) NetworkStatusChanged(_ js.Value, args []js.Value) interface{} {
	callback := event_listener.NewBaseCallback(utils.FirstLower(utils.GetSelfFuncName()), w.commonFunc)
	return event_listener.NewCaller(open_im_sdk.NetworkStatusChanged, callback, &args).AsyncCallWithCallback()
}
func (w *WrapperInitLogin) GetLoginStatus(_ js.Value, args []js.Value) interface{} {
	return event_listener.NewCaller(open_im_sdk.GetLoginStatus, nil, &args).AsyncCallWithOutCallback()
}
func (w *WrapperInitLogin) SetAppBackgroundStatus(_ js.Value, args []js.Value) interface{} {
	callback := event_listener.NewBaseCallback(utils.FirstLower(utils.GetSelfFuncName()), w.commonFunc)
	return event_listener.NewCaller(open_im_sdk.SetAppBackgroundStatus, callback, &args).AsyncCallWithCallback()
}

func (w *WrapperCommon) SetCustomHTTPHeader(this js.Value, args []js.Value) interface{} {
	// 1. 入参校验：JS 必须传入一个对象（headers 键值对）
	if len(args) < 1 || !args[0].IsObject() {
		// JS 端需要错误信息，返回标准错误格式（和其他 SDK 方法一致）
		return js.ValueOf(map[string]interface{}{
			"errCode": -1,
			"errMsg":  "参数错误：必须传入一个对象（格式：{ 'Authorization': 'xxx', 'X-Device-Id': 'xxx' }）",
		})
	}

	// 2. 将 JS 对象转换为 Go 的 map[string]string（适配核心层方法参数）
	customHeaders := make(map[string]string)
	// 获取 JS 对象的所有 key（JS 对象没有原生 keys() 时，用这个兼容写法）
	keys := js.Global().Get("Object").Call("keys", args[0])
	for i := 0; i < keys.Length(); i++ {
		key := keys.Index(i).String()
		value := args[0].Get(key).String() // JS 值转 Go 字符串
		customHeaders[key] = value
	}

	// 3. 调用 Go 核心层的 SetCustomHTTPHeader 方法
	open_im_sdk.SetCustomHTTPHeader(customHeaders)

	// 4. 返回成功结果（JS 端可拿到是否设置成功）
	return js.ValueOf(map[string]interface{}{
		"errCode": 0,
		"errMsg":  "自定义 HTTP 头部设置成功",
	})
}