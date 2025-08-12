/*
 *
 *  * Licensed to the Apache Software Foundation (ASF) under one or more
 *  * contributor license agreements.  See the NOTICE file distributed with
 *  * this work for additional information regarding copyright ownership.
 *  * The ASF licenses this file to You under the Apache License, Version 2.0
 *  * (the "License"); you may not use this file except in compliance with
 *  * the License.  You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package websocketproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const (
	WsScheme  = "ws"
	WssScheme = "wss"
	BufSize   = 1024 * 32
)

var ErrFormatAddr = errors.New("remote websockets addr format error")

type WebsocketProxy struct {
	// ws, wss
	scheme string
	// The target address: host:port
	remoteAddr string
	// path
	defaultPath string
	tlsc        *tls.Config
	logger      SlogWriter
	// Send handshake before callback
	beforeHandshake func(r *http.Request) error
}

type Options func(wp *WebsocketProxy)

// You must carry a port number，ws://ip:80/ssss, wss://ip:443/aaaa
// ex: ws://ip:port/ajaxchattest
func NewProxy(addr string, options ...Options) (*WebsocketProxy, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, ErrFormatAddr
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, ErrFormatAddr
	}
	if u.Scheme != WsScheme && u.Scheme != WssScheme {
		return nil, ErrFormatAddr
	}
	wp := &WebsocketProxy{
		scheme:      u.Scheme,
		remoteAddr:  fmt.Sprintf("%s:%s", host, port),
		defaultPath: u.Path,
		logger:      NullLogger{},
	}
	if u.Scheme == WssScheme {
		wp.tlsc = &tls.Config{InsecureSkipVerify: true}
	}
	for op := range options {
		options[op](wp)
	}
	return wp, nil
}

func (wp *WebsocketProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	wp.Proxy(writer, request)
}

func (wp *WebsocketProxy) Proxy(writer http.ResponseWriter, request *http.Request) {
	if strings.ToLower(request.Header.Get("Connection")) != "upgrade" ||
		strings.ToLower(request.Header.Get("Upgrade")) != "websocket" {
		msg := "must be a websocket request"
		slog.Error(msg)
		http.Error(writer, msg, http.StatusExpectationFailed)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		msg := "request does not satisfy the http.Hijacker interface"
		slog.Error(msg)
		http.Error(writer, msg, http.StatusBadRequest)
		return
	}

	connRW, _, err := hijacker.Hijack()
	if err != nil {
		msg := fmt.Errorf("could not hijack the request. %w", err)
		slog.Error(msg.Error())
		fmt.Fprint(writer, msg.Error())
		return
	}
	defer connRW.Close()

	connR := io.TeeReader(connRW, wp.logger.Direction("response"))

	req := request.Clone(request.Context())
	req.URL.Path, req.URL.RawPath, req.RequestURI = wp.defaultPath, wp.defaultPath, wp.defaultPath
	req.Host = wp.remoteAddr
	if wp.beforeHandshake != nil {
		// Add headers, permission authentication + masquerade sources
		err = wp.beforeHandshake(req)
		if err != nil {
			msg := fmt.Errorf("error returned by callback: %w", err)
			slog.Error(msg.Error())
			fmt.Fprint(writer, msg.Error())
			return
		}
	}
	var remoteConnRW net.Conn
	switch wp.scheme {
	case WsScheme:
		remoteConnRW, err = net.Dial("tcp", wp.remoteAddr)
	case WssScheme:
		remoteConnRW, err = tls.Dial("tcp", wp.remoteAddr, wp.tlsc)
	}
	if err != nil {
		msg := fmt.Errorf("problem dialing remote: %w", err.Error())
		slog.Error(msg.Error())
		fmt.Fprint(writer, msg.Error())
		return
	}
	defer remoteConnRW.Close()
	err = req.Write(remoteConnRW)
	if err != nil {
		msg := fmt.Errorf("remote write err: %w", err)
		slog.Error(msg.Error())
		fmt.Fprint(writer, msg.Error())
		return
	}

	remoteConnR := io.TeeReader(remoteConnRW, wp.logger.Direction("request"))

	errChan := make(chan error, 2)
	copyConn := func(a io.Writer, b io.Reader) {
		buf := ByteSliceGet(BufSize)
		defer ByteSlicePut(buf)
		_, err := io.CopyBuffer(a, b, buf)
		errChan <- err
	}
	go copyConn(connRW, remoteConnR) // response
	go copyConn(remoteConnRW, connR) // request

	err = <-errChan
	if err != nil {
		slog.Error(err.Error())
		fmt.Fprint(writer, err.Error())
	}
}

func SetTLSConfig(tlsc *tls.Config) Options {
	return func(wp *WebsocketProxy) {
		wp.tlsc = tlsc
	}
}

func SetLogger(l SlogWriter) Options {
	return func(wp *WebsocketProxy) {
		if l != nil {
			wp.logger = l
		}
	}
}

func SetBeforeCallback(cb func(r *http.Request) error) Options {
	return func(wp *WebsocketProxy) {
		wp.beforeHandshake = cb
	}
}

type SlogWriter interface {
	Direction(string) io.Writer
}

type NullLogger struct{}

func (m NullLogger) Direction(_ string) io.Writer {
	return io.Discard
}

type FullLogger struct {
	*slog.Logger
}

func (m FullLogger) Direction(name string) io.Writer {
	return &FullLogger{slog.With(name)}
}

func (m *FullLogger) Write(v []byte) (int, error) {
	m.Logger.Debug(string(v))
	return len(v), nil
}
