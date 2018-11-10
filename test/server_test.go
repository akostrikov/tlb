package main

import (
	"flag"
	"net"
	"net/http"
	"testing"
	"time"
)

var serverAddress = flag.String("serverAddress", "127.0.0.1:7777", "server address")

func TestServer(t *testing.T) {
	t.Parallel()
	t.Logf("serverAddress %s", *serverAddress)

	client := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		}}

	resp, err := client.Get("http://" + *serverAddress + "/blank")
	if err != nil {
		t.Fatalf("Get failed with err %v", err)
	}
	defer resp.Body.Close()
}
