package main

import (
	"flag"
	"net/http"
	"testing"
)

var serverAddress = flag.String("serverAddress", "127.0.0.1:7777", "server address")

func TestServer(t *testing.T) {
	t.Parallel()
	t.Logf("serverAddress %s", *serverAddress)

	_, err := http.Get("http://" + *serverAddress + "/blank")
	if err != nil {
		t.Fatalf("Get failed with err %v", err)
	}
}
