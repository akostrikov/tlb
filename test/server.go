package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

type Service struct {
	signalChannel   chan os.Signal
	errorChannel    chan error
	httpServer      *http.Server
	debugHttpServer *http.Server
	serverId        string
}

func (svc *Service) stop() {
	log.Printf("stopping\n")
	svc.httpServer.Shutdown(context.Background())
	svc.debugHttpServer.Shutdown(context.Background())
	log.Printf("stopped\n")
}

func (svc *Service) serverHttp() {
	log.Print("server http\n")
	err := svc.httpServer.ListenAndServe()
	if err != nil {
		svc.errorChannel <- err
	}
}

func (svc *Service) serverDebugHttp() {
	log.Printf("server debug\n")
	err := svc.debugHttpServer.ListenAndServe()
	if err != nil {
		svc.errorChannel <- err
	}
}

func (svc *Service) runEventLoop() error {
	for {
		select {
		case <-svc.signalChannel:
			log.Printf("signal\n")
			svc.stop()
			return nil
		case err := <-svc.errorChannel:
			log.Printf("error %v\n", err)
			svc.stop()
			return err
		}
	}
}

type BaseRequest struct {
	RequestId string `json:"requestId"`
}

type BaseResponse struct {
	RequestId string `json:"requestId"`
	Error     string `json:"error"`
	ServerId  string `json:"serverId"`
}

var (
	ErrNotFound = fmt.Errorf("Not found")
)

func completeRequest(w http.ResponseWriter, requestId string, err error, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		switch err {
		case ErrNotFound:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		err = json.NewEncoder(w).Encode(&BaseResponse{RequestId: requestId, Error: err.Error(), ServerId: g_Svc.serverId})
		if err != nil {
			panic(fmt.Sprintf("encode error failed, error %v", err))
		}
	} else {
		w.WriteHeader(http.StatusOK)
		switch tv := v.(type) {
		case *BaseResponse:
			resp := v.(*BaseResponse)
			resp.Error = ""
			resp.RequestId = requestId
			resp.ServerId = g_Svc.serverId
		default:
			panic(fmt.Sprintf("unknown type %v", tv))
		}

		err = json.NewEncoder(w).Encode(v)
		if err != nil {
			panic(fmt.Sprintf("encode error failed, error %v", err))
		}
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	req := &BaseRequest{}
	resp := &BaseResponse{}

	defer func() {
		completeRequest(w, req.RequestId, err, resp)
	}()

	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return
	}
}

func blankHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	req := &BaseRequest{}
	resp := &BaseResponse{}

	defer func() {
		completeRequest(w, req.RequestId, err, resp)
	}()
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	resp := &BaseResponse{}

	defer func() {
		completeRequest(w, "", err, resp)
	}()

	err = ErrNotFound
}

func getHttpHandler() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/", rootHandler).Methods("GET")
	r.HandleFunc("/blank", blankHandler).Methods("GET")

	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	return r
}

func getDebugHttpHandler() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/debug/pprof/", pprof.Index).Methods("GET")
	r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline).Methods("GET")
	r.HandleFunc("/debug/pprof/profile", pprof.Profile).Methods("GET")
	r.HandleFunc("/debug/pprof/symbol", pprof.Symbol).Methods("GET")

	r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine")).Methods("GET")
	r.Handle("/debug/pprof/heap", pprof.Handler("heap")).Methods("GET")
	r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate")).Methods("GET")
	r.Handle("/debug/pprof/block", pprof.Handler("block")).Methods("GET")

	return r
}

var g_Svc Service

func main() {
	var address string
	var debugAddress string

	flag.StringVar(&address, "address", "127.0.0.1:8080", "address")
	flag.StringVar(&debugAddress, "debugAddress", "127.0.0.1:9090", "debug address")
	flag.Parse()

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ltime | log.Ldate | log.LUTC | log.Lmicroseconds | log.Lshortfile)
	log.Printf("address %s debugAddress %s\n", address, debugAddress)

	serverId, err := uuid.NewV4()
	if err != nil {
		panic(err)
	}

	svc := &g_Svc
	svc.serverId = serverId.String()
	svc.signalChannel = make(chan os.Signal, 1)
	svc.errorChannel = make(chan error, 1)
	signal.Notify(svc.signalChannel, syscall.SIGINT, syscall.SIGTERM)
	svc.httpServer = &http.Server{Addr: address, Handler: getHttpHandler()}
	svc.debugHttpServer = &http.Server{Addr: debugAddress, Handler: getDebugHttpHandler()}

	go svc.serverHttp()
	go svc.serverDebugHttp()

	svc.runEventLoop()
}
