package server

import (
	"encoding/json"
	"math"
	"net/http"
)

type Server struct{}

func (s *Server) RegisterRoutes(mux http.ServeMux) {
	mux.HandleFunc("/", s.index)
}

func (s *Server) index(rw http.ResponseWriter, r *http.Request) {
	rw.Write([]byte("banner?"))
}

type uploadPayload struct {
	Metadata      string `json:"metadata"`
	ContentHash   string `json:"content_hash"`
	ContentLength int    `json:"content_length"`
	Type          string `json:"type"`
}

func (s *Server) upload(rw http.ResponseWriter, r *http.Request) {
	var x uploadPayload
	err := json.NewDecoder(r.Body).Decode(&x)
	if err != nil {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	if x.ContentLength > 4*int(math.Pow(10, 9)) {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(x.ContentHash) != 64 {
	}
}

func (s *Server) getChildren(rw http.ResponseWriter, r *http.Request) {
}
