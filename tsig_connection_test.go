package dns

import (
	"testing"
	"time"
)

func TestRepeatedTSIGTransactionsOnConnection(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, update := range []bool{false, true} {
			name := network + "/query"
			if update {
				name = network + "/update"
			}
			t.Run(name, func(t *testing.T) {
				secret := map[string]string{"test.": "so6ZGir4GPAqINNh9U5c3A=="}
				statuses := make(chan error, 3)
				configure := func(s *Server) {
					s.TsigSecret = secret
					s.MsgAcceptFunc = func(Header) MsgAcceptAction { return MsgAccept }
					s.Handler = HandlerFunc(func(w ResponseWriter, request *Msg) {
						statuses <- w.TsigStatus()
						response := new(Msg)
						response.SetReply(request)
						response.SetTsig("test.", HmacSHA256, 300, time.Now().Unix())
						if err := w.WriteMsg(response); err != nil {
							t.Errorf("write response: %v", err)
						}
					})
				}
				var server *Server
				var address string
				var err error
				if network == "tcp" {
					server, address, _, err = RunLocalTCPServer("127.0.0.1:0", configure)
				} else {
					server, address, _, err = RunLocalUDPServer("127.0.0.1:0", configure)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer server.Shutdown()

				conn, err := Dial(network, address)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.TsigSecret = secret
				for i := 0; i < 3; i++ {
					request := new(Msg)
					if update {
						request.SetUpdate("example.org.")
					} else {
						request.SetQuestion("example.org.", TypeA)
					}
					request.SetTsig("test.", HmacSHA256, 300, time.Now().Unix())
					if err := conn.WriteMsg(request); err != nil {
						t.Fatalf("transaction %d write: %v", i+1, err)
					}
					conn.SetReadDeadline(time.Now().Add(time.Second))
					response, err := conn.ReadMsg()
					if err != nil {
						t.Fatalf("transaction %d read: %v", i+1, err)
					}
					if status := <-statuses; status != nil {
						t.Fatalf("transaction %d server verification: %v", i+1, status)
					}
					if response.Rcode != RcodeSuccess {
						t.Fatalf("transaction %d rcode: %s", i+1, RcodeToString[response.Rcode])
					}
					if conn.tsigRequestMAC != "" {
						t.Fatalf("transaction %d retained its MAC after the response", i+1)
					}
				}
			})
		}
	}
}

func TestMixedTSIGTransactionsOnTCP(t *testing.T) {
	secret := map[string]string{"test.": "so6ZGir4GPAqINNh9U5c3A=="}
	statuses := make(chan error, 3)
	server, address, _, err := RunLocalTCPServer("127.0.0.1:0", func(s *Server) {
		s.TsigSecret = secret
		s.MsgAcceptFunc = func(Header) MsgAcceptAction { return MsgAccept }
		s.Handler = HandlerFunc(func(w ResponseWriter, request *Msg) {
			statuses <- w.TsigStatus()
			response := new(Msg)
			response.SetReply(request)
			if request.IsTsig() != nil {
				response.SetTsig("test.", HmacSHA256, 300, time.Now().Unix())
			}
			if err := w.WriteMsg(response); err != nil {
				t.Errorf("write response: %v", err)
			}
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	conn, err := Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.TsigSecret = secret
	for i := 0; i < 3; i++ {
		request := new(Msg)
		if i == 1 {
			request.SetQuestion("example.org.", TypeA)
		} else {
			request.SetUpdate("example.org.")
			request.SetTsig("test.", HmacSHA256, 300, time.Now().Unix())
		}
		if err := conn.WriteMsg(request); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		response, err := conn.ReadMsg()
		if err != nil {
			t.Fatal(err)
		}
		if status := <-statuses; status != nil {
			t.Fatalf("transaction %d server verification: %v", i+1, status)
		}
		if response.Rcode != RcodeSuccess || conn.tsigRequestMAC != "" {
			t.Fatalf("transaction %d: rcode=%s retainedMAC=%q", i+1, RcodeToString[response.Rcode], conn.tsigRequestMAC)
		}
	}
}
