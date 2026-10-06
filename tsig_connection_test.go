package dns

import (
	"testing"
	"time"
)

func TestRepeatedTSIGTransactionsOnConnection(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
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
				request.SetUpdate("example.org.")
				request.SetTsig("test.", HmacSHA256, 300, time.Now().Unix())
				if err := conn.WriteMsg(request); err != nil {
					t.Fatalf("transaction %d write: %v", i+1, err)
				}
				conn.SetReadDeadline(time.Now().Add(time.Second))
				response, err := conn.ReadMsg()
				if err != nil {
					t.Fatalf("transaction %d read: %v", i+1, err)
				}
				select {
				case status := <-statuses:
					if status != nil {
						t.Errorf("transaction %d server verification: %v", i+1, status)
					}
				case <-time.After(time.Second):
					t.Fatalf("transaction %d was not verified by the server", i+1)
				}
				if response.Rcode != RcodeSuccess {
					t.Fatalf("transaction %d rcode: %s", i+1, RcodeToString[response.Rcode])
				}
				if network == "tcp" {
					if tsig := response.IsTsig(); tsig == nil || conn.tsigRequestMAC != tsig.MAC {
						t.Errorf("transaction %d did not retain the verified response MAC", i+1)
					}
				} else if conn.tsigRequestMAC != "" {
					t.Errorf("transaction %d retained a MAC across UDP datagrams", i+1)
				}
			}
		})
	}
}
