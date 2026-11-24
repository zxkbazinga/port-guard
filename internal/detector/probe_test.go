package detector

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSourceProbeEchoesAndRecords(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewSourceProbe(log, 0)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	// 端口 0 由系统分配，从 Stats 拿不到实际端口，这里单独暴露监听地址
	addr := p.ln.Addr().String()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("期望 HTTP 200，实际 %q", resp)
	}

	st := p.Stats()
	if st["hits"].(uint64) != 1 {
		t.Fatalf("期望 1 次命中，实际 %v", st["hits"])
	}
	records := st["records"].([]ProbeRecord)
	if len(records) != 1 || records[0].IP == "" {
		t.Fatalf("记录异常：%+v", records)
	}
}
