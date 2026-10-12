package auth

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type mockRedisServer struct {
	listener net.Listener
	mu       sync.Mutex
	data     map[string]string
	sets     map[string]map[string]struct{}
	subs     map[string][]chan []string
	closed   bool
}

func startMockRedis(t *testing.T) (*mockRedisServer, *redis.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock redis: %v", err)
	}

	m := &mockRedisServer{
		listener: ln,
		data:     make(map[string]string),
		sets:     make(map[string]map[string]struct{}),
		subs:     make(map[string][]chan []string),
	}
	go m.serve()

	rdb := redis.NewClient(&redis.Options{
		Addr:         ln.Addr().String(),
		Protocol:     2,
		ReadTimeout:  time.Second,
		WriteTimeout: time.Second,
	})

	t.Cleanup(func() {
		m.close()
		_ = rdb.Close()
	})

	return m, rdb
}

func (m *mockRedisServer) close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		_ = m.listener.Close()
	}
	m.mu.Unlock()
}

func (m *mockRedisServer) serve() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			return
		}
		go m.handle(conn)
	}
}

func (m *mockRedisServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	var mySubChannels []string
	msgChan := make(chan []string, 20)

	go func() {
		for msg := range msgChan {
			ch := msg[0]
			payload := msg[1]
			resp := fmt.Sprintf("*3\r\n$7\r\nmessage\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(ch), ch, len(payload), payload)
			if _, err := conn.Write([]byte(resp)); err != nil {
				return
			}
		}
	}()

	defer func() {
		close(msgChan)
		m.mu.Lock()
		for _, ch := range mySubChannels {
			subList := m.subs[ch]
			for i, c := range subList {
				if c == msgChan {
					m.subs[ch] = append(subList[:i], subList[i+1:]...)
					break
				}
			}
		}
		m.mu.Unlock()
	}()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "*") {
			continue
		}
		numArgs, err := strconv.Atoi(line[1:])
		if err != nil {
			return
		}
		args := make([]string, 0, numArgs)
		for i := 0; i < numArgs; i++ {
			lenLine, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			lenLine = strings.TrimRight(lenLine, "\r\n")
			argLen, _ := strconv.Atoi(lenLine[1:])
			buf := make([]byte, argLen+2)
			if _, err := io.ReadFull(reader, buf); err != nil {
				return
			}
			args = append(args, string(buf[:argLen]))
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		switch cmd {
		case "PING":
			_, _ = conn.Write([]byte("+PONG\r\n"))
		case "HELLO":
			_, _ = conn.Write([]byte("-ERR unknown command 'HELLO'\r\n"))
		case "CLIENT":
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "GET":
			m.mu.Lock()
			val, ok := m.data[args[1]]
			m.mu.Unlock()
			if !ok {
				_, _ = conn.Write([]byte("$-1\r\n"))
			} else {
				_, _ = fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(val), val)
			}
		case "SET":
			m.mu.Lock()
			m.data[args[1]] = args[2]
			m.mu.Unlock()
			_, _ = conn.Write([]byte("+OK\r\n"))
		case "DEL":
			m.mu.Lock()
			count := 0
			for _, k := range args[1:] {
				if _, ok := m.data[k]; ok {
					delete(m.data, k)
					count++
				}
				if _, ok := m.sets[k]; ok {
					delete(m.sets, k)
					count++
				}
			}
			m.mu.Unlock()
			_, _ = fmt.Fprintf(conn, ":%d\r\n", count)
		case "SADD":
			setKey := args[1]
			m.mu.Lock()
			if m.sets[setKey] == nil {
				m.sets[setKey] = make(map[string]struct{})
			}
			count := 0
			for _, mem := range args[2:] {
				if _, exists := m.sets[setKey][mem]; !exists {
					m.sets[setKey][mem] = struct{}{}
					count++
				}
			}
			m.mu.Unlock()
			_, _ = fmt.Fprintf(conn, ":%d\r\n", count)
		case "SREM":
			setKey := args[1]
			m.mu.Lock()
			count := 0
			if s, ok := m.sets[setKey]; ok {
				for _, mem := range args[2:] {
					if _, exists := s[mem]; exists {
						delete(s, mem)
						count++
					}
				}
			}
			m.mu.Unlock()
			_, _ = fmt.Fprintf(conn, ":%d\r\n", count)
		case "SMEMBERS":
			setKey := args[1]
			m.mu.Lock()
			var members []string
			if s, ok := m.sets[setKey]; ok {
				for mem := range s {
					members = append(members, mem)
				}
			}
			m.mu.Unlock()
			var buf strings.Builder
			buf.WriteString(fmt.Sprintf("*%d\r\n", len(members)))
			for _, mem := range members {
				buf.WriteString(fmt.Sprintf("$%d\r\n%s\r\n", len(mem), mem))
			}
			_, _ = conn.Write([]byte(buf.String()))
		case "SUBSCRIBE":
			subChan := args[1]
			m.mu.Lock()
			mySubChannels = append(mySubChannels, subChan)
			m.subs[subChan] = append(m.subs[subChan], msgChan)
			m.mu.Unlock()
			resp := fmt.Sprintf("*3\r\n$9\r\nsubscribe\r\n$%d\r\n%s\r\n:1\r\n", len(subChan), subChan)
			_, _ = conn.Write([]byte(resp))
		case "PUBLISH":
			pubChan := args[1]
			payload := args[2]
			m.mu.Lock()
			count := len(m.subs[pubChan])
			for _, ch := range m.subs[pubChan] {
				select {
				case ch <- []string{pubChan, payload}:
				default:
				}
			}
			m.mu.Unlock()
			_, _ = fmt.Fprintf(conn, ":%d\r\n", count)
		case "QUIT":
			_, _ = conn.Write([]byte("+OK\r\n"))
			return
		default:
			_, _ = conn.Write([]byte("+OK\r\n"))
		}
	}
}
