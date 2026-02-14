package network

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

func getSystemConnections() []ConnectionInfo {
	switch runtime.GOOS {
	case "linux":
		return getLinuxConnections()
	case "windows":
		return getWindowsConnections()
	case "darwin":
		return getDarwinConnections()
	default:
		return nil
	}
}

func getLinuxConnections() []ConnectionInfo {
	var connections []ConnectionInfo

	tcpConns := parseLinuxProcNet("/proc/net/tcp", "tcp")
	connections = append(connections, tcpConns...)

	udpConns := parseLinuxProcNet("/proc/net/udp", "udp")
	connections = append(connections, udpConns...)

	return connections
}

func parseLinuxProcNet(path, protocol string) []ConnectionInfo {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var connections []ConnectionInfo
	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip header

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		localAddr, localPort := parseHexAddr(fields[1])
		remoteAddr, remotePort := parseHexAddr(fields[2])
		state := parseConnState(fields[3])

		if remoteAddr == "0.0.0.0" || remoteAddr == "::" {
			continue
		}

		connections = append(connections, ConnectionInfo{
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			LocalPort:  localPort,
			RemotePort: remotePort,
			Protocol:   protocol,
			State:      state,
		})
	}

	return connections
}

func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}

	port, _ := strconv.ParseInt(parts[1], 16, 32)

	addrHex := parts[0]
	if len(addrHex) == 8 {
		bytes, err := hex.DecodeString(addrHex)
		if err != nil || len(bytes) != 4 {
			return "", int(port)
		}
		ip := net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
		return ip.String(), int(port)
	}

	return addrHex, int(port)
}

func parseConnState(s string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if state, ok := states[s]; ok {
		return state
	}
	return "UNKNOWN"
}

func getWindowsConnections() []ConnectionInfo {
	out, err := exec.Command("netstat", "-n", "-o").Output()
	if err != nil {
		return nil
	}
	return parseNetstatOutput(string(out))
}

func getDarwinConnections() []ConnectionInfo {
	out, err := exec.Command("netstat", "-n", "-p", "tcp").Output()
	if err != nil {
		return nil
	}
	return parseNetstatOutput(string(out))
}

func parseNetstatOutput(output string) []ConnectionInfo {
	var connections []ConnectionInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		localAddr, localPort := splitAddrPort(fields[1])
		remoteAddr, remotePort := splitAddrPort(fields[2])

		if remoteAddr == "0.0.0.0" || remoteAddr == "*" || remoteAddr == "::" {
			continue
		}

		state := ""
		if len(fields) > 3 {
			state = fields[3]
		}

		connections = append(connections, ConnectionInfo{
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
			LocalPort:  localPort,
			RemotePort: remotePort,
			Protocol:   proto,
			State:      state,
		})
	}

	return connections
}

func splitAddrPort(s string) (string, int) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return s, 0
	}
	addr := s[:lastColon]
	portStr := s[lastColon+1:]
	port, _ := strconv.Atoi(portStr)
	return addr, port
}

func FormatConnection(c ConnectionInfo) string {
	return fmt.Sprintf("%s %s:%d -> %s:%d [%s]",
		c.Protocol, c.LocalAddr, c.LocalPort,
		c.RemoteAddr, c.RemotePort, c.State)
}
