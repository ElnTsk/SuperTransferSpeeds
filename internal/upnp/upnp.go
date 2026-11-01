// Package upnp asks the local router to forward a TCP port to this machine.
// It is what lets a self-hosted relay be reachable from the internet without
// the user ever opening a router admin page.
package upnp

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Router is a discovered IGD's control endpoint.
type Router struct {
	Gateway string // LAN address that answered
	Base    string // http://host:port
	Control string // absolute control URL for WANIPConnection
	Service string // service type for the SOAPAction header
}

var (
	reLocation = regexp.MustCompile(`(?i)LOCATION:\s*(\S+)`)
	reService  = regexp.MustCompile(`(?is)<service>(.*?)</service>`)
	reType     = regexp.MustCompile(`(?i)<serviceType>([^<]*WANIPConnection[^<]*)</serviceType>`)
	reCtrl     = regexp.MustCompile(`(?i)<controlURL>([^<]*)</controlURL>`)
	reBase     = regexp.MustCompile(`(?i)^(https?://[^/]+)`)
	reIP       = regexp.MustCompile(`<NewExternalIPAddress>([^<]*)<`)
)

// Discover finds the gateway with SSDP, then falls back to the two common
// hub addresses for networks that do not answer multicast.
func Discover() (*Router, error) {
	if base, gw, err := ssdpBase(); err == nil {
		if r, err := fromDescription(base, gw); err == nil {
			return r, nil
		}
	}
	for _, gw := range []string{"192.168.1.1", "192.168.0.1"} {
		r, err := fromDescription("http://"+gw+":5000", gw)
		if err == nil {
			return r, nil
		}
	}
	return nil, fmt.Errorf("no router answered UPnP (is it enabled in the hub settings?)")
}

func ssdpBase() (string, string, error) {
	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	dst := &net.UDPAddr{IP: net.IPv4(239, 255, 255, 250), Port: 1900}
	if _, err := conn.WriteTo([]byte(msg), dst); err != nil {
		return "", "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return "", "", err
		}
		if loc := reLocation.FindStringSubmatch(string(buf[:n])); loc != nil {
			gw := ""
			if ua, ok := addr.(*net.UDPAddr); ok {
				gw = ua.IP.String()
			}
			return strings.TrimSpace(loc[1]), gw, nil
		}
	}
}

func fromDescription(base, gw string) (*Router, error) {
	body, err := fetch(base+"/rootDesc.xml", 5*time.Second)
	if err != nil {
		return nil, err
	}
	for _, svc := range reService.FindAllStringSubmatch(body, -1) {
		t := reType.FindStringSubmatch(svc[1])
		c := reCtrl.FindStringSubmatch(svc[1])
		if t == nil || c == nil {
			continue
		}
		root := reBase.FindStringSubmatch(base)
		if root == nil {
			return nil, fmt.Errorf("odd description URL %q", base)
		}
		ctrl := c[1]
		if !strings.HasPrefix(ctrl, "/") {
			ctrl = "/" + ctrl
		}
		return &Router{Gateway: gw, Base: root[1], Control: root[1] + ctrl, Service: t[1]}, nil
	}
	return nil, fmt.Errorf("%s exposes no WANIPConnection service", base)
}

func (r *Router) call(action, inner string) (string, error) {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body><u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>`, action, r.Service, inner, action)
	req, err := http.NewRequest("POST", r.Control, bytes.NewBufferString(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, r.Service, action))
	resp, err := (&http.Client{Timeout: 6 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: router answered %d (%.120s)", action, resp.StatusCode, string(data))
	}
	return string(data), nil
}

func fetch(url string, timeout time.Duration) (string, error) {
	resp, err := (&http.Client{Timeout: timeout}).Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return string(b), err
}

// ExternalIP is the address the router believes it holds.
func (r *Router) ExternalIP() (string, error) {
	out, err := r.call("GetExternalIPAddress", "")
	if err != nil {
		return "", err
	}
	if m := reIP.FindStringSubmatch(out); m != nil {
		return m[1], nil
	}
	return "", fmt.Errorf("router did not report an external address")
}

// LocalIP is this machine's address on the interface that reaches the gateway.
func (r *Router) LocalIP() (string, error) {
	c, err := net.Dial("udp4", net.JoinHostPort(r.Gateway, "53"))
	if err != nil {
		return "", err
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.String(), nil
	}
	return "", fmt.Errorf("could not determine the local address")
}

// AddMapping forwards external TCP externalPort to localPort on this machine.
func (r *Router) AddMapping(externalPort, localPort int, desc string) error {
	local, err := r.LocalIP()
	if err != nil {
		return err
	}
	inner := fmt.Sprintf(`<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>%d</NewInternalPort><NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled><NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>0</NewLeaseDuration>`, externalPort, localPort, local, desc)
	_, err = r.call("AddPortMapping", inner)
	return err
}

// DeleteMapping removes a rule this machine created.
func (r *Router) DeleteMapping(externalPort int) error {
	inner := fmt.Sprintf(`<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>`, externalPort)
	_, err := r.call("DeletePortMapping", inner)
	return err
}

// Mapping returns who an external port currently belongs to.
func (r *Router) Mapping(externalPort int) (client string, localPort string, err error) {
	inner := fmt.Sprintf(`<NewRemoteHost></NewRemoteHost><NewExternalPort>%d</NewExternalPort><NewProtocol>TCP</NewProtocol>`, externalPort)
	out, err := r.call("GetSpecificPortMappingEntry", inner)
	if err != nil {
		return "", "", err
	}
	c := regexp.MustCompile(`<NewInternalClient>([^<]*)<`).FindStringSubmatch(out)
	p := regexp.MustCompile(`<NewInternalPort>([^<]*)<`).FindStringSubmatch(out)
	if c != nil {
		client = c[1]
	}
	if p != nil {
		localPort = p[1]
	}
	return client, localPort, nil
}
