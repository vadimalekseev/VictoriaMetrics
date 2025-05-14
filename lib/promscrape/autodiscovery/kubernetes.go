package autodiscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
)

type kubeAPIConfig struct {
	Server        string
	BearerToken   string
	ClientCert    []byte
	ClientCertKey []byte
	GetCACert     func() (*x509.CertPool, error)
}

type kubeAPIClient struct {
	config *kubeAPIConfig
	c      *http.Client

	apiURL *url.URL
}

func newKubeAPIClient(cfg *kubeAPIConfig) (*kubeAPIClient, error) {
	certPool, err := cfg.GetCACert()
	if err != nil {
		return nil, fmt.Errorf("cannot get CA certificate: %s", err)
	}
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}
	if len(cfg.ClientCert) != 0 {
		clientCert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientCertKey)
		if err != nil {
			return nil, fmt.Errorf("cannot load client certificate: %s", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	// todo: ca cert can be updated, need to support this behavior in the client
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	apiURL, err := url.Parse(cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("cannot parse server URL %q: %s", cfg.Server, err)
	}

	return &kubeAPIClient{
		config: cfg,
		c:      c,
		apiURL: apiURL,
	}, nil
}

type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

func (c *kubeAPIClient) WatchNodePods(nodeName string, handleEvent func(event watchEvent)) error {
	args := url.Values{
		"watch": []string{"true"},
		"labelSelector": []string{
			"vmscrape/port",
		},
		"fieldSelector": []string{
			"spec.nodeName=" + nodeName,
		},
	}
	req := c.mustCreateRequest(context.Background(), http.MethodGet, "/api/v1/pods", args)
	resp, err := c.c.Do(req)
	if err != nil {
		return fmt.Errorf("cannot do %q GET request: %s", req.URL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d from %q: %s", resp.StatusCode, req.URL.String(), resp.Status)
	}
	if err := scanEvents(resp.Body, handleEvent); err != nil {
		return err
	}
	return nil
}

func scanEvents(r io.Reader, handleEvent func(event watchEvent)) error {
	lr := newLineReader(r)
	for {
		line, err := lr.ReadLine()
		if err != nil {
			return fmt.Errorf("cannon read event line: %s", err)
		}
		var e watchEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("cannot decode event: %s", err)
		}
		handleEvent(e)
	}
}

type lineReader struct {
	lr  *bufio.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{
		lr:  bufio.NewReaderSize(r, 16*1024),
		buf: []byte{},
	}
}

func (l *lineReader) ReadLine() ([]byte, error) {
	l.buf = l.buf[:0]
	for {
		line, isPrefix, err := l.lr.ReadLine()
		if err != nil {
			return nil, err
		}
		if isPrefix {
			// The line is incomplete, we need to read more data to finish it
			l.buf = append(l.buf, line...)
			continue
		}

		if len(l.buf) == 0 {
			// Fast path: the entire line fits within the *bufio.Reader, no need for further reading
			return line, nil
		}

		// Slow path: the line doesn't fit in the buffer, so we append the remainder to the prefix and return the complete line
		l.buf = append(l.buf, line...)
		return l.buf, nil
	}
}

type pod struct {
	Metadata podMetadata `json:"metadata"`
	Status   podStatus   `json:"status"`
	Spec     podSpec     `json:"spec"`
}

type podMetadata struct {
	Name      string
	Labels    map[string]string `json:"labels"`
	Namespace string            `json:"namespace"`
	UID       string            `json:"uid"`
}

type podSpec struct {
	NodeName   string         `json:"nodeName"`
	Containers []podContainer `json:"containers"`
}

type podContainer struct {
	Name  string          `json:"name"`
	Image string          `json:"image"`
	Ports []containerPort `json:"ports"`
}

type containerPort struct {
	Name          string `json:"name"`
	ContainerPort int    `json:"containerPort"`
}

type podStatus struct {
	PodIP             string            `json:"podIP"`
	ContainerStatuses []containerStatus `json:"containerStatuses"`
	QosClass          string            `json:"qosClass"`
}

type containerStatus struct {
	Name        string `json:"name"`
	ContainerID string `json:"containerID"`
}

func (c *kubeAPIClient) GetPod(ctx context.Context, namespace string, podName string) (pod, error) {
	req := c.mustCreateRequest(ctx, http.MethodGet, "/api/v1/namespaces/"+namespace+"/pods/"+podName, nil)
	resp, err := c.c.Do(req)
	if err != nil {
		return pod{}, fmt.Errorf("cannot do %q GET request: %s", req.URL.String(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return pod{}, fmt.Errorf("cannot read response body: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return pod{}, fmt.Errorf("unexpected status code %d from %q: %s", resp.StatusCode, req.URL.String(), string(body))
	}
	var p pod
	if err := json.Unmarshal(body, &p); err != nil {
		return pod{}, fmt.Errorf("cannot decode response body: %s", err)
	}
	return p, nil
}

func (c *kubeAPIClient) mustCreateRequest(ctx context.Context, method, urlPath string, args url.Values) *http.Request {
	req, err := http.NewRequestWithContext(ctx, method, "/", nil)
	if err != nil {
		logger.Fatalf("cannot create request: %s", err)
	}
	u := *c.apiURL
	req.URL = &u
	req.URL.Path = urlPath
	req.URL.RawQuery = args.Encode()
	if c.config.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.BearerToken)
	}
	return req
}
