package containerstats

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil"
	"github.com/VictoriaMetrics/easyproto"
)

// containerdClient is handwritten gRPC containerd client written just for fun.
// Should be replaced with gogoproto or go-grpc because it probably won't work on all devices.
type containerdClient struct {
	client *http.Client
}

func newContainerdClient() *containerdClient {
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	client := &http.Client{
		Transport: &http.Transport{
			Protocols:         &protocols,
			ForceAttemptHTTP2: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", "/run/containerd/containerd.sock")
			},
		},
	}
	return &containerdClient{
		client: client,
	}
}

type getTaskRequest struct {
	ContainerID string
}

var mp = easyproto.MarshalerPool{}

func (r *getTaskRequest) MarshalProtobuf(dst []byte) []byte {
	m := mp.Get()
	defer mp.Put(m)
	mm := m.MessageMarshaler()
	mm.AppendString(1, r.ContainerID)
	dst = m.Marshal(dst)
	return dst
}

type process struct {
	PID uint32
}

func (p *process) UnmarshalProtobuf(b []byte) (err error) {
	var fc easyproto.FieldContext
	for len(b) > 0 {
		b, err = fc.NextField(b)
		if err != nil {
			return fmt.Errorf("cannot read next field in Process message: %s", err)
		}
		switch fc.FieldNum {
		case 3:
			pid, ok := fc.Uint32()
			if !ok {
				return fmt.Errorf("cannot read PID")
			}
			p.PID = pid
		}
	}
	return nil
}

type getTaskResponse struct {
	Process process
}

func (r *getTaskResponse) UnmarshalProtobuf(b []byte) (err error) {
	var fc easyproto.FieldContext
	for len(b) > 0 {
		b, err = fc.NextField(b)
		if err != nil {
			return fmt.Errorf("cannot read next field in GetGaskResponse message: %s", err)
		}
		switch fc.FieldNum {
		case 1:
			messageData, ok := fc.MessageData()
			if !ok {
				return fmt.Errorf("cannot read process data")
			}
			var p process
			if err := p.UnmarshalProtobuf(messageData); err != nil {
				return err
			}
			r.Process = p
		}
	}
	return nil
}

var bodyBufferPool bytesutil.ByteBufferPool

func (c *containerdClient) GetTask(ctx context.Context, namespace string, containerID string) (getTaskResponse, error) {
	resp, err := c.sendGetTask(ctx, namespace, containerID)
	if err != nil {
		return getTaskResponse{}, fmt.Errorf("cannot send get tasks request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return getTaskResponse{}, fmt.Errorf("unexpected status code %d from containerd", resp.StatusCode)
	}
	grpcStatus := resp.Header.Get("Grpc-Status")
	if grpcStatus != "" && grpcStatus != "0" {
		msg := resp.Header.Get("Grpc-Message")
		return getTaskResponse{}, fmt.Errorf("unexpected gRPC status code %q from containerd: %q", grpcStatus, msg)
	}

	r, err := readGetTask(resp.Body)
	if err != nil {
		return getTaskResponse{}, fmt.Errorf("cannot read get tasks response: %s", err)
	}

	return r, nil
}

func (c *containerdClient) sendGetTask(ctx context.Context, namespace string, containerID string) (*http.Response, error) {
	bb := bodyBufferPool.Get()
	defer bodyBufferPool.Put(bb)
	grpcRequest := getTaskRequest{ContainerID: containerID}
	bb.B = marshalGrpcRequest(bb.B, grpcRequest)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://containerd/containerd.services.tasks.v1.Tasks/Get", bb.NewReader())
	if err != nil {
		panic(fmt.Errorf("BUG: NewRequest failed with %s", err))
	}
	req.Header.Set("Content-Type", "application/grpc+proto")
	// This is required header that defines in which namespace to search for the container.
	// Some default namespaces:
	// "k8s.io" - namespace used for Kubernetes containers
	// "moby" - namespace used for Docker containers
	req.Header.Set("Containerd-Namespace", namespace)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

func readGetTask(r io.Reader) (getTaskResponse, error) {
	bb := bodyBufferPool.Get()
	defer bodyBufferPool.Put(bb)
	if _, err := bb.ReadFrom(r); err != nil {
		return getTaskResponse{}, err
	}

	if len(bb.B) < 5 {
		return getTaskResponse{}, fmt.Errorf("too few bytes read from buffer")
	}
	compressionType := bb.B[0]
	if compressionType != 0 {
		return getTaskResponse{}, fmt.Errorf("unknown compression type %d", compressionType)
	}
	messageLength := binary.BigEndian.Uint32(bb.B[1:5])
	if len(bb.B) < int(messageLength) {
		return getTaskResponse{}, fmt.Errorf("expected message length %d, got %d", messageLength, len(bb.B))
	}

	message := bb.B[5 : messageLength+5]
	var resp getTaskResponse
	if err := resp.UnmarshalProtobuf(message); err != nil {
		return getTaskResponse{}, err
	}
	return resp, nil
}

func marshalGrpcRequest(dst []byte, request getTaskRequest) []byte {
	dst = append(dst, 0)                  // Set compression type
	dst = append(dst, make([]byte, 4)...) // Reserve space for protobuf message length
	n := len(dst)
	dst = request.MarshalProtobuf(dst)
	n = len(dst) - n
	binary.BigEndian.PutUint32(dst[1:], uint32(n)) // Set payload length
	return dst
}
