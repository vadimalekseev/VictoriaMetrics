package autodiscovery

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/prompbmarshal"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/timeutil"
	"gopkg.in/yaml.v2"
)

type Discovery struct {
	kubeAPI          *kubeAPIClient
	mu               *sync.RWMutex
	targets          map[targetEntry]ScrapeTarget
	currentNamespace string
	currentNodeName  string
}

func MustStart() *Discovery {
	cfg, err := loadKubeAPIConfig()
	if err != nil {
		logger.Fatalf("cannot load Kubernetes config: %s", err)
	}
	kubeAPI, err := newKubeAPIClient(cfg)
	if err != nil {
		logger.Fatalf("cannot create Kubernetes client: %s", err)
	}

	d := &Discovery{
		kubeAPI: kubeAPI,
		mu:      &sync.RWMutex{},
		targets: map[targetEntry]ScrapeTarget{},
	}

	d.mustInitCurrentNodeInfo()

	logger.Infof("autodiscovery started successfully at %q node in %q namespace", d.currentNodeName, d.currentNamespace)

	go d.mustStartWatchCluster()

	return d
}

type ScrapeTarget struct {
	URL    string
	Labels []prompbmarshal.Label
}

func (d *Discovery) Targets() []ScrapeTarget {
	d.mu.RLock()
	defer d.mu.RUnlock()
	targets := make([]ScrapeTarget, 0, len(d.targets))
	for _, t := range d.targets {
		targets = append(targets, t)
	}
	return targets
}

func (d *Discovery) mustStartWatchCluster() {
	for {
		const minRetryDuration = time.Second
		retryDuration := timeutil.AddJitterToDuration(minRetryDuration)
		maxRetryDuration := timeutil.AddJitterToDuration(time.Second * 30)

		handleEvent := func(event watchEvent) {
			// Reset retry duration after successful response
			if retryDuration > minRetryDuration*2 {
				retryDuration = timeutil.AddJitterToDuration(minRetryDuration)
			}
			d.handleEvent(event)
		}

		if err := d.kubeAPI.WatchNodePods(d.currentNodeName, handleEvent); err != nil {
			logger.Errorf("cannot watch Kubernetes pods: %s", err)
			d.mu.Lock()
			clear(d.targets)
			d.mu.Unlock()

			time.Sleep(retryDuration)
			retryDuration = retryDuration * 2
			if retryDuration > maxRetryDuration {
				retryDuration = maxRetryDuration
			}
		}
	}
}

type targetEntry struct {
	Namespace string
	Pod       string
	Port      int
}

func (d *Discovery) handleEvent(event watchEvent) {
	logger.Infof("handling event %q for pod %s", event.Type, event.Object)
	switch event.Type {
	case "ADDED", "MODIFIED":
		var pod pod
		if err := json.Unmarshal(event.Object, &pod); err != nil {
			logger.Errorf("cannon unmarshal object %q of event %q: %s", event.Object, event.Type, err)
			return
		}
		if pod.Status.PodIP == "" {
			// PodIP can be empty in case of pending pods
			return
		}

		targetPortName := pod.Metadata.Labels["vmscrape/port"]
		targetContainer := pod.Metadata.Labels["vmscrape/container"]
		targetMetricsPath := pod.Metadata.Labels["vmscrape/metrics_path"]

		if targetMetricsPath == "" {
			targetMetricsPath = "/metrics"
		}
		targetMetricsPath = path.Join("/", targetMetricsPath)

		jobName := d.currentNamespace + "/" + "vmscrape"
		visitTargetContainers(pod.Spec.Containers, targetContainer, targetPortName, func(c podContainer, cp containerPort) {
			ipPort := net.JoinHostPort(pod.Status.PodIP, strconv.Itoa(cp.ContainerPort))
			labels := []prompbmarshal.Label{
				{Name: "job", Value: jobName},
				{Name: "instance", Value: ipPort},
				{Name: "namespace", Value: pod.Metadata.Namespace},
				{Name: "container", Value: c.Name},
				{Name: "pod", Value: pod.Metadata.Name},
				{Name: "endpoint", Value: cp.Name},
			}
			scrapeURL := "http://" + ipPort + targetMetricsPath
			entry := targetEntry{
				Pod:       pod.Metadata.Name,
				Namespace: pod.Metadata.Namespace,
				Port:      cp.ContainerPort,
			}
			d.mu.Lock()
			d.targets[entry] = ScrapeTarget{
				URL:    scrapeURL,
				Labels: labels,
			}
			d.mu.Unlock()
		})
	case "DELETED":
		var pod pod
		if err := json.Unmarshal(event.Object, &pod); err != nil {
			logger.Errorf("cannon unmarshal object %q of event %q: %s", event.Object, event.Type, err)
			return
		}
		targetPortName := pod.Metadata.Labels["vmscrape/port"]
		targetContainer := pod.Metadata.Labels["vmscrape/container"]
		visitTargetContainers(pod.Spec.Containers, targetContainer, targetPortName, func(_ podContainer, cp containerPort) {
			entry := targetEntry{
				Pod:       pod.Metadata.Name,
				Namespace: pod.Metadata.Namespace,
				Port:      cp.ContainerPort,
			}
			d.mu.Lock()
			delete(d.targets, entry)
			d.mu.Unlock()
		})
	case "ERROR":
		logger.Errorf("got an error event from Kubernetes API: %q", string(event.Object))
	default:
		logger.Warnf("unexpected Kubernetes event type %q: %s", event.Type, string(event.Object))
	}
}

func visitTargetContainers(containers []podContainer, targetContainer, targetPortName string, f func(podContainer, containerPort)) {
	for _, c := range containers {
		if targetContainer != "" && c.Name != targetContainer {
			// Skip unneeded containers by its name if "vmscrape/container" label is set
			continue
		}
		for _, cp := range c.Ports {
			if cp.Name == targetPortName {
				f(c, cp)
				break
			}
		}
	}
}

func loadKubeAPIConfig() (*kubeAPIConfig, error) {
	cfg, loadInClusterErr := loadInClusterConfig()
	if loadInClusterErr != nil {
		cfg, loadLocalErr := loadLocalConfig()
		if loadLocalErr != nil {
			return nil, fmt.Errorf("cannot load discovery config from in-cluster config: %s; and from local config: %s", loadInClusterErr, loadLocalErr)
		}
		return cfg, nil
	}
	return cfg, nil
}

func loadInClusterConfig() (*kubeAPIConfig, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(host) == 0 || len(port) == 0 {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST/KUBERNETES_SERVICE_PORT environment variables not set")
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("cannot read in-cluster token: %s", err)
	}

	return &kubeAPIConfig{
		Server:      "https://" + net.JoinHostPort(host, port),
		BearerToken: string(token),
		GetCACert: func() (*x509.CertPool, error) {
			certs, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
			if err != nil {
				return nil, fmt.Errorf("cannot read root CA from %q: %s", err)
			}

			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(certs) {
				return nil, fmt.Errorf("cannot parse PEM encoded certificates")
			}
			return roots, nil
		},
	}, nil
}

type kubeConfig struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`

	Users []struct {
		Name string `yaml:"name"`
		User struct {
			Token                 string `yaml:"token"`
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`

	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster string `yaml:"cluster"`
			User    string `yaml:"user"`
		} `yaml:"context"`
	} `yaml:"contexts"`

	CurrentContext string `yaml:"current-context"`
}

func loadLocalConfig() (*kubeAPIConfig, error) {
	configPath := os.Getenv("KUBECONFIG")
	if configPath == "" {
		configPath = filepath.Join(os.Getenv("HOME"), ".kube", "config")
	}
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %s", configPath, err)
	}
	var config kubeConfig
	if err := yaml.Unmarshal(rawConfig, &config); err != nil {
		return nil, fmt.Errorf("cannot parse yaml %q: %s", configPath, err)
	}

	var cluster, user string
	for _, ctx := range config.Contexts {
		if ctx.Name == config.CurrentContext {
			cluster = ctx.Context.Cluster
			user = ctx.Context.User
			break
		}
	}
	var server, ca string
	for _, cl := range config.Clusters {
		if cl.Name == cluster {
			server = cl.Cluster.Server
			ca = cl.Cluster.CertificateAuthorityData
			break
		}
	}

	var token string
	var clientCert []byte
	var clientCertKey []byte
	for _, u := range config.Users {
		if u.Name != user {
			continue
		}
		token = u.User.Token

		if u.User.ClientCertificateData != "" {
			clientCert, _ = base64.StdEncoding.AppendDecode(nil, []byte(u.User.ClientCertificateData))
		}
		if u.User.ClientKeyData != "" {
			clientCertKey, _ = base64.StdEncoding.AppendDecode(nil, []byte(u.User.ClientKeyData))
		}
	}

	return &kubeAPIConfig{
		Server:        server,
		BearerToken:   token,
		ClientCert:    clientCert,
		ClientCertKey: clientCertKey,
		GetCACert: func() (*x509.CertPool, error) {
			pemCerts, err := base64.StdEncoding.AppendDecode(nil, []byte(ca))
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pemCerts) {
				return nil, fmt.Errorf("cannot parse root CA for %q cluster from %q for user %q; no certs fetched", cluster, configPath, user)
			}
			return roots, nil
		},
	}, nil
}

func (d *Discovery) NodeName() string {
	return d.currentNodeName
}

func (d *Discovery) mustInitCurrentNodeInfo() {
	namespace, err := getCurrentNamespace()
	if err != nil {
		logger.Fatalf("cannot get current namespace: %s", err)
	}

	podName, err := os.Hostname()
	if err != nil {
		logger.Fatalf("cannot get hostname: %s", err)
	}

	nodeName, err := d.getCurrentNodeName(namespace, podName)
	if err != nil {
		logger.Fatalf("cannot get current node name: %s", err)
	}

	d.currentNamespace = namespace
	d.currentNodeName = nodeName
}

func (d *Discovery) getCurrentNodeName(ns, pod string) (string, error) {
	if v := os.Getenv("VMSCRAPE_NODE_NAME"); v != "" {
		// Special case to run vmagent outside Kubernetes cluster
		return v, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	currentPod, err := d.kubeAPI.GetPod(ctx, ns, pod)
	if err != nil {
		return "", fmt.Errorf("cannont get current pod %q at namespace %q: %v", pod, ns, err)
	}
	return currentPod.Spec.NodeName, nil
}

func getCurrentNamespace() (string, error) {
	if v := os.Getenv("VMSCRAPE_NAMESPACE"); v != "" {
		// Special case to run vmagent outside Kubernetes cluster
		return v, nil
	}

	namespace, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", fmt.Errorf("cannot read current namespace: %s; use VMSCRAPE_NAMESPACE environment variable to specify a namespace to run scraping outside of the Kubernetes cluster", err)
	}
	namespace = bytes.TrimSpace(namespace)
	return string(namespace), nil
}
