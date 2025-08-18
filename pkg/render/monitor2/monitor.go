package monitor2

import (
	"crypto/x509"
	"fmt"
	"strings"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/components"
	"github.com/tigera/operator/pkg/render"
	"github.com/tigera/operator/pkg/render/common/authentication"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
	"github.com/tigera/operator/pkg/tls/certkeyusage"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Config contains all the config information needed to render the Monitor component.
type Config struct {
	Monitor                       operatorv1.MonitorSpec
	Installation                  *operatorv1.InstallationSpec
	PullSecrets                   []*corev1.Secret
	AlertmanagerConfigSecret      *corev1.Secret
	KeyValidatorConfig            authentication.KeyValidatorConfig
	ServerTLSSecret               certificatemanagement.KeyPairInterface
	ClientTLSSecret               certificatemanagement.KeyPairInterface
	ClusterDomain                 string
	TrustedCertBundle             certificatemanagement.TrustedBundle
	OpenShift                     bool
	KubeControllerPort            int
	FelixPrometheusMetricsEnabled bool
}

type monitorComponent struct {
	cfg               *Config
	alertmanagerImage string
	prometheusImage   string
}

func (mc *monitorComponent) ResolveImages(is *operatorv1.ImageSet) error {
	reg := mc.cfg.Installation.Registry
	path := mc.cfg.Installation.ImagePath
	prefix := mc.cfg.Installation.ImagePrefix

	errMsgs := []string{}
	var err error

	mc.alertmanagerImage, err = components.GetReference(components.ComponentPrometheusAlertmanager, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	mc.prometheusImage, err = components.GetReference(components.ComponentPrometheus, reg, path, prefix, is)
	if err != nil {
		errMsgs = append(errMsgs, err.Error())
	}

	if len(errMsgs) != 0 {
		return fmt.Errorf("%s", strings.Join(errMsgs, ","))
	}
	return nil
}

// Register secret/certs that need Server and Client Key usage
func init() {
	certkeyusage.SetCertKeyUsage(monitor.PrometheusClientTLSSecretName, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth})
}

func Monitor(cfg *Config) render.Component {
	return &monitorComponent{
		cfg: cfg,
	}
}

func (mc *monitorComponent) Ready() bool {
	return true
}

func (mc *monitorComponent) SupportedOSType() rmeta.OSType {
	return rmeta.OSTypeLinux
}

func (mc *monitorComponent) Objects() ([]client.Object, []client.Object) {
	return []client.Object{
		calicoPrometheusRulefiles0ConfigMap(),
		calicoPrometheusWebConfigSecret(),
		calicoPrometheusConfigCmConfigMap(),
		calicoPrometheusService(),
		calicoPrometheusStatefulSet(),
	}, []client.Object{}
}

func calicoPrometheusRulefiles0ConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-prometheus-rulefiles-0",
			Namespace: "tigera-prometheus",
			Labels: map[string]string{
				"prometheus-name": "calico-node-prometheus",
			},
		},
		Data: map[string]string{
			"tigera-prometheus-tigera-prometheus-dp-rate-d7c571a3-8a38-4aeb-9728-5fdf12d79c83.yaml": `groups:
- name: calico.rules
  rules:
  - alert: DeniedPacketsRate
    annotations:
      description: '{{$labels.instance}} with calico-node pod {{$labels.pod}} has
        been denying packets at a fast rate {{$labels.sourceIp}} by policy {{$labels.policy}}.'
      summary: Instance {{$labels.instance}} - Large rate of packets denied
    expr: rate(calico_denied_packets[10s]) > 50
    labels:
      severity: critical
`,
		},
	}
}

func calicoPrometheusWebConfigSecret() *corev1.Secret {
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-prometheus-web-config",
			Namespace: "tigera-prometheus",
		},
		Data: map[string][]byte{
			"web-config.yaml": []byte(""),
		},
		Type: "Opaque",
	}
}

func calicoPrometheusConfigCmConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-prometheus-config-cm",
			Namespace: "tigera-prometheus",
		},
		Data: map[string]string{
			"prometheus.yml": `global:
  scrape_interval: 15s

scrape_configs:
  - job_name: tigera-elasticsearch-metrics
    kubernetes_sd_configs:
    - role: endpoints
      namespaces:
        names:
        - tigera-elasticsearch
    relabel_configs:
      - source_labels: [__meta_kubernetes_namespace]
        action: keep
        regex: tigera-elasticsearch
      - source_labels: [__meta_kubernetes_service_label_k8s_app]
        action: keep
        regex: tigera-elasticsearch-metrics
    scrape_interval: 5s
    scrape_timeout: 5s
    scheme: https
    tls_config:
      server_name: tigera-elasticsearch-metrics
      ca_file: /etc/pki/tls/certs/tigera-ca-bundle.crt
      cert_file: /calico-node-prometheus-client-tls/tls.crt
      key_file: /calico-node-prometheus-client-tls/tls.key


    - job_name: calico-node-metrics
      honor_labels: true
      kubernetes_sd_configs:
      - role: endpoints
        namespaces:
          names:
          - calico-system
      scrape_interval: 5s
      scrape_timeout: 5s
      scheme: https
      tls_config:
        server_name: calico-node-metrics
        ca_file: /etc/pki/tls/certs/tigera-ca-bundle.crt
        cert_file: /calico-node-prometheus-client-tls/tls.crt
        key_file: /calico-node-prometheus-client-tls/tls.key
      relabel_configs:
      - source_labels:
        - job
        target_label: __tmp_prometheus_job_name
      - action: keep
        source_labels:
        - __meta_kubernetes_service_label_k8s_app
        - __meta_kubernetes_service_labelpresent_k8s_app
        regex: (calico-node|calico-node-windows);true
      - action: keep
        source_labels:
        - __meta_kubernetes_endpoint_port_name
        regex: (calico-metrics-port|calico-bgp-metrics-port|felix-metrics-port)
      - source_labels:
        - __meta_kubernetes_endpoint_address_target_kind
        - __meta_kubernetes_endpoint_address_target_name
        separator: ;
        regex: Node;(.*)
        replacement: ${1}
        target_label: node
      - source_labels:
        - __meta_kubernetes_endpoint_address_target_kind
        - __meta_kubernetes_endpoint_address_target_name
        separator: ;
        regex: Pod;(.*)
        replacement: ${1}
        target_label: pod
      - source_labels:
        - __meta_kubernetes_namespace
        target_label: namespace
      - source_labels:
        - __meta_kubernetes_service_name
        target_label: service
      - source_labels:
        - __meta_kubernetes_pod_name
        target_label: pod
      - source_labels:
        - __meta_kubernetes_pod_container_name
        target_label: container
      - action: drop
        source_labels:
        - __meta_kubernetes_pod_phase
        regex: (Failed|Succeeded)
      - source_labels:
        - __meta_kubernetes_service_name
        target_label: job
        replacement: ${1}
      - target_label: endpoint
        replacement: calico-metrics-port
      - source_labels:
        - __address__
        - __tmp_hash
        target_label: __tmp_hash
        regex: (.+);
        replacement: $1
        action: replace
      - source_labels:
        - __tmp_hash
        target_label: __tmp_hash
        modulus: 1
        action: hashmod
      - source_labels:
        - __tmp_hash
        - __tmp_disable_sharding
        regex: 0;|.+;.+
        action: keep
`,
		},
	}
}

func calicoPrometheusService() *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-prometheus",
			Namespace: "tigera-prometheus",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Ports: []corev1.ServicePort{
				{
					Name:       "web",
					Port:       9090,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromString("web"),
				},
			},
			Selector: map[string]string{
				"k8s-app2": "calico-prometheus",
			},
		},
	}
}

func calicoPrometheusStatefulSet() *appsv1.StatefulSet {
	var (
		replicas                      int32 = 1
		revisionHistoryLimit          int32 = 10
		terminationGracePeriodSeconds int64 = 600
		fsGroup                       int64 = 10001
		runAsGroup                    int64 = 10001
		runAsUser                     int64 = 10001
		defaultMode                   int32 = 420
	)
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "StatefulSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "calico-prometheus",
			Namespace: "tigera-prometheus",
		},
		Spec: appsv1.StatefulSetSpec{
			PodManagementPolicy:  appsv1.ParallelPodManagement,
			Replicas:             &replicas,
			RevisionHistoryLimit: &revisionHistoryLimit,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"k8s-app":  "tigera-prometheus",
					"k8s-app2": "calico-prometheus",
				},
			},
			ServiceName: "prometheus-operated",
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"k8s-app":  "tigera-prometheus",
						"k8s-app2": "calico-prometheus",
					},
					Annotations: map[string]string{
						"kubectl.kubernetes.io/default-container": "prometheus",
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: &[]bool{true}[0],
					Containers: []corev1.Container{
						{
							Name:  "prometheus",
							Image: "prom/prometheus:v3.4.1",
							Args: []string{
								"--config.file=/etc/prometheus/config/prometheus.yml",
								"--web.route-prefix=/",
								"--web.listen-address=127.0.0.1:9090",
								"--storage.tsdb.retention.time=24h",
								"--storage.tsdb.path=/prometheus",
								"--web.config.file=/etc/prometheus/web_config/web-config.yaml",
							},
							ImagePullPolicy: corev1.PullAlways,
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"sh",
											"-c",
											"if [ -x \"$(command -v curl)\" ]; then exec curl --fail http://localhost:9090/-/healthy; elif [ -x \"$(command -v wget)\" ]; then exec wget -q -O /dev/null http://localhost:9090/-/healthy; else exit 1; fi",
										},
									},
								},
								PeriodSeconds:    5,
								SuccessThreshold: 1,
								FailureThreshold: 6,
								TimeoutSeconds:   3,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"sh",
											"-c",
											"if [ -x \"$(command -v curl)\" ]; then exec curl --fail http://localhost:9090/-/ready; elif [ -x \"$(command -v wget)\" ]; then exec wget -q -O /dev/null http://localhost:9090/-/ready; else exit 1; fi",
										},
									},
								},
								PeriodSeconds:    5,
								SuccessThreshold: 1,
								FailureThreshold: 3,
								TimeoutSeconds:   3,
							},
							StartupProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"sh",
											"-c",
											"if [ -x \"$(command -v curl)\" ]; then exec curl --fail http://localhost:9090/-/ready; elif [ -x \"$(command -v wget)\" ]; then exec wget -q -O /dev/null http://localhost:9090/-/ready; else exit 1; fi",
										},
									},
								},
								PeriodSeconds:    15,
								SuccessThreshold: 1,
								FailureThreshold: 60,
								TimeoutSeconds:   3,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceMemory: resource.MustParse("400Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										"ALL",
									},
								},
								ReadOnlyRootFilesystem: &[]bool{true}[0],
							},
							TerminationMessagePath:   "/dev/termination-log",
							TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "config-out",
									MountPath: "/etc/prometheus/config_out",
									ReadOnly:  true,
								},
								{
									Name:      "tls-assets",
									MountPath: "/etc/prometheus/certs",
									ReadOnly:  true,
								},
								{
									Name:      "prometheus-calico-prometheus-db",
									MountPath: "/prometheus",
									SubPath:   "prometheus-db",
								},
								{
									Name:      "tigera-ca-bundle",
									MountPath: "/etc/pki/tls/certs",
									ReadOnly:  true,
								},
								{
									Name:      "calico-node-prometheus-tls",
									MountPath: "/calico-node-prometheus-tls",
									ReadOnly:  true,
								},
								{
									Name:      "calico-node-prometheus-client-tls",
									MountPath: "/calico-node-prometheus-client-tls",
									ReadOnly:  true,
								},
								{
									Name:      "calico-prometheus-rulefiles-0",
									MountPath: "/etc/prometheus/rules/calico-prometheus-rulefiles-0",
								},
								{
									Name:      "web-config",
									MountPath: "/etc/prometheus/web_config/web-config.yaml",
									ReadOnly:  true,
									SubPath:   "web-config.yaml",
								},
								{
									Name:      "calico-prometheus-config-cm",
									MountPath: "/etc/prometheus/config/",
									ReadOnly:  true,
								},
							},
						},
					},
					DNSPolicy: corev1.DNSClusterFirst,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: "tigera-pull-secret",
						},
					},
					NodeSelector: map[string]string{
						"kubernetes.io/os": "linux",
					},
					RestartPolicy: corev1.RestartPolicyAlways,
					SchedulerName: "default-scheduler",
					SecurityContext: &corev1.PodSecurityContext{
						FSGroup:      &fsGroup,
						RunAsGroup:   &runAsGroup,
						RunAsNonRoot: &[]bool{true}[0],
						RunAsUser:    &runAsUser,
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					ServiceAccountName:            "prometheus",
					ShareProcessNamespace:         &[]bool{true}[0],
					TerminationGracePeriodSeconds: &terminationGracePeriodSeconds,
					Tolerations: []corev1.Toleration{
						{
							Key:      "kubernetes.io/arch",
							Operator: corev1.TolerationOpEqual,
							Value:    "arm64",
							Effect:   corev1.TaintEffectNoSchedule,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "prometheus-calico-prometheus",
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "tls-assets",
							VolumeSource: corev1.VolumeSource{
								Projected: &corev1.ProjectedVolumeSource{
									Sources: []corev1.VolumeProjection{
										{
											Secret: &corev1.SecretProjection{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: "prometheus-calico-node-prometheus-tls-assets-0",
												},
											},
										},
									},
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "config-out",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium: corev1.StorageMediumMemory,
								},
							},
						},
						{
							Name: "calico-prometheus-rulefiles-0",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "calico-prometheus-rulefiles-0",
									},
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "calico-prometheus-config-cm",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "calico-prometheus-config-cm",
									},
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "web-config",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "calico-prometheus-web-config",
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "calico-node-prometheus-tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "calico-node-prometheus-tls",
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "calico-node-prometheus-client-tls",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  "calico-node-prometheus-client-tls",
									DefaultMode: &defaultMode,
								},
							},
						},
						{
							Name: "tigera-ca-bundle",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "tigera-ca-bundle",
									},
									DefaultMode: &defaultMode,
								},
							},
						},
					},
				},
			},
			UpdateStrategy: appsv1.StatefulSetUpdateStrategy{
				Type: appsv1.RollingUpdateStatefulSetStrategyType,
			},
			VolumeClaimTemplates: []corev1.PersistentVolumeClaim{
				{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "PersistentVolumeClaim",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "prometheus-calico-prometheus-db",
					},
					Spec: corev1.PersistentVolumeClaimSpec{
						AccessModes: []corev1.PersistentVolumeAccessMode{
							corev1.ReadWriteOnce,
						},
						Resources: corev1.VolumeResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceStorage: resource.MustParse("10Gi"),
							},
						},
						StorageClassName: &[]string{"tigera-prometheus"}[0],
						VolumeMode:       &[]corev1.PersistentVolumeMode{corev1.PersistentVolumeFilesystem}[0],
					},
				},
			},
		},
	}
}

func MonitorPolicy(cfg *Config) render.Component {
	return render.NewPassthrough(
		allowTigeraAlertManagerPolicy(cfg),
		allowTigeraAlertManagerMeshPolicy(cfg),
		allowTigeraPrometheusPolicy(cfg),
		allowTigeraPrometheusAPIPolicy(cfg),
		allowTigeraPrometheusOperatorPolicy(cfg),
		networkpolicy.AllowTigeraDefaultDeny(common.TigeraPrometheusNamespace),
	)
}

// Creates a network policy to allow traffic to Alertmanager (TCP port 9093).
func allowTigeraAlertManagerPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, v3.Rule{
		// Allows all egress traffic from AlertManager.
		Action:   v3.Allow,
		Protocol: &networkpolicy.TCPProtocol,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.AlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.AlertmanagerPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic between Alertmanagers for HA configuration (TCP port 6783).
func allowTigeraAlertManagerMeshPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.UDPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(9094),
			},
		},
	}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.MeshAlertManagerPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: alertManagerSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.UDPProtocol,
					Destination: v3.EntityRule{
						Selector: alertManagerSelector,
						Ports:    networkpolicy.Ports(9094),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access the Prometheus (TCP port 9095).
func allowTigeraPrometheusPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, []v3.Rule{
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: networkpolicy.KubeAPIServerEntityRule,
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for Felix metrics
				Ports: networkpolicy.Ports(9081, 9091),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for BGP metrics
				Ports: networkpolicy.Ports(9900),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access form QueryServer metrics
				Ports: networkpolicy.Ports(8080),
			},
		},
		{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				Selector: alertManagerSelector,
				Ports:    networkpolicy.Ports(monitor.AlertmanagerPort),
			},
		},
		{
			Action:      v3.Allow,
			Protocol:    &networkpolicy.TCPProtocol,
			Destination: render.DexEntityRule,
		},
	}...)

	if cfg.KubeControllerPort != 0 {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// Egress access for Kube controller port metrics.
				Ports: networkpolicy.Ports(uint16(cfg.KubeControllerPort)),
			},
		})
	}

	typhaMetricsPort := cfg.Installation.TyphaMetricsPort
	if typhaMetricsPort != nil {
		egressRules = append(egressRules, v3.Rule{
			Action:   v3.Allow,
			Protocol: &networkpolicy.TCPProtocol,
			Destination: v3.EntityRule{
				// dest is host networked and so the policy cannot be made more specific.
				Ports: networkpolicy.Ports(uint16(*typhaMetricsPort)),
			},
		},
		)
	}

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.PrometheusPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.PrometheusSelector,
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow traffic to access through tigera-prometheus-api
func allowTigeraPrometheusAPIPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.PrometheusEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.PrometheusAPIPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: networkpolicy.KubernetesAppSelector("tigera-prometheus-api"),
			Types:    []v3.PolicyType{v3.PolicyTypeIngress, v3.PolicyTypeEgress},
			Ingress: []v3.Rule{
				{
					Action:   v3.Allow,
					Protocol: &networkpolicy.TCPProtocol,
					Destination: v3.EntityRule{
						Ports: networkpolicy.Ports(monitor.PrometheusProxyPort),
					},
				},
			},
			Egress: egressRules,
		},
	}
}

// Creates a network policy to allow the prometheus-operatorto access the kube-apiserver
func allowTigeraPrometheusOperatorPolicy(cfg *Config) *v3.NetworkPolicy {
	egressRules := []v3.Rule{}
	egressRules = networkpolicy.AppendDNSEgressRules(egressRules, cfg.OpenShift)
	egressRules = append(egressRules, v3.Rule{
		Action:      v3.Allow,
		Protocol:    &networkpolicy.TCPProtocol,
		Destination: networkpolicy.KubeAPIServerEntityRule,
	})

	return &v3.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "projectcalico.org/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      monitor.PrometheusOperatorPolicyName,
			Namespace: common.TigeraPrometheusNamespace,
		},
		Spec: v3.NetworkPolicySpec{
			Order:    &networkpolicy.HighPrecedenceOrder,
			Tier:     networkpolicy.TigeraComponentTierName,
			Selector: "operator == 'prometheus'",
			Types:    []v3.PolicyType{v3.PolicyTypeEgress},
			Egress:   egressRules,
		},
	}
}

var alertManagerSelector = fmt.Sprintf(
	"(app == 'alertmanager' && alertmanager == '%[1]s') || (app.kubernetes.io/name == 'alertmanager' && alertmanager == '%[1]s')",
	monitor.CalicoNodeAlertmanager,
)
