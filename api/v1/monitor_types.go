// Copyright (c) 2021-2022 Tigera, Inc. All rights reserved.
/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	v1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MonitorSpec defines the desired state of Tigera monitor.
type MonitorSpec struct {
	// ExternalPrometheusConfiguration if not nil, the operator will create a ServiceMonitor and/or other resources in
	// the namespace for your convenience. For example, this makes it possible to configure scraping from git-ops tools,
	// without needing extra tools.
	ExternalPrometheusConfiguration *ExternalPrometheusConfiguration `json:"externalPrometheusConfiguration,omitempty"`
}

type ExternalPrometheusConfiguration struct {
	// ServiceMonitor if not nil, the operator will create a ServiceMonitor object in the namespace. It is important
	// that you configure metadata.labels if you want your prometheus instance to pick up the configuration automatically.
	// The operator will configure 1 endpoint by default:
	// - Params to scrape all metrics available in Calico Enterprise.
	// - BearerTokenSecret (If not overridden, the operator will also create corresponding RBAC that allows authz to the metrics.)
	// - TLSConfig, containing the caFile and serverName.
	// All values can be overridden.
	// +optional
	ServiceMonitor *v1.ServiceMonitor `json:"serviceMonitor,omitempty"`

	// Namespace is the namespace where the operator will create resources for your Prometheus instance.
	// Default: default
	Namespace string `json:"namespace"`
}

// MonitorStatus defines the observed state of Tigera monitor.
type MonitorStatus struct {
	// State provides user-readable status.
	State string `json:"state,omitempty"`

	// Conditions represents the latest observed set of conditions for the component. A component may be one or more of
	// Ready, Progressing, Degraded or other customer types.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// Monitor is the Schema for the monitor API. At most one instance
// of this resource is supported. It must be named "tigera-secure".
type Monitor struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MonitorSpec   `json:"spec,omitempty"`
	Status MonitorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MonitorList contains a list of Monitor
type MonitorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Monitor `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Monitor{}, &MonitorList{})
}
