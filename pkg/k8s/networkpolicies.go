package k8s

import (
	"fmt"
	"yaml"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateNetworkPolicy() {

	netPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.PodName + "-policy",
			Namespace: pod.Namespace,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: pod.Labels,
			},
			Ingress: policy.Ingress,
			Egress:  policy.Egress,
		},
	}
	fmt.Println("Creating Network Policy...")

	netPolicyYAML, err := yaml.Marshal(netPolicy)
	if err != nil {
		panic(err)
	}
}
