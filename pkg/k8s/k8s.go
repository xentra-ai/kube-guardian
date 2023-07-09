package k8s

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Policy struct {
	PodName string
	Ingress []networkingv1.NetworkPolicyIngressRule
	Egress  []networkingv1.NetworkPolicyEgressRule
}

type Client struct {
	clientset *kubernetes.Clientset
}

func New(kubeconfigPath string) (*Client, error) {
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	config, err := kubeconfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{clientset}, nil
}

func (c *Client) ApplyPolicy(policy *Policy) error {
	// Note: Retrieving the pod is omitted here for brevity.
	pod, err := c.clientset.CoreV1().Pods("default").Get(policy.PodName, metav1.GetOptions{})
	if err != nil {
		return err
	}

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

	_, err = c.clientset.NetworkingV1().NetworkPolicies(pod.Namespace).Create(netPolicy)
	return err
}
