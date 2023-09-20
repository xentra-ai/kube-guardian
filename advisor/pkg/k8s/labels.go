package k8s

import (
	"context"
	"fmt"
	"reflect"

	api "github.com/arx-inc/advisor/pkg/api"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DetectLabels detects the labels of a pod.
func DetectSelectorLabels(clientset *kubernetes.Clientset, origin interface{}) (map[string]string, error) {

	fmt.Println(reflect.TypeOf(origin))
	// You can use type assertion to check the specific type
	switch o := origin.(type) {
	case *v1.Pod:
		return GetOwnerRef(clientset, o)
	case *api.PodDetail:
		return GetOwnerRef(clientset, &o.Pod)
	case *api.SvcDetail:
		var svc v1.Service
		svc = o.Service
		return svc.Spec.Selector, nil
	default:
		return nil, fmt.Errorf("unknown type")
	}
}

func GetOwnerRef(clientset *kubernetes.Clientset, pod *v1.Pod) (map[string]string, error) {
	ctx := context.TODO()
	// Check if the& Pod has an owner
	if len(pod.OwnerReferences) > 0 {
		owner := pod.OwnerReferences[0]

		// Based on the owner, get the controller object to check its labels
		switch owner.Kind {
		case "ReplicaSet":
			replicaSet, err := clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			deployment, err := clientset.AppsV1().Deployments(pod.Namespace).Get(ctx, replicaSet.OwnerReferences[0].Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return deployment.Spec.Selector.MatchLabels, nil

		case "StatefulSet":
			statefulSet, err := clientset.AppsV1().StatefulSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return statefulSet.Spec.Selector.MatchLabels, nil

		case "DaemonSet":
			daemonSet, err := clientset.AppsV1().DaemonSets(pod.Namespace).Get(ctx, owner.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}
			return daemonSet.Spec.Selector.MatchLabels, nil

		// Add more controller kinds here if needed

		default:
			return nil, fmt.Errorf("unknown or unsupported owner kind: %s", owner.Kind)
		}
	}
	return pod.Labels, nil
}
