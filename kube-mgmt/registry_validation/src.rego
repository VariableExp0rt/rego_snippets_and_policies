deny[msg] {
	count(valid_registry) == 0
    msg := "Denied."
}

valid_registry[res] {
    tmp := input_containers[c].image
    obj := split(tmp, "/")[0]
    res := check_match(obj, allowedRegistries)
}

check_match(obj, allowedRegistries) = obj {
    msg := {res | res := allowedRegistries[_] == obj }
    msg[i] == true
}

allowedRegistries = ["Idonotexist", "docker.io"]

test_bad_registry {
	in := {
    "apiVersion": "admission.k8s.io/v1beta1",
    "kind": "AdmissionReview",
    "oldObject": null,
    "request": {
        "kind": {
            "group": "extensions",
            "kind": "DaemonSet",
            "version": "v1beta1"
        },
        "namespace": "production",
        "object": {
            "metadata": {
                "creationTimestamp": "2019-01-18T18:10:56Z",
                "generation": 1,
                "name": "ingress-ok",
                "namespace": "production",
                "uid": "66c73498-1b4c-11e9-a7d2-080027f75b4a"
            },
            "spec": {
                "containers": [
                    {
                        "image": "docker.io/nginx",
                        "name": "nginx",
                        "resources": {}
                    },
                    {
                        "image": "quay.io/redis",
                        "name": "redis"
                    }
                ],
                "rules": [
                    {
                        "host": "signin.acmecorp.com",
                        "http": {
                            "paths": [
                                {
                                    "backend": {
                                        "serviceName": "nginx",
                                        "servicePort": 80
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        },
        "operation": "CREATE",
        "resource": {
            "group": "extensions",
            "resource": "ingresses",
            "version": "v1beta1"
        },
        "status": {
            "loadBalancer": {}
        },
        "uid": "66c738ea-1b4c-11e9-a7d2-080027f75b4a",
        "userInfo": {
            "groups": [
                "system:masters",
                "system:authenticated"
            ],
            "username": "minikube-user"
        }
    }
}

	reg := ["myprivateregistry", "doesntexist"]
    
    violation := deny
    	with input as in
        with data.kubernetes.allowedRegistries as reg
    count(violation) == 0
}
