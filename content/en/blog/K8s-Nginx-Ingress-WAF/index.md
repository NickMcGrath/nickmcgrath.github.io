---
title: "K8s Nginx Ingress WAF"
description: ""
excerpt: ""
date: 2023-01-09T22:03:50-08:00
lastmod: 2023-01-09T22:03:50-08:00
draft: false
weight: 50
images: ["lock-in-clouds.png"]
categories: ["kubernetes"]
tags: []
contributors: ["Nicholas McGrath"]
pinned: false
homepage: false
---

## Introduction to Technologies

NGINX is Kubernetes most popular ingress controller with powerful open source add-ons. We will be exploring using
ModSecurity engine to secure our publicly exposed services.

[NGINX by Kubernetes community](https://artifacthub.io/packages/helm/ingress-nginx/ingress-nginx) is used to control
external access to services by routing incoming traffic.

[Minikube](https://minikube.sigs.k8s.io/docs/) is a tool for running a single-node Kubernetes cluster locally on your
computer, it allows developers to test and develop applications that run on Kubernetes. It is open-source and available
for Linux, macOS and Windows.

[ModSecurity](https://github.com/SpiderLabs/ModSecurity) is an open-source web application firewall (WAF) module for the
Apache, Nginx, and IIS web servers. It can be used to protect web applications from various types of attacks, such as
SQL injection and cross-site scripting (XSS). It provides a set of rules that can be used to detect and block malicious
requests.

[ModSecurity OWASP Core Rule Set (CRS)](https://github.com/coreruleset/coreruleset) is a collection of generic attack
detection rules for the ModSecurity web application firewall (WAF). It provides protection against a wide range of known
web application vulnerabilities and misconfigurations, such as SQL injection and cross-site scripting. It is developed
and maintained by the Open Web Application Security Project (OWASP).

## Creating a service

We will use WordPress as an example application and create the ingress for the service.

This helm deployment with set up WordPress frontend with a MariaDB backend and expose the appliation internally using a
Cluster IP service.

```shell
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
helm upgrade --install wordpress bitnami/wordpress --set service.type=ClusterIP --set wordpressPassword='yolo' --version 15.2.33
```

```shell
kubectl get service
NAME                TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)         AGE
...
wordpress           ClusterIP      10.96.22.55     <none>        80/TCP,443/TCP  10m
wordpress-mariadb   ClusterIP      10.101.67.174   <none>        3306/TCP        10m
```

## Configuring our Ingress

We can edit our ingress via a config map or helm override variables, we will be using helm override variables. From the
NGNIX Ingress
controller [site](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#configmaps) we
can see the enable-modsecurity and enable-owasp-modsecurity-crs are off by default. We can also edit the
[modsecurity-snippet](https://github.com/SpiderLabs/ModSecurity/blob/v3/master/modsecurity.conf-recommended) to
configure Modsecurity to our liking.

Here is a basic example

```yaml
controller:
  config:
    # Enable Modsecurity and the OWASP Core rule set
    enable-modsecurity: "true"
    enable-owasp-modsecurity-crs: "true"
    # Update ModSecurity config and rules
    modsecurity-snippet: |
      # Enable prevention mode. Can be any of: DetectionOnly,On,Off (default is   DetectionOnly)
      SecRuleEngine On

      # Enable scanning of the request body
      SecRequestBodyAccess On
```

minikube tunnel runs as a process, creating a network route on the host to the service CIDR of the cluster using the
cluster’s IP address as a gateway. The tunnel command exposes the external IP directly to any program running on the
host operating system.

```shell
minikube tunnel
```

Applying nginx helm chart

```shell
helm repo add nginx https://helm.nginx.com/stable
helm repo update
helm install ingress-nginx -f ./nginx-helm-values.yaml ingress-nginx/ingress-nginx -n nginx-ingress --create-namespace --version 0.16.0
```

Applying ingress to WordPress service

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: wordpress-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
    - host: mynewblog.ca
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: wordpress
                port:
                  number: 80
```

Adding local DNS to route using our ingress. Open cmd as admin

```shell
notepad c:\Windows\System32\Drivers\etc\hosts
```

Append record pointing to ingress ip

```shell
127.0.0.1 mynewblog.ca
```

![mynewblog.ca site](mynewblog.png "mynewblog.ca")

