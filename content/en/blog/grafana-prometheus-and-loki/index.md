---
title: "K8s Installing Grafana Prometheus and Loki"
description: ""
excerpt: ""
date: 2023-01-15T19:25:45-08:00
lastmod: 2023-01-15T19:25:45-08:00
draft: false
weight: 50
images: ["raining-docs2.png"]
categories: []
tags: []
contributors: []
pinned: false
homepage: false
---

## Logging and Monitoring in k8s

Logging and monitoring in Kubernetes are important for understanding the behavior and performance of a cluster. Logging
allows tracking events and activities, while monitoring provides real-time visibility into the resource usage,
performance, and availability of the cluster and its components. Together, they help detect and diagnose issues,
troubleshoot problems and ensure the cluster is running smoothly.

**Prometheus** is an open-source monitoring and alerting system. It collects metrics from monitored targets by scraping
metrics HTTP endpoints on these targets. It stores all scraped samples locally and runs rules over this data to either
aggregate and record new time series from existing data or generate alerts.

**Grafana** is an open-source visualization and analytics platform. It allows you to query, visualize, and alert on
metrics and logs no matter where they are stored. It supports various data sources, including Prometheus, and can be
used to create dashboards for analyzing and monitoring metrics.

**Loki** is an open-source, horizontally-scalable, highly-available, multi-tenant log aggregation system inspired by
Prometheus. It is designed to be very cost-effective and easy to operate, as it does not index the contents of the logs,
but rather a set of labels for each log stream. It allows to search and analyze logs by labels, which can be used as a
replacement for Prometheus metrics for certain use cases.

### Installing kube-prometheus-stack

prom-values.yaml

```yaml
prometheus:
  prometheusSpec:
    # picks up metrics of service monitors
    serviceMonitorSelectorNilUsesHelmValues: false
    serviceMonitorSelector: { }
    serviceMonitorNamespaceSelector: { }

grafana:
  sidecar:
    datasources:
      defaultDatasourceEnabled: true
  additionalDataSources:
    - name: Loki
      type: loki
      url: http://loki-loki-distributed-query-frontend.monitoring:3100

```

```shell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install prom prometheus-community/kube-prometheus-stack -n monitoring --create-namespace --values prom-values.yaml --version 44.2.1
```

### Installing prom-tail

promtail-values.yaml

```yaml
config:
  serverPort: 80
  clients:
    - url: http://loki-loki-distributed-gateway/loki/api/v1/push

```

```shell
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm upgrade --install promtail grafana/promtail -f promtail-values.yaml -n monitoring --version 6.8.1
```

### Installing loki

```shell
helm upgrade --install loki grafana/loki-distributed -n monitoring --version 0.69.1
```

### Viewing Grafana

```shell
kubectl port-forward service/prom-grafana 3000:80 -n monitoring
```

The default login to Grafana is user "admin" password "prom-operator".
