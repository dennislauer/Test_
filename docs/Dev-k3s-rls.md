

### k3s Installation

Diese Umgebung wird aus Performanz-Gründen auf Basis von k3s (Kubernetes 1.27.2) ausgerollt und die `KUBECONFIG` unter `/etc/rancher/k3s/k3s.yaml` so angepasst, dass wir über die IP auf den Cluster zugreifen können:

```bash
export K3S_VERSION="v1.27.2+k3s1"
export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
export NODE_NAME=$(hostname)
curl -sfL https://get.k3s.io \
  | INSTALL_K3S_VERSION="${K3S_VERSION}" sh -s - \
    --disable metrics-server \
    --node-name="${NODE_NAME}" \
    --tls-san="${NODE_IP}" \
    --disable-cloud-controller \
    --write-kubeconfig-mode=0644
sudo sed -i "s/127.0.0.1/${NODE_IP}/g" "${KUBECONFIG}"
printf "\nKUBECONFIG=\"${KUBECONFIG}\"\n" | sudo tee -a /etc/environment
```

Nach ca. einer Minute kann mittels

```bash
sudo systemctl status k3s -l
```

der Status der k3s Installation überprüft werden. Nun können wir uns grundlegende Daten des Clusters anschauen:

```bash
kubectl get nodes -o wide
kubectl get nodes -o json | jq -r .items[].status.nodeInfo
kubectl get nodes -o json | jq -r .items[].status.capacity
kubectl get nodes -o json | jq -r .items[].status.allocatable
kubectl get nodes -o json | jq -r .items[].status.addresses
kubectl get nodes -o json | jq -r .items[].status.conditions
kubectl get nodes -o json | jq -r .items[].status.images[].names[]
kubectl get nodes -o json | jq -r .items[].status.daemonEndpoints
kubectl get addon -A
kubectl get pods -A --sort-by='{.metadata.namespace}'
kubectl -n kube-system get configmap coredns \
  -o yaml | grep -i "kubernetes" | tr -s "[:space:]" | cut -d " " -f 3
```

Damit die IngressClass `traefik` als Standard gesetzt wird, müssen wir das Helm Chart konfigurieren und nur zur Sicherheit k3s neustarten: 

```bash
sudo mkdir -p /var/lib/rancher/k3s/server/manifests
sudo tee /var/lib/rancher/k3s/server/manifests/traefik-config.yaml <<EOF
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    ingressClass:
      enabled: true
      isDefaultClass: true
EOF
sudo systemctl restart k3s
```

Danach können wir den Status der k3s Installation erneut überprüfen:

```bash
sudo systemctl status k3s -l
```

## helm3 installieren

Als Näcshtes werden wir `helm` installieren.

```bash
export HELM_VERSION="3.12.1"
wget -O /tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz \
  https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz
pushd /tmp
wget -O helm-v${HELM_VERSION}-linux-amd64.tmp \
  https://get.helm.sh/helm-v${HELM_VERSION}-linux-amd64.tar.gz.sha256sum
cat helm-v${HELM_VERSION}-linux-amd64.tmp \
  | grep helm-v${HELM_VERSION}-linux-amd64.tar.gz > helm-v${HELM_VERSION}-linux-amd64.sha256sum
[[ "$(sha256sum -c helm-v${HELM_VERSION}-linux-amd64.sha256sum)" == *"OK" ]] || exit 1
rm -rf helm-v${HELM_VERSION}-linux-amd64.tmp \
       helm-v${HELM_VERSION}-linux-amd64.sha256sum
popd
sudo tar -zxvf /tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz \
  --strip-components=1 \
  -C /usr/local/bin \
  linux-amd64/helm
rm -rf /tmp/helm-v${HELM_VERSION}-linux-amd64.tar.gz
sudo chown root:root /usr/local/bin/helm
sudo chmod 755 /usr/local/bin/helm
sudo ln -sf /usr/local/bin/helm /usr/local/bin/helm3
helm list --all-namespaces
```

## CoreDNS konfigurieren

Nun muss die ConfigMap des CoreDNS Dienstes modifiziert werden. Die ConfigMap von CoreDNS kann über den folgenden Befehl bearbeitet werden (Achtung: vi-Syntax!): `kubectl edit cm -n kube-system coredns`.

>---
>Selbst wenn bereits unter `NodeHosts` eine Zeile mit der NODE_IP vorhanden sein sollte, muss eine neue Zeile eingefügt werden. `NODE_IP` entspricht hierbei dem Wert der gleichnamigen Variablen.
> 
>---

```bash 
NODE_IP vault.local.test harbor.local.test notary.local.test gitlab.local.test registry.local.test kas.local.test minio.local.test longhorn.local.test tekton.local.test keycloak.local.test
```

Anschließend die CoreDNS Pods neustarten:

```bash
kubectl get pods -n kube-system | grep -i "coredns"
coredns=$(kubectl get pods -n kube-system | grep -i "coredns" | cut -d' ' -f1)
for pod in ${coredns}; do
  kubectl delete pods -n kube-system "${pod}"
done
unset coredns
```

## Longhorn

```bash
sudo apt update -y
sudo apt install -y \
  open-iscsi
```

### Longhorn via `helm` installieren

```bash
helm repo add longhorn https://charts.longhorn.io
helm repo update
helm search repo longhorn | grep -i "longhorn/longhorn"
# helm show values longhorn/longhorn
export LONGHORN_VERSION="1.4.2"
longhorn_helm_version=$(helm search repo longhorn | grep -i "longhorn/longhorn" | grep -i "${LONGHORN_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install longhorn longhorn/longhorn \
  --namespace longhorn-system \
  --create-namespace \
  --timeout 600s \
  --version "${longhorn_helm_version}" \
  --set enablePSP=false \
  --set ingress.enabled=true \
  --set ingress.ingressClassName=traefik \
  --set ingress.host=longhorn.local.test
sudo sed -i '/^127.0.0.1/ s/$/ longhorn.local.test/' /etc/hosts
unset longhorn_helm_version
```

Mittels `kubectl get pods -n longhorn-system` können wir den Status der Pods und nach einiger Zeit mittels `curl -k -L https://longhorn.local.test` die Verbindung überprüfen.

### Longhorn Storage Classes konfigurieren und erstellen

Standardmäßig wird `longhorn` als Default Storage Class gesetzt. Diese sieht drei Replikas vor, was bei einem einzelnen Knoten sinnlos ist. Daher erstellen wir eine Storage Class vom Typ `driver.longhorn.io` mit dem Namen `longhorn-single`, welche nur eine Replika vorsieht, aber ebenfalls nicht die Default Storage Class sein soll:

```yaml
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: longhorn-single
  annotations:
    storageclass.kubernetes.io/is-default-class: "false"
provisioner: driver.longhorn.io
reclaimPolicy: "Delete"
allowVolumeExpansion: true
volumeBindingMode: Immediate
parameters:
  numberOfReplicas: "1"
  staleReplicaTimeout: "30"
  fsType: "ext4"
  dataLocality: "disabled"
EOF
```

Nun können wir uns alle Storage Classes anzeigen lassen:

```bash
kubectl get storageclass
```

>---
>Wir können erst fortfahren, sobald alle drei Storage Classes `local-path`, `longhorn` und `longhorn-single` vorhanden sind.
> 
>---

Damit hätten wir mit `local-path` (von k3s) und `longhorn` zwei Storage Classes als Default gesetzt. Wir wollen aber nur `local-path` als Default setzen, daher:

```bash
kubectl patch storageclass longhorn -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}'
kubectl patch storageclass longhorn-single -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"false"}}}'
kubectl patch storageclass local-path -p '{"metadata": {"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
kubectl get storageclass
```

## Vault installieren

### Vault CLI installieren

Wir installieren zuerst die CLI von vault, um leichter mit der Vault-Instanz im Cluster kommunizieren zu können:

```bash
sudo apt update -y
sudo apt install -y \
  gpg
wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg >/dev/null
gpg --no-default-keyring --keyring /usr/share/keyrings/hashicorp-archive-keyring.gpg --fingerprint
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update
sudo apt install -y \
  vault
```

### Vault via `helm` installieren

Nun installieren wir Vault im k3s-Cluster via `helm`:

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm search repo vault | grep -i "hashicorp/vault"
# helm show values hashicorp/vault
export VAULT_VERSION="1.14.0"
vault_helm_version=$(helm search repo vault | grep -i "hashicorp/vault" | grep -i "${VAULT_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install vault hashicorp/vault \
  --namespace vault \
  --create-namespace \
  --timeout 600s \
  --version "${vault_helm_version}" \
  --set server.dataStorage.size=1Gi \
  --set server.ingress.enabled=true \
  --set server.ingress.hosts[0].host=vault.local.test \
  --set ui.enabled=true \
  --set server.ha.enabled=false \
  --set server.ha.replicas=3 \
  --set server.logLevel="trace" \
  --set injector.enabled=false
unset vault_helm_version
sudo sed -i '/^127.0.0.1/ s/$/ vault.local.test/' /etc/hosts
```

Mittels `kubectl get pods -n vault` können wir den Status des Pods und nach einiger Zeit mittels `curl -k -L https://vault.local.test` die Verbindung überprüfen.

Der Status von `vault-0` (`kubectl get pods -n vault`) wird ohne Eingriff bei `0/1` verbleiben. Dies ist normal, da das Vault standardmäßig verschlossen ist, siehe auch `kubectl -n vault logs vault-0`.

```bash
core: security barrier not initialized
core: seal configuration missing, not initialized
``` 

Da wir die CLI installiert haben, wollen wir direkt mit `vault` arbeiten. Zuerst exportieren wir die Addresse, unter welcher Vault erreichbar ist, bevor wir den Status abfragen.

```bash
export VAULT_ADDR="http://$(kubectl get ing -n vault vault -o jsonpath='{.spec.rules[].host}')"
vault status
```

