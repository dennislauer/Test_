# Disclaimer

>---
>Diese Dokumentation wurde in einer virtuellen Instanz von [Ubuntu 22.04.2 LTS (64bit)](https://releases.ubuntu.com/jammy/) getestet, welche wir gleich zu Beginn auf den aktuellen Stand bringen werden. Es bietet sich an, eine Installation mit grafischer Oberfläche zu wählen, um mit den Komponenten mittel UI interagieren zu können. Der Einsatz der Server-Variante und das saubere Routing der einzelnen Komponenten "nach außen", d.h. sodass sie von dem Host der virtuellen Maschine aus erreichbar sind, wird empfohlen. Es handelt sich nicht um eine Anleitung für eine gekapselte Air-Gapped Installation. Da es sich um eine einzelne virtuelle Instanz handelt, konnte und wurde keine Hochverfügbarkeit getestet. Es wurde primär mit selbstsignierten oder automatisch erstellten Zertifikaten gearbeitet und oftmals die Verifikation der Zertifikate deaktiviert. Daher ausdrücklich der Hinweis, dass es sich hierbei um eine Dokumentation einer Testumgebung handelt. In diesem Dokument wird keine Produktivumgebung beschrieben!
> 
>```bash
>uname -a
>Linux ubuntu 5.15.0-70-generic #77-Ubuntu SMP Tue Mar 21 14:02:37 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
>```
> 
>---

# Vorbereitung

- Virtuelle Maschine auf Basis von VirtualBox
- Dimensionierung der virtuellen Maschine:
  + 4 - 6 CPUs
  + 12GB - 16GB Arbeitspeicher
  + 80GB Festplatte
- [Ubuntu 22.04.2 LTS (64bit)](https://releases.ubuntu.com/jammy/)

# Installationsanleitung für Tools und Komponenten

>---
>Der Zeitaufwand hängt von der Performanz des Hosts der virtuellen Maschine sowie der Internetanbindung ab. Bitte rechnen Sie mit ca. 1,5 Stunden.
> 
>---

## Übersicht

In dieser Dokumentation wird die Installation und Konfiguration der folgenden Tools und Komponenten besprochen:

1. k3s als leichtgewichtige Alternative zu rke2. Beides sind zertifizierte Kubernetes Distributionen von Rancher und daher auf Plattformsicht hinreichend vergleichbar.
2. Longhorn als persistenten Speicherlayer. k3s bringt einen persistenten Speicherlayer mit, rke2 aber nicht, daher soll hier dies auch gezeigt werden.
3. Vault als Schlüsselspeicher, um sensible Variablen sicher ablegen zu können.
4. Harbor als Container Registry, um die Container Images zur Verwendung im Cluster ablegen zu können.
5. Tekton als CI/CD Komponente.
6. Gitlab als Quellcode-Verwaltungssystem.
7. ExternalSecrets Operator zur Bereitstellung der in Vault gespeicherten Secrets innerhalb der Plattform.
8. Keycloak als Identity Provider.
9. Linkerd als Service Mesh zur Ermöglichung von mTLS innerhalb des Clusters.

## Umgebungsvariablen:

>---
>Es ist zu beachten, dass durch das Schließen eines Terminals alle Umgebungsvariablen gelöscht bzw. zurückgesetzt werden. Hierauf ist zu achten und bei Bedarf die entsprechenden Variablen (mit `export` gekennzeichnet) nachziehen, ggf. auch manuell. Die folgende Variable ist nur eine von vielen!
> 
>---

```bash
printf '\nPATH="/usr/local/bin:$PATH"\n' | sudo tee -a /root/.bashrc
```

## Installation grundlegender Software 

```bash
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y \
  nano \
  wget \
  jq \
  git
```

## k3s installieren

### Vorbereitungen

Dynamische Bestimmung der IP unserer Instanz:

```bash
export NODE_IP=$(ip -4 -o a | grep -i "ens3" | tr -s ' ' | cut -d ' ' -f4 | cut -d '/' -f1)
```

Nun müssen wir mittels `echo "${NODE_IP}"` überprüfen, ob die IP richtig ausgelesen wurde, ob die IP richtig ausgelesen wurde. Falls nicht, so korrigieren wir dies manuell mittels `NODE_IP="X.X.X.X"`, wobei `X.X.X.X` die aktuelle IP ist.

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

Zum Entsperren muss zuerst Vault initialisiert und sogenannten `Unseal Keys` erzeugt werden. Da wir die CLI installiert haben, müssen wir nicht mit 

```bash
kubectl exec -ti vault-0 -n vault -- vault operator init
```

das Vault initialisieren, sondern können direkt

```bash
vault operator init
```

nutzen. `Unseal Keys` und `Initial Root Token` müssen gesichert werden. Sie werden später immer wieder benötigt. Bei einer Neuinstallation werden sie neu generiert. Von diesen `Unseal Keys` müssen nach einem Neustart, etc. mindestens drei eingegeben werden (können). Hierzu dreimal den Befehl:

```bash
vault operator unseal
```

ausführen und jeweils einen `Unseal Key` eingeben. Auch hier müssen wir nicht mehr über `exec` in den Container gehen, um das Vault zu entsperren (`kubectl exec -ti vault-0 -n vault -- vault operator unseal`). Man muss insgesamt drei unterschiedliche `Unseal Keys` eingeben.

Der dargestellte `Root Key` wird von Vault nicht persistiert, sondern aus mindestens drei der `Unseal Keys` rekonstruiert. Ist dies nicht möglich, bleibt das Vault für immer versiegelt. Neue Unseal Keys können erzeugt werden, siehe `vault operator rekey`. Die folgende Schritte erfordern, dass wir uns am Vault mit dem `Initial Root Token` einloggen:

```bash
export VAULT_ADDR="http://$(kubectl get ing -n vault vault -o jsonpath='{.spec.rules[].host}')"
vault login
```

Dieser Schritt ist nach einer gewissen Zeit der Inaktivität ggf. erneut erforderlich.

### Einrichten der Key/Value Secret Engine zum Ablegen von einfachen Secrets im Pfad `kv/`

```bash
vault secrets enable -path=kv -version=2 kv
```

### Einrichten der Kubernetes Authentifizierungsmethode im Pfad `kubernetes`

```bash
vault auth enable -path=kubernetes kubernetes
```

### Konfigurieren einer `kubernetes` Authentifizierungsmethode

```bash
vault auth tune -default-lease-ttl=72h kubernetes/
```

## Harbor installieren und konfigurieren

Die folgenden Schritte dienen der Installation und Konfiguration von Harbor:

```bash
export HARBOR_URL="https://harbor.local.test"
helm repo add harbor https://helm.goharbor.io
helm repo update
helm search repo harbor | grep -i "harbor/harbor"
# helm show values harbor/harbor
export HARBOR_VERSION="2.8.2"
harbor_helm_version=$(helm search repo harbor | grep -i "harbor/harbor" | grep -i "${HARBOR_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install harbor harbor/harbor \
  --namespace harbor \
  --create-namespace \
  --timeout 600s \
  --version "${harbor_helm_version}" \
  --set notary.enabled=false \
  --set expose.ingress.hosts.core=harbor.local.test \
  --set expose.ingress.hosts.notary=notary.local.test \
  --set externalURL=https://harbor.local.test \
  --set persistence.persistentVolumeClaim.registry.size=5Gi \
  --set persistence.persistentVolumeClaim.chartmuseum.size=1Gi \
  --set persistence.persistentVolumeClaim.jobservice.jobLog.size=1Gi \
  --set persistence.persistentVolumeClaim.jobservice.scanDataExports.size=1Gi \
  --set persistence.persistentVolumeClaim.database.size=1Gi \
  --set persistence.persistentVolumeClaim.redis.size=1Gi \
  --set persistence.persistentVolumeClaim.trivy.size=1Gi
unset harbor_helm_version
sudo sed -i '/^127.0.0.1/ s/$/ harbor.local.test notary.local.test/' /etc/hosts
```

### Hinzufügen der Harbor-Zertifikate zum Trust Store des Betriebssystems.

```bash
kubectl get secret \
  -n harbor harbor-ingress \
  -o jsonpath='{.data.ca\.crt}' | base64 --decode > /tmp/harbor-ingress-ca.crt
kubectl get secret \
  -n harbor harbor-ingress \
  -o jsonpath='{.data.tls\.crt}' | base64 --decode > /tmp/harbor-ingress-tls.crt
kubectl get secret \
  -n harbor harbor-ingress \
  -o jsonpath='{.data.tls\.key}' | base64 --decode > /tmp/harbor-ingress-tls.key
sudo mv /tmp/harbor-ingress-ca.crt \
        /tmp/harbor-ingress-tls.crt \
        /tmp/harbor-ingress-tls.key \
        /usr/local/share/ca-certificates
sudo update-ca-certificates
```

### Harbor für k3s einrichten

>---
>Bevor wir fortfahren, müssen wir mittels `watch kubectl get pods -n harbor` überprüfen, ob alle Pods korrekt gestartet werden konnten. Dies kann einige Zeit dauern und zwischenzeitliche Neustarts sind normal.
> 
>---

```bash
tee /etc/rancher/k3s/registries.yaml <<EOF
mirrors:
  $(printf "${HARBOR_URL}" | cut -d'/' -f3-):
    endpoint:
      - "${HARBOR_URL}"
configs:
  "$(printf "${HARBOR_URL}" | cut -d'/' -f3-)":
    tls:
      cert_file: /usr/local/share/ca-certificates/harbor-ingress-tls.crt
      key_file: /usr/local/share/ca-certificates/harbor-ingress-tls.key
      ca_file: /usr/local/share/ca-certificates/harbor-ingress-ca.crt
EOF
sudo systemctl restart k3s
```

### Verbindung und Status überprüfen

Danach können wir den Status der k3s Installation erneut überprüfen:

```bash
sudo systemctl status k3s -l
```

Mittels `watch kubectl get pods -n harbor` können wir den Status der Pods und nach einiger Zeit mittels `curl -k -L https://harbor.local.test` die Verbindung überprüfen.

### Admin Credentials im Vault speichern

```bash
export HARBOR_ADMIN_NAME="admin"
export HARBOR_ADMIN_PASSWORD=$(kubectl -n harbor get secret harbor-core -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 --decode)
export HARBOR_ADMIN_TOKEN=$(echo -n "${HARBOR_ADMIN_NAME}:${HARBOR_ADMIN_PASSWORD}" | base64)
vault kv put "kv/harbor" adminUserName="${HARBOR_ADMIN_NAME}"
vault kv patch "kv/harbor" adminUserPassword="${HARBOR_ADMIN_PASSWORD}"
vault kv patch "kv/harbor" adminUserToken="${HARBOR_ADMIN_TOKEN}"
vault kv get "kv/harbor"
```

Nun werden wir ein Projekt in Harbor sowie den Token-gesicherten Zugriff darauf einrichten.

### Privates Projekt anlegen

```bash
export HARBOR_ADMIN_NAME="admin"
export HARBOR_ADMIN_PASSWORD=$(kubectl -n harbor get secret harbor-core -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 --decode)
export HARBOR_ADMIN_TOKEN=$(echo -n "${HARBOR_ADMIN_NAME}:${HARBOR_ADMIN_PASSWORD}" | base64)
export PRIVATE_HARBOR_PROJECT_NAME="privates-projekt"
curl \
  --request POST \
  --header "Authorization: Basic ${HARBOR_ADMIN_TOKEN}" \
  --header "Content-Type: application/json" \
  --data "{\"project_name\": \"${PRIVATE_HARBOR_PROJECT_NAME}\", \"metadata\": {\"public\": \"false\", \"auto-scan\": \"true\"}}" \
  -k \
  https://harbor.local.test/api/v2.0/projects
```

### Robot Account für privates Projekt anlegen und den Token generieren

```bash
export HARBOR_URL="https://harbor.local.test"
export HARBOR_ADMIN_NAME="admin"
export HARBOR_ADMIN_PASSWORD=$(kubectl -n harbor get secret harbor-core -o jsonpath='{.data.HARBOR_ADMIN_PASSWORD}' | base64 --decode)
export HARBOR_ADMIN_TOKEN=$(echo -n "${HARBOR_ADMIN_NAME}:${HARBOR_ADMIN_PASSWORD}" | base64)
export PRIVATE_HARBOR_PROJECT_NAME="privates-projekt"
private_harbor_robot_name="privat"
harbor_url_short_name=$(printf "${HARBOR_URL}" | cut -d'/' -f3-)
export PRIVATE_HARBOR_ROBOT_FULL_NAME='robot$'"${PRIVATE_HARBOR_PROJECT_NAME}"'+'"${private_harbor_robot_name}"
export PRIVATE_HARBOR_ROBOT_MAIL="${PRIVATE_HARBOR_PROJECT_NAME}@${harbor_url_short_name}"
unset harbor_url_short_name
tee /tmp/robot.json <<EOF
{
  "disable": false,
  "name": "${private_harbor_robot_name}",
  "level": "project",
  "duration": -1,
  "description": "Robot Account des privaten Projekts",
  "permissions": [
    {
      "access": [
        {"action": "create", "resource": "scan"},
        {"action": "list", "resource": "repository"},
        {"action": "push", "resource": "repository"},
        {"action": "pull", "resource": "repository"},
        {"action": "list", "resource": "artifact"},
        {"action": "create", "resource": "tag"},
        {"action": "delete", "resource": "tag"}
      ],
      "kind": "project",
      "namespace": "${PRIVATE_HARBOR_PROJECT_NAME}"
    }
  ]
}
EOF
unset private_harbor_robot_name
export PRIVATE_HARBOR_ROBOT_TOKEN=$(curl -k -X "POST" \
  "${HARBOR_URL}/api/v2.0/robots" \
  -H "Authorization: Basic ${HARBOR_ADMIN_TOKEN}" \
  -H "accept: application/json" \
  -H "Content-Type: application/json" \
  -d @/tmp/robot.json \
  | jq -r '.secret')
rm -rf /tmp/robot.json
private_harbor_robot_auth=$(printf "${PRIVATE_HARBOR_ROBOT_FULL_NAME}:${PRIVATE_HARBOR_ROBOT_TOKEN}" | tr -d '\n' | base64)
export PRIVATE_HARBOR_DOCKERCONFIGJSON=$(printf "{\"auths\":{\"${HARBOR_URL}\":{\"username\":\"${PRIVATE_HARBOR_ROBOT_FULL_NAME}\",\"password\":\"${PRIVATE_HARBOR_ROBOT_TOKEN}\",\"email\":\"${PRIVATE_HARBOR_ROBOT_MAIL}\",\"auth\":\"${private_harbor_robot_auth}\"}}}" | tr -d '\n' | base64)
unset private_harbor_robot_auth
```

Da das oben erstellte JSON schlecht lesbar ist, schauen wir es uns nochmal genauer mit Hilfe von `jq` an, um die Korrektheit der Angaben zu überprüfen:

```bash
printf "${PRIVATE_HARBOR_DOCKERCONFIGJSON}" | base64 --decode | jq -r .
```

### Credentials für das Private Repo im Vault speichern

```bash
vault kv put "kv/demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}" robotName="${PRIVATE_HARBOR_ROBOT_FULL_NAME}"
vault kv patch "kv/demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}" robotToken="${PRIVATE_HARBOR_ROBOT_TOKEN}"
vault kv patch "kv/demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}" .dockerconfigjson="${PRIVATE_HARBOR_DOCKERCONFIGJSON}"
vault kv get "kv/demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}"
```

>---
>An dieser Stelle haben wir etwas vorausgegriffen: `demo` bezeichnet hier den Kubernetes Namespace, den wir mit diesem Harbor-Projekt verknüfen wollen. Aber den Namespace selbst werden wir erst später anlegen. Das ist jedoch kein Problem. Der Aufbau des Vaults ist in dieser Dokumentation sehr einfach gehalten und wird in einer produktiven Umgebung komplexer sein. Der Aufbau und die Einrichtung aller Komponenten liegen beim Betreiber der Plattform, nicht dem Endnutzer.
> 
>---

## Tekton und Tekton CLI installieren

Wir werden zuerst das CI/CD Tool Tekton selbst installieren:

```bash
export TEKTON_VERSION="0.49.0"
kubectl apply -f https://github.com/tektoncd/pipeline/releases/download/v${TEKTON_VERSION}/release.yaml
```

Nun können wir die zugehörige Tekton CLI `tkn` als Plugin zu `kubectl` installieren:

```bash
export TEKTON_CLI_VERSION="0.31.1"
wget -O /tmp/tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tar.gz \
  https://github.com/tektoncd/cli/releases/download/v${TEKTON_CLI_VERSION}/tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tar.gz
pushd /tmp
wget -O tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tmp \
  https://github.com/tektoncd/cli/releases/download/v${TEKTON_CLI_VERSION}/checksums.txt
cat tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tmp \
  | grep tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tar.gz > tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.checksums
[[ "$(sha256sum -c tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.checksums)" == *"OK" ]] || exit 1
rm -rf tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tmp \
       tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.checksums
popd
sudo tar -zxvf /tmp/tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tar.gz \
  -C /usr/local/bin \
  tkn
rm -rf /tmp/tkn_${TEKTON_CLI_VERSION}_Linux_x86_64.tar.gz
sudo chown root:root /usr/local/bin/tkn
sudo chmod 755 /usr/local/bin/tkn
sudo ln -sf /usr/local/bin/tkn /usr/local/bin/kubectl-tkn
kubectl plugin list
```

## Tekton Dashboards

### Installation des Dashboards

Wir installieren zuerst das Dashboard:

```bash
export TEKTON_DASHBOARD_VERSION="0.37.0"
kubectl apply -f https://github.com/tektoncd/dashboard/releases/download/v${TEKTON_DASHBOARD_VERSION}/release.yaml
sudo sed -i '/^127.0.0.1/ s/$/ tekton.local.test/' /etc/hosts
```

Mittels `kubectl get pods -n tekton-pipelines` können wir den Status der Pods und nach einiger Zeit mittels `curl -k -L https://tekton.local.test` die Verbindung überprüfen. Die Verbindung wird scheitern, da kein Ingress angelegt wurde. Nachdem wir dies nachgezogen haben, können wir erneut die Verbindung testen.

### Anlegen des fehlenden Ingress auf das Dashboard für traefik

```yaml
kubectl apply -n tekton-pipelines -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tekton-dashboard
  namespace: tekton-pipelines
spec:
  ingressClassName: "traefik"
  rules:
  - host: tekton.local.test
    http:
      paths:
      - pathType: ImplementationSpecific
        backend:
          service:
            name: tekton-dashboard
            port:
              number: 9097
EOF
```

## Gitlab installieren & konfigurieren

```bash
helm repo add gitlab https://charts.gitlab.io
helm repo update
helm search repo gitlab | grep -i "gitlab/gitlab"
# helm show values gitlab/gitlab
export GITLAB_VERSION="16.1.0"
gitlab_helm_version=$(helm search repo gitlab | grep -i "gitlab/gitlab " | grep -i "${GITLAB_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install gitlab gitlab/gitlab \
  --namespace gitlab \
  --create-namespace \
  --timeout 600s \
  --version "${gitlab_helm_version}" \
  --set global.edition=ce \
  --set global.hosts.domain=local.test \
  --set global.hosts.https=true \
  --set global.ingress.configureCertmanager=false \
  --set global.ingress.provider=traefik \
  --set global.ingress.enabled=true \
  --set global.ingress.class=traefik \
  --set global.registry.enabled=false \
  --set global.appConfig.defaultProjectsFeatures.containerRegistry=false \
  --set registry.enabled=false \
  --set unicorn.registry.enabled=false \
  --set gitlab.sidekiq.registry.enabled=false \
  --set gitlab.gitaly.persistence.size=2Gi \
  --set gitlab.sidekiq.resources.requests.cpu=250m \
  --set gitlab.webservice.resources.requests.cpu=100m \
  --set gitlab-runner.install=false \
  --set nginx-ingress.enabled=false \
  --set certmanager.install=false \
  --set shared-secrets.enabled=true \
  --set postgresql.image.tag=13.6.0 \
  --set global.grafana.enabled=false \
  --set global.kas.enabled=false \
  --set prometheus.install=false
unset gitlab_helm_version
sudo sed -i '/^127.0.0.1/ s/$/ gitlab.local.test minio.local.test/' /etc/hosts
```

### Automatisch erzeugte Zertifikate und CA dem Trust Store hinzufügen

```bash
kubectl -n gitlab get secret gitlab-wildcard-tls-ca \
        -ojsonpath='{.data.cfssl_ca}' \
  | base64 --decode \
  | sudo tee -a /usr/local/share/ca-certificates/gitlab.local.test.ca.crt
kubectl -n gitlab get secret gitlab-wildcard-tls-chain \
        -ojsonpath='{.data.gitlab\.local\.test\.crt}' \
  | base64 --decode \
  | sudo tee -a /usr/local/share/ca-certificates/gitlab.local.test.crt
sudo update-ca-certificates
```

### Verbindung und Status überprüfen

Mittels `kubectl get pods -n gitlab` können wir den Status des Pods und nach einiger Zeit mittels `curl -L "https://gitlab.local.test"` die Verbindung überprüfen.

### Erstkonfiguration von Gitlab

Um Gitlab initial einzurichten, benötigen wir zuerst das Einmalpasswort. Dieses können wir mittels:

```bash
kubectl -n gitlab get secret gitlab-gitlab-initial-root-password \
  -ojsonpath='{.data.password}' \
  | base64 --decode
```

auslesen. Danach rufen wir im Browser `https://gitlab.local.test` auf, loggen uns mit `root` als Benutzername und dem eben ausgelesenen Passwort ein und richten Gitlab ein.

## ExternalSecrets Operator installieren

Zuerst installieren wir den ExternalSecrets Operator via `helm`. Sollten bei der Installation von Vault Fehler aufgetreten sein, so muss dieses Kapitel übersprungen werden.

```bash
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm search repo external-secrets | grep -i "external-secrets/external-secrets"
# helm show values external-secrets/external-secrets
export ESO_VERSION="0.9.0"
eso_helm_version=$(helm search repo external-secrets | grep -i "external-secrets/external-secrets" | grep -i "${ESO_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets \
  --create-namespace \
  --timeout 600s \
  --version "${eso_helm_version}"
unset eso_helm_version
```

### Authentifizierung via Kubernetes in Vault einrichten 

```bash
vault auth enable -path=kubernetes kubernetes
```

Bei der Authentifizierung über Kubernetes greift Vault auf die TokenReview API des Kubenretes Clusters zu und überprüft, ob ein übergebener ServiceAccount JSON Web Token eines SecretStores existiert. Damit wird validiert, dass die Anfrage aus dem korrekten Cluster kommt. Aus diesem Grund müssen wir für Vault einen ServiceAccount erstellen, der Zugriff auf die TokenReview API ermöglicht. Die benötigte Rolle, die dies ermöglicht, ist die Rolle `system:auth-delegator`. Aus diesem Grund erstellen wir einen ServiceAccount und ein ClusterRoleBinding, der auf diese Rolle verweist. Es ist zu beachten, dass Secrets für ServiceAccounts seit Kubernetes 1.24 nicht mehr automatisch erstellt werden, weshalb wir manuell ein Secret erzeugen müssen, um ein JSON Web Token zu erhalten.

```yaml
kubectl apply -f -<<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-auth
  namespace: external-secrets
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: role-tokenreview-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: vault-auth
    namespace: external-secrets
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-auth-token
  namespace: external-secrets
  annotations:
    kubernetes.io/service-account.name: vault-auth
type: kubernetes.io/service-account-token
EOF
```

Nun muss die Authentifizierungsmethode `kubernetes` noch konfiguriert werden. Damit Vault die Kubernetes TokenReview API nutzen kann, benötigt man folgende Informationen:

1. den Service Account Token: `jwt_token=$(kubectl get secret vault-auth-token -n external-secrets -o jsonpath='{$.data.token}' | base64 --decode | sed $'s/$/\\\n/g')`
2. das CA-Cert des Clusters: `kubernetes_ca_cert="$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 --decode)"`
3. den Host des Kubenetes Clusters: `kubernetes_host="https://kubernetes.default.svc:443"`

Nun kann die Authentifizierungsmethode konfiguriert werden, indem die Informationen an den Endpunkt `/config` der Authentifizierungsmethode geschrieben werden.

```bash
jwt_token=$(kubectl get secret vault-auth-token -n external-secrets -o jsonpath='{$.data.token}' | base64 --decode | sed $'s/$/\\\n/g')
kubernetes_ca_cert="$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 --decode)"
kubernetes_host="https://kubernetes.default.svc:443"
vault write auth/kubernetes/config \
  token_reviewer_jwt="${jwt_token}" \
  kubernetes_ca_cert="${kubernetes_ca_cert}" \
  kubernetes_host="${kubernetes_host}"
unset jwt_token
unset kubernetes_ca_cert
unset kubernetes_host
```

Vault ist damit konfiguriert, um auf die TokenReview API zuzugreifen. Als nächstes muss Vault als SecretStore gesetzt werden. Ein SecretStore verbindet Vault mit dem Kubernetes Cluster, indem er sich bei Vault mit einer Rolle und einem ServiceAccount Token anmeldet. Vault überprüft, ob eine entsprechende Rolle in der Kubernetes Authentifizierungsmethode vorliegt, auf die der angegebene ServiceAccount und Namespace. Wichtig ist hierbei zu erwähnen, dass es sich bei diesem ServiceAccount nicht um den zuvor, zum Zugriff auf die TokenReview API erstellte ServiceAccount handelt. 

Zuerst müssen wir eine Policy für die Rolle anlegen, über welche die spätere Berechtigungszuweisung geregelt wird. Wir wollen den Zugriff in Vault auf einen Bereich eingrenzen und hierfür eine dynamische Policiy erstellen, so dass wir z.B. den Zugriff in Vault auf eine Bereich einschränken können, welcher wie der Namespace in Kubernetes, in welchem der SecretStore bereitgestellt wird, benannt ist. Hierfür definieren wir zuerst den `Accessor Key` der Kubernetes Authentifizierungsmethode. Dieser wird benötigt, um dynamisch den Namespace des anfragenden ServiceAccounts zu definieren:

```bash
kubernetes_accessor=$(vault auth list -format=json | jq -r '.["kubernetes/"].accessor')
vault policy write kubernetes-read -<<EOF
path "kv/data/{{identity.entity.aliases.${kubernetes_accessor}.metadata.service_account_namespace}}/*" {
  capabilities = ["read"]
}
path "kv/metadata/{{identity.entity.aliases.${kubernetes_accessor}.metadata.service_account_namespace}}/*" {
  capabilities = ["read"]
}
EOF
unset kubernetes_accessor
```

Konkret bedeutet dies, dass z.B. für einen Namespace mit dem Namen `demo` die obigen Pfade zu `kv/data/demo/*` bzw. `kv/metadata/demo/*` expandiert werden.

Es ist darauf zu achten, die Pfade an die eigentliche Struktur des eigenen Vault anzupassen, d.h. ist die Pfadstruktur im Vault anders aufgebaut, muss dies hier, aber auch bei allen anderen bisherigen und nachfolgenden Abfragen an Vault berücksichtigt werden.

## Erstellung des Namespaces `demo`

Zuerst erstellen wir den Namespace für diese Demo mit dem Namen `demo`. Sollten bei der Installation von Vault Fehler aufgetreten sein, so muss dieses Kapitel übersprungen werden.

```bash
kubectl create namespace demo
kubectl get namespace
```

### Erstellung der Rolle in Vault für den Namespace `demo`

Nun definieren wir eine Rolle in Vault, um den Zugriff genauer zu regeln:
1. Welcher ServiceAccount ist berechtigt (`default`)?
2. Aus welchem Namespace darf die Anfrage kommen (`demo`)?
3. Welche Policy/Rechte hat diese Rolle (`kubernetes-read`)?
4. Wie lange hat der vergebene Token Gültigkeit, bevor ein neuer angefordert werden muss (`24h`)?

```bash
vault write auth/kubernetes/role/demo-role \
    bound_service_account_names=default \
    bound_service_account_namespaces=demo \
    policies=kubernetes-read \
    ttl=24h
```

Diese Rolle authorisiert im Namespace `demo` den ServiceAccount `default` und weist ihm die Policy `kubernetes-read` zu. Sie kann nun von einem SecretStore verwendet werden. Grundsätzlich besteht die Möglichkeit, einen sogenannten ClusterSecretStore zu erstellen, der von ExternalSecrets aus allen Namespaces erreicht werden kann. Damit jeder Namespace nur auf seine eigenen Daten im Vault zugreifen kann, können individuelle SecretStores in jedem Namespace, der Zugriff auf Vault benötigt und auch nur dort, erzeugt werden.

### Erstellung des SecretStores im Namespace `demo`

Nun legen wir den SecretStore an. Er übergibt den Namen des ServiceAccounts, der von Vault an der TokenReview API auf Existenz geprüft wird. Ebenso definieren wir den Pfad, unter welchem die Daten (`spec.provider.vault.path`) und die Authentifizierungsmethode (`spec.provider.vault.auth.kubernetes.mountPath`) verfügbar sind.

```yaml
kubectl apply -n demo -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "http://vault.local.test"
      path: "kv"
      version: "v2"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "demo-role"
          serviceAccountRef:
            name: "default"
EOF
```

Nun kann überprüft werden, ob der SecretStore erfolgreich angelegt wurde und eine Verbindung aufbauen konnte:

```bash
kubectl describe secretstore vault-backend -n demo
```

Nun kann ein ExternalSecret erstellt werden, welches über den Vault Secret Store abgesichert ist.

### Erstellung der ExternalSecrets

Nun können wir Secrets in Kubernetes anlegen, indem wir lediglich auf das Vault verweisen, in welchem der eigentliche Inhalt sicher abgelegt ist. Dadurch werden keine Schlüssel, Zertifikate, etc. in Gitlab abgelegt. Hierzu verwenden wir den soeben angelegten SecretStore. Beispielhaft werden wir ein sogenanntes ImagePullSecret anlegen, welches die `.dockerconfigjson` enthält. Um auf den Inhalt im Vault zugreifen zu können, müssen wir dem ExternalSecret folgende Informationen mitgeben:
1. welcher SecretStore zu verwenden ist (`spec.secretStoreRef.name`)
2. wie das neu zu erstellende Secret in Kubernetes heißen soll (`metadata.name`)
3. Interval, in welchem das Secret von Vault abgefragt werden soll (`spec.refreshInterval`)
4. wie der Key im neuen Secret heißen soll (`spec.target.name`)
5. der Pfad des Secrets in Vault (ohne die Angabe von `kv/`, `spec.data[].remoteRef.key`)
6. der auszulesende Key im Secret in Vault (ohne die Angabe von `kv/`, `spec.data[].remoteRef.property`)

Wir wollen nun das ImagePullSecret (hier mit dem Namen `harbor`) anlegen, welches wie folgt aussehen soll:

```yaml
kind: Secret
type: kubernetes.io/dockerconfigjson
apiVersion: v1
metadata:
  name: harbor
data:
  .dockerconfigjson: ...
```

Es ist zu beachten, dass wir unter `spec.target.template` den gewünschten Typ `kubernetes.io/dockerconfigjson` setzen. Gleichzeitig muss auch festgelegt werden, wie das Datenfeld aussehen soll. In diesem Beispiel ist es der Eintrag `.dockerconfigjson`, welcher mit dem Wert (`property`) `.dockerconfigjson` aus `demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}` befüllt werden soll. Unter `spec.target.template.data` darf der Inhalt selbst nicht base64-kodiert sein, sodass wir zuerst unter `spec.data[].remoteRef.decodingStrategy` den Inhalt von `.dockerconfigjson` base64-dekodieren und mittels `spec.data[].secretKey` als `dockerconfigstring` referenzierbar und damit unter `spec.target.template.data` nutzbar machen:

```yaml
kubectl apply -n demo -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: harbor
spec:
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  refreshInterval: "10m"
  target:
    name: harbor
    template:
      type: kubernetes.io/dockerconfigjson
      data:
        .dockerconfigjson: "{{ .dockerconfigstring }}"
        config.json: "{{ .dockerconfigstring }}"
  data:
  - secretKey: dockerconfigstring
    remoteRef:
      key: demo/harbor/${PRIVATE_HARBOR_PROJECT_NAME}
      property: .dockerconfigjson
      decodingStrategy: Base64
EOF
```

Der Wert des ImagePullSecrets lässt sich über 

```bash
kubectl get secret harbor -n demo -o jsonpath='{.data.\.dockerconfigjson}' | base64 --decode | jq -r .
kubectl get secret harbor -n demo -o jsonpath='{.data.config\.json}' | base64 --decode | jq -r .
```

auslesen. Es sei angemerkt, dass wir hier noch einen zweiten Eintrag, `config.json`, mit dem exakt gleichen Eintrag setzen. Dies ist wichtig, damit wir dieses Secret auch für Tekton nutzen können. Hierzu legen wir den notwendigen ServiceAccount im `demo` Namespace an:

```yaml
kubectl apply -n demo -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pipeline
secrets:
- name: harbor
imagePullSecrets:
- name: harbor
EOF
```

## Keycloak installieren

Zuerst installieren wir PostgeSQL für Keycloak via:

```bash
pg_keycloak_database="keycloak"
pg_keycloak_username="keycloak-system"
pg_keycloak_password="$(openssl rand -base64 12)"
kc_admin_username="keycloak"
kc_admin_password="$(openssl rand -base64 12)"
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update
helm search repo postgresql | grep -i "bitnami/postgresql"
# helm show values bitnami/postgresql
export POSTGRES_VERSION="15.3.0"
pg_helm_version=$(helm search repo postgresql | grep -i "bitnami/postgresql " | grep -i "${POSTGRES_VERSION}" | cut -d$'\t' -f2 | xargs | cut -d' ' -f1)
helm upgrade --install keycloak-db bitnami/postgresql \
  --namespace keycloak \
  --create-namespace \
  --version "${pg_helm_version}" \
  --set global.postgresql.auth.database="${pg_keycloak_database}" \
  --set global.postgresql.auth.username="${pg_keycloak_username}" \
  --set global.postgresql.auth.password="${pg_keycloak_password}"
pg_admin_password=$(kubectl get secret -n keycloak keycloak-db-postgresql -ojsonpath='{.data.postgres-password}' | base64 --decode)
printf "Postgres Admin Username: postgres (cannot be changed)\n"; \
printf "Postgres Admin Password: ${pg_admin_password}\n"
printf "Postgres Keycloak Database: ${pg_keycloak_database}\n"
printf "Postgres Keycloak Username: ${pg_keycloak_username}\n"
printf "Postgres Keycloak Password: ${pg_keycloak_password}\n"
```

Danach installieren wir Keycloak selbst:

```bash
helm repo add codecentric https://codecentric.github.io/helm-charts
helm repo update
helm search repo keycloak | grep -i "codecentric/keycloakx"
# helm show values codecentric/keycloakx
export KEYCLOAK_VERSION="20.0.3"
kc_helm_version=$(helm search repo keycloak | grep -i "codecentric/keycloakx" | grep -i "${KEYCLOAK_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install keycloak codecentric/keycloakx \
  --namespace keycloak \
  --create-namespace \
  --timeout 600s \
  --version "${kc_helm_version}" \
  --values https://raw.githubusercontent.com/codecentric/helm-charts/keycloakx-${kc_helm_version}/charts/keycloakx/examples/postgresql/keycloak-server-values.yaml \
  --set database.database="${pg_keycloak_database}" \
  --set database.username="${pg_keycloak_username}" \
  --set database.existingSecret="keycloak-db-postgresql" \
  --set database.existingSecretKey="password" \
  --set secrets.admin-creds.stringData.user="${kc_admin_username}" \
  --set secrets.admin-creds.stringData.password="${kc_admin_password}" \
  --set ingress.enabled=true \
  --set ingress.ingressClassName=traefik \
  --set ingress.rules[0].host=keycloak.local.test \
  --set ingress.rules[0].paths[0].path="/auth" \
  --set ingress.rules[0].paths[0].pathType=Prefix \
  --set ingress.annotations."nginx\.ingress\.kubernetes\.io\/proxy-buffer-size"="128k"
sudo sed -i '/^127.0.0.1/ s/$/ keycloak.local.test/' /etc/hosts
printf "Username: "; kubectl -n keycloak get secret keycloak-keycloakx-admin-creds -ojsonpath='{.data.user}' | base64 --decode ; echo; \
printf "Password: "; kubectl -n keycloak get secret keycloak-keycloakx-admin-creds -ojsonpath='{.data.password}' | base64 --decode ; echo
```

Nachdem alle Pods gestartet sind (`watch kubectl get pods -n keycloak`), können wir die Verbidung testen:

```bash
curl -k -L https://keycloak.local.test/auth
```

Nun speichern wir alle Informationen im Vault ab und bereinigen die Umgebungsvariablen:

```bash
vault kv put "kv/keycloak" pg_admin_username="postgres"
vault kv patch "kv/keycloak" pg_admin_password="${pg_admin_password}"
vault kv patch "kv/keycloak" pg_keycloak_database="${pg_keycloak_database}"
vault kv patch "kv/keycloak" pg_keycloak_username="${pg_keycloak_username}"
vault kv patch "kv/keycloak" pg_keycloak_password="${pg_keycloak_password}"
vault kv patch "kv/keycloak" kc_admin_username="${kc_admin_username}"
vault kv patch "kv/keycloak" kc_admin_password="${kc_admin_password}"
vault kv get "kv/keycloak"
unset pg_keycloak_database
unset pg_keycloak_username
unset pg_keycloak_password
unset kc_admin_username
unset kc_admin_password
```

## Linkerd

Bei der Installation von Linkerd folgen wir der offiziellen Doku mit der Ausnahme, dass wir das CNI Plugin von Linkerd verwenden möchten. Dies ist notwendig, da wir innerhalb des Clusters mit so wenigen Rechten wie möglich arbeiten wollen. Um die [Architektur von Linkerd](https://linkerd.io/2.12/reference/architecture/) aufzubauen, verwendet Linkerd `initContainer`, welche die Capability `CAP_NET_ADMIN`, um die nötigen Anpassungen Regeln für `iptables` zu setzen. Durch die Verwendung des CNI Plugins sind die `initContainer` und damit `CAP_NET_ADMIN` obsolet. Eine Einschränkung, die bei der Verwendung des Linkerd CNI Plugins berücksichtigt werden muss, ist die Tatsache, dass der `linkerd-proxy` erst nach den `initContainern` gestartet wird, wodurch kein `initContainer` Netzwerkzugriff hat. Möchte man auch für die `initContainer` Netzwerkzugriff haben, [so kann dies realisiert werden](https://linkerd.io/2.12/features/cni/#allowing-initcontainer-networking), jedoch sind die `initContainer` kein Teil des Service Meshes und mTLS ist ebenfalls nicht möglich.

### Linkerd CLI installieren

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://run.linkerd.io/install | sh
export PATH=$PATH:$HOME/.linkerd2/bin
linkerd version
```

Die Rückmeldung `Server version: unavailable` ist normal.

Bei k3s ist es erforderlich, dass die [Speicherorte der CNI-Komponenten](https://linkerd.io/2.12/features/cni/#additional-configuration) angepasst werden müssen (`destCNINetDir` und `destCNIBinDir`). Dass diese Anpassung notwendig ist, erkennt man spätestens an der Fehlermeldung `{ "message": "Failed to connect", "error": "received corrupt message" }` der `linkerd-proxy` Pods.

### Linkerd via `helm` installieren

```bash
helm repo add linkerd https://helm.linkerd.io/stable
helm repo update
helm search repo linkerd2-cni | grep -i "linkerd/linkerd2-cni"
helm search repo linkerd | grep -i "linkerd/linkerd-crds"
helm search repo linkerd | grep -i "linkerd/linkerd-control-plane"
# helm show values linkerd/linkerd2-cni
# helm show values linkerd/linkerd-crds
# helm show values linkerd/linkerd-control-plane
```

Zuerst müssen wir das CNI Plugin installieren:

```bash
export LINKERD_CNI_VERSION="2.13.5"
linkerd_cni_helm_version=$(helm search repo linkerd2-cni | grep -i "linkerd/linkerd2-cni" | grep -i "${LINKERD_CNI_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install linkerd-cni linkerd/linkerd2-cni \
  --namespace linkerd-cni \
  --create-namespace \
  --version "${linkerd_cni_helm_version}" \
  --set destCNINetDir="/var/lib/rancher/k3s/agent/etc/cni/net.d" \
  --set destCNIBinDir="/var/lib/rancher/k3s/data/current/bin" \
  --set logLevel=debug
unset linkerd_cni_helm_version
```

Mit Hilfe von `linkerd check --pre --linkerd-cni-enabled` kann nun überprüft werden, ob die Control Plane von Linkerd grundsätzlich installiert werden kann. Nach erfolgreicher Prüfung installieren wir zuerst die Custom Resource Definitions von Linkerd:

```bash
export LINKERD_CRDS_VERSION="1.6.1"
linkerd_crds_helm_version=$(helm search repo linkerd | grep -i "linkerd/linkerd-crds" | grep -i "${LINKERD_CRDS_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install linkerd-crds linkerd/linkerd-crds \
  --namespace linkerd \
  --create-namespace \
  --version "${linkerd_crds_helm_version}" \
  --set cniEnabled=true
unset linkerd_crds_helm_version
```

### Erstellung/Bereitstellung der notwendigen Zertifikate und Schlüssel

Für mTLS benötigt Linkerd ein Zertifikat als Trust Anchor sowie ein Issuer-Zertifikat mit zugehörigem Schlüssel. Wir orientieren uns hier an der [offiziellen Dokumentation](https://linkerd.io/2.12/tasks/generate-certificates), um die notwendigen Zertifikate und Schlüssel zu erzeugen.

1. Installation der Software `step`

```bash
export STEP_VERSION="0.24.4"
wget -O /tmp/step_linux_${STEP_VERSION}_amd64.tar.gz \
  https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/step_linux_${STEP_VERSION}_amd64.tar.gz
pushd /tmp
wget -O step_linux_${STEP_VERSION}_amd64.tmp \
  https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/checksums.txt
cat step_linux_${STEP_VERSION}_amd64.tmp | grep step_linux_${STEP_VERSION}_amd64.tar.gz > step_linux_${STEP_VERSION}_amd64.checksums
[[ "$(sha256sum -c step_linux_${STEP_VERSION}_amd64.checksums)" == *"OK" ]] || exit 1
rm -rf step_linux_${STEP_VERSION}_amd64.tmp \
       step_linux_${STEP_VERSION}_amd64.checksums
popd
tar -zxvf /tmp/step_linux_${STEP_VERSION}_amd64.tar.gz \
  -C /tmp \
  step_${STEP_VERSION}/bin
sudo mv /tmp/step_${STEP_VERSION}/bin/step /usr/local/bin/step
rm -rf /tmp/step_linux_${STEP_VERSION}_amd64.tar.gz \
       /tmp/step_${STEP_VERSION}
sudo chown root:root /usr/local/bin/step
sudo chmod 755 /usr/local/bin/step
```

2. Trust Anchor (Zertifikat und Schlüssel) erzeugen (vom Typ her eine Root-CA)::

```bash
mkdir -p ~/linkerd/linkerd-certificates
pushd ~/linkerd/linkerd-certificates
step certificate create \
  root.linkerd.cluster.local \
  ca.crt \
  ca.key \
  --profile root-ca \
  --no-password \
  --insecure
popd
```

Die so erzeugte `ca.crt` werden wir später via `--set-file identityTrustAnchorsPEM=ca.crt` (oder im Falle der CLI-basierten Installation via `--identity-trust-anchors-file`) an Linkerd übergeben. Durch die Optionen `--no-password` und `--insecure` findet keine Verschlüsselung statt.

3. Issuer-Zertifikat und Schlüssel (das Issuer-Zertifiakt ist vom Typ her eine Intermediate-CA):

```bash
pushd ~/linkerd/linkerd-certificates
step certificate create \
  identity.linkerd.cluster.local \
  issuer.crt \
  issuer.key \
  --profile intermediate-ca \
  --no-password \
  --insecure \
  --not-after 8760h \
  --ca ca.crt \
  --ca-key ca.key
popd
```

Die so erzeugte Dateien `issuer.crt` und `issuer.key` werden später via `--set-file identity.issuer.tls.crtPEM` und `--set-file identity.issuer.tls.keyPEM` übergeben.

4. Bezüglich der Rotation von Zertifikaten sei auf die [offizielle Dokumentation](https://linkerd.io/2.12/tasks/automatically-rotating-control-plane-tls-credentials/) verwiesen.

### Non-HA Installation

```bash
pushd ~/linkerd
export LINKERD_CONROL_PLANE_VERSION="2.13.5"
linkerd_control_plane_helm_version=$(helm search repo linkerd | grep -i "linkerd/linkerd-control-plane" | grep -i "${LINKERD_CONROL_PLANE_VERSION}" | cut -d$'\t' -f2 | xargs)
helm upgrade --install linkerd-control-plane linkerd/linkerd-control-plane \
  --namespace linkerd \
  --create-namespace \
  --version "${linkerd_control_plane_helm_version}" \
  --set-file identityTrustAnchorsPEM=linkerd-certificates/ca.crt \
  --set-file identity.issuer.tls.crtPEM=linkerd-certificates/issuer.crt \
  --set-file identity.issuer.tls.keyPEM=linkerd-certificates/issuer.key \
  --set cniEnabled=true \
  --set proxy.await=false
popd
unset linkerd_control_plane_helm_version
```

Ob die Installation erfolgreich war, kann mit dem Befehl `linkerd check` überprüft werden.

Nun ist der Cluster für `mTLS` vorbereitet. Das Hinzufügen der Deployments, Pods, etc. zum Linkerd Service Mesh, um `mTLS` für die Workload zu aktivieren, ist hier noch optional und wird nicht automatisch erzwungen, um Tests mit und ohne `mTLS` durchführen zu können. Für jegliche weitere Konfiguration sei auf die offizielle Doku verwiesen.
