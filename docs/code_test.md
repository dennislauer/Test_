- Anydesk -
ID: 433940383
Password: XXX

- System -
User: cruloff
Password: XXX

- Openstack -
User: cruloff
Password: XXX

--------------------------------------------------------------------------------------------------

Harbor: 
--set
notary
cosign
Anbindung an Vault

ArgoCD
TLS Ingress

Keycloak
pg_admin_password vorab setzen!
-o statt -i ???
OIDC

kubectl
OIDC

helm template . \
    | yq '..|.image? | select(.)' \
    | sort -u

Alle TODO (auch später in der Datei!)

--------------------------------------------------------------------------------------------------

>TODO: trivy operator --> warum sind die CVE reports leer, der Rest aber nicht?

>TODO: Opensearch
>TODO: Prometheus Operator
>TODO: kube-state-metrics über Prometheus
>TODO: wazuh oder fluentd
>TODO: skywalking
>TODO: Vault als PKI
>TODO: cert-manager an Vault anbinden
>TODO: Linkerd an Vault/cert-manager anbinden
>TODO: Encrpyt etcd: 
>  https://docs.rke2.io/security/secrets_encryption
>  https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/
>  https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#understanding-the-encryption-at-rest-configuration
>  https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#rotating-a-decryption-key
>  https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#configure-automatic-reloading
>  `secrets-encrypt status`
>TODO: otel-collector?
>TODO: Kyverno Policies?
>TODO: externalDNS?
>TODO: Capsule?
>TODO: vcluster?
>TODO: Telepresence?
>TODO: Rancher Server?
>TODO: Falco?
>TODO: NeuVector?
>TODO: nginx durch traefik ersetzen?
>TODO: [Firewall-Regeln](https://docs.rke2.io/install/requirements#networking)?
>TODO: SELinux vs Apparmor?
>TODO: trivy SBOM?
>TODO: trivy kube-bench?
>TODO: linux-bench?
>TODO: containerd-bench?
>TODO: opencost?

>--disable rke2-coredns --> wozu?
>--disable rke2-ingress-nginx --> traefik wie bei k3s?
>--private-registry --> tarball-Methode für images!?
>--selinux --> true? To force the install script to log a warning rather than fail, you can set the following environment variable: INSTALL_K3S_SELINUX_WARN=true?
>--token --> random string?

>https://github.com/clemenko/rke_airgap_install/blob/main/air_gap_all_the_things.sh
>https://github.com/longhorn/longhorn/issues/812
>https://github.com/containers/skopeo

>https://docs.rke2.io/install/network_options

>---










>--- 
>### [Cyberlab] Oracle Linux 
>
>Da beim Oracle Linux 7 Image im Cyberlab die Festplatte nicht automatisch erweitert wird, muss man manuell die LVM Volumes anpassen:
>
>1. Mit `lsblk` schauen, wo das Logical Volume liegt, das man erweitern möchte. Das Logical Volume (LV) mit vollständigem Namen `vg_main-lv_root`, welches zur Volume Group (VG) `vg_main` gehört, liegt bei unserer Installation auf dem Physical Volume (PV) `/dev/vda2`:
>```bash
>lsblk
>```
>2. Entsprechende Partition vergrößern: 
>```bash
>sudo growpart /dev/vda 2
>```
>3. LVM über die nun geänderte Größe des zugrundeliegenden PV informieren: 
>```bash
>sudo pvresize /dev/vda2
>```
>4. Das Logical Volume vergrößern, z.B. maximal: 
>```bash
>sudo lvextend -l +100%FREE /dev/vg_main/lv_root
>```
>5. Das Dateisystem nachziehen:
>```bash
>sudo xfs_growfs /dev/vg_main/lv_root
>```
>
>---

>--- 
>### Zertifikate und CAs hinzufügen
>
>Da beim Oracle Linux 7 Image im Cyberlab die Festplatte nicht automatisch erweitert wird, muss man manuell die LVM Volumes anpassen:
>
>- Unter Oracle Linux 7 oder CentOS 7, zuerst das Zertifikat nach `/etc/pki/ca-trust/source/anchors` oder `/usr/share/pki/ca-trust-source/anchors` kopieren (mit sudo) und danach das Zertifikat dem Trust Store mit `sudo update-ca-trust extract` oder `sudo update-ca-trust enable` hinzufügen.
>- Unter Debian oder Ubuntu, zuerst das Zertifikat nach `/usr/local/share/ca-certificates` kopieren (mit sudo) und danach das Zertifikat dem Trust Store mit `sudo update-ca-certificates` hinzufügen.
>
>---

# Disclaimer

>---
>Diese Dokumentation wurde in einer virtuellen Instanz von [Ubuntu 22.04.2 LTS (64bit)](https://releases.ubuntu.com/jammy/) getestet, welche wir gleich zu Beginn auf den aktuellen Stand bringen werden. Es bietet sich an, eine Installation mit grafischer Oberfläche zu wählen, um mit den Komponenten mittel UI interagieren zu können. Der Einsatz der Server-Variante und das saubere Routing der einzelnen Komponenten "nach außen", d.h. sodass sie von dem Host der virtuellen Maschine aus erreichbar sind, wird empfohlen. Es handelt sich nicht um eine Anleitung für eine gekapselte Air-Gapped Installation. Da es sich um eine einzelne virtuelle Instanz handelt, konnte und wurde keine Hochverfügbarkeit getestet. Es wurde primär mit selbstsignierten oder automatisch erstellten Zertifikaten gearbeitet und oftmals die Verifikation der Zertifikate deaktiviert. Daher ausdrücklich der Hinweis, dass es sich hierbei um eine Dokumentation einer Testumgebung handelt. In diesem Dokument wird keine Produktivumgebung beschrieben!
> 
>```bash
>uname -a
>Linux ubuntu-test 5.15.0-69-generic #76-Ubuntu SMP Fri Mar 17 17:19:29 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
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

## Bei Oracle Linux 7 oder CentOS 7

```bash
jq
git
yum-utils
iscsi-initiator-utils
cryptsetup
vault
java-11-openjdk
unzip
```

Und wenn SELinux aktiviert ist, so sind zusätzlich noch folgende Pakete erforderlich:

### Für [rke2](https://github.com/rancher/rke2-selinux/releases)

```bash
container-selinux
iptables
libnetfilter_conntrack
libnfnetlink
libnftnl
policycoreutils-python-utils
rke2-common
rke2-selinux
```

### Für [k3s](https://github.com/k3s-io/k3s-selinux/releases)

```bash
container-selinux
selinux-policy-base
k3s-selinux
```

## Bei Debian oder Ubuntu

```bash
jq
git
open-iscsi
cryptsetup
vault
gpg
default-jre
unzip
```

# Installationsanleitung für Tools und Komponenten

>---
>Der Zeitaufwand hängt von der Performanz des Hosts der virtuellen Maschine sowie der Internetanbindung ab. Bitte rechnen Sie mit ca. 1,5 Stunden.
> 
>---

## Übersicht

In dieser Dokumentation wird die Installation und Konfiguration der folgenden Tools und Komponenten besprochen:
1. `rke2` oder `k3s` als leichtgewichtige Alternative zu `rke2`. Beides sind zertifizierte Kubernetes Distributionen von Rancher und daher auf Plattformsicht hinreichend vergleichbar.
2. Longhorn als persistenten Speicherlayer. `k3s` bringt einen persistenten Speicherlayer mit, `rke2` aber nicht, daher soll hier dies auch gezeigt werden.
3. Vault als Schlüsselspeicher, um sensible Variablen sicher ablegen zu können.
4. Harbor als Container Registry, um die Container Images zur Verwendung im Cluster ablegen zu können.
5. Tekton als CI/CD Komponente.
6. Gitlab als Quellcode-Verwaltungssystem.
7. ExternalSecrets Operator zur Bereitstellung der in Vault gespeicherten Secrets innerhalb der Plattform
8. Keycloak als Identity Provider
9. Linkerd als Service Mesh zur Ermöglichung von mTLS innerhalb des Clusters.

## Umgebungsvariablen:

>---
>Es ist zu beachten, dass durch das Schließen eines Terminals alle Umgebungsvariablen gelöscht bzw. zurückgesetzt werden. Hierauf ist zu achten und bei Bedarf die entsprechenden Variablen (mit `export` gekennzeichnet) nachziehen, ggf. auch manuell. Die folgende Variable ist nur eine von vielen!
> 
>---

Wir erstellen Variablen bzgl. der Architektur mittels:

```bash
export ARCH_X=$(uname -m)
[[ ${ARCH_X} == "x86_64" ]] && export ARCH="amd64" || export ARCH=${ARCH_X}
[[ ${ARCH_X} == "x86_64" ]] && export ARCH_BIT="64bit" || export ARCH_BIT=${ARCH_X}
printf '\nPATH="/usr/local/bin:$PATH"\n' | sudo tee -a /root/.bashrc
printf '\nPATH="/usr/local/bin:$PATH"\n' | sudo tee -a "${HOME}/.bashrc"
```

Wir erstellen zuerst den Ordner, in welchen alle Artefakte, die wir benötigen, mit Hilfe eines Computers mit Internet-Zugriff heruntergeladen werden.

```bash
export ARTIFACT_DIR="${HOME}/artifacts"
mkdir -p "${ARTIFACT_DIR}"
```

Nun erstellen wir einen Ordner in der virtuellen Maschine, in welchen die zuvor heruntergeladenen Artefakte transferiert werden und in welchem die während der Installation der Komponenten erzeugten Dateien (Manifeste, Zertifikate, etc.) gespeichert werden. 

```bash
export INSTALL_DIR="${HOME}/install"
mkdir -p "${INSTALL_DIR}"
```

Der Transfer der Daten von `ARTIFACT_DIR` nach `INSTALL_DIR` kann auf verschiedene Arten erfolgen und soll hier nicht weiter ausgeführt werden. Dieser Schritt stellt gleichzeitig die Simulation einer Air-Gapped-Umgebung dar, da die virtuelle Maschine keinen Internetzugriff erhalten soll.

>---
>Sofern dies ausdrücklich gewünscht ist, kann die Simulation der Air-Gapped-Umgebung übersprungen werden.
> 
>---

## Installation grundlegender Software 

### Bei Oracle Linux 7 oder CentOS 7
```bash
sudo yum-config-manager \
  --enable ol7_addons
sudo yum repolist -y
sudo yum update -y
sudo yum upgrade -y
sudo yum install -y \
  jq \
  git \
  yum-utils
```

### Bei Debian oder Ubuntu
```bash
sudo apt update -y
sudo apt upgrade -y
sudo apt install -y \
  jq \
  git
```

## Installation der Software `step`

```bash
export STEP_VERSION="0.24.4"
```

### Download

Nun laden wir zuerst alles notwendige herunter:

```bash
pushd "${ARTIFACT_DIR}"
curl -Lo step_linux_${STEP_VERSION}_${ARCH}.tar.gz \
  https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/step_linux_${STEP_VERSION}_${ARCH}.tar.gz
curl -Lo step_linux_${STEP_VERSION}_${ARCH}.tmp \
  https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}/checksums.txt
cat step_linux_${STEP_VERSION}_${ARCH}.tmp | grep step_linux_${STEP_VERSION}_${ARCH}.tar.gz > step_linux_${STEP_VERSION}_${ARCH}.checksums
[[ "$(sha256sum -c step_linux_${STEP_VERSION}_${ARCH}.checksums)" == *"OK" ]] || exit 1
rm -rf step_linux_${STEP_VERSION}_${ARCH}.tmp \
       step_linux_${STEP_VERSION}_${ARCH}.checksums
popd
```

### Installation und Konfiguration

Zuerst stellen wir sicher, dass die Datei im Ordner `${INSTALL_DIR}` vorliegt (z.B. mittels `ls -lha` und manuellem Vergleich). Nun starten wir die Installation mittels:

```bash
pushd "${INSTALL_DIR}"
tar -zxvf "step_linux_${STEP_VERSION}_${ARCH}.tar.gz" \
  -C "${INSTALL_DIR}" \
  "step_${STEP_VERSION}/bin"
sudo mv "step_${STEP_VERSION}/bin/step /usr/local/bin/step"
# rm -rf "step_${STEP_VERSION}"
sudo chown root:root /usr/local/bin/step
sudo chmod 755 /usr/local/bin/step
popd
```

## Kubernetes installieren

### Vorbereitungen

Dynamische Bestimmung der IP unserer Instanz und Überprüfung mittels `echo "${NODE_IP}"`, ob die IP richtig ausgelesen wurde (Korrektur bei Bedarf). Desweiteren benötigen wir für später den jeweiligen Pfad zum Zertifikatsspeicher der jeweiligen Distribution:

#### Bei Oracle Linux 7 oder CentOS 7
```bash
export NODE_IP=$(ip -4 -o a | grep -i "eth0" | tr -s ' ' | cut -d ' ' -f4 | cut -d '/' -f1)
export CERTIFICATE_PATH="/etc/pki/ca-trust/source/anchors"
```

#### Bei Debian oder Ubuntu
```bash
export NODE_IP=$(ip -4 -o a | grep -i "ens3" | tr -s ' ' | cut -d ' ' -f4 | cut -d '/' -f1)
export CERTIFICATE_PATH="/usr/local/share/ca-certificates"
```

### Alternative 1: rke2 installieren

Zuerst legen wir die zu installierende Version fest mittels:

```bash
export KUBERNETES_DISTRIBUTION="rke2"
export KUBERNETES_VERSION="v1.27.2+rke2r1"
```

#### rke2 herunterladen

Nun laden wir zuerst alles notwendige herunter:

```bash
pushd "${ARTIFACT_DIR}"
kubernetes_version=$(echo "${KUBERNETES_VERSION//+/$'%2B'}")
curl -OLs https://github.com/rancher/rke2/releases/download/${kubernetes_version}/rke2-images-core.linux-${ARCH}.tar.zst
curl -OLs https://github.com/rancher/rke2/releases/download/${kubernetes_version}/rke2-images-canal.linux-${ARCH}.tar.zst
curl -OLs https://github.com/rancher/rke2/releases/download/${kubernetes_version}/rke2.linux-${ARCH}.tar.gz
curl -OLs https://github.com/rancher/rke2/releases/download/${kubernetes_version}/sha256sum-${ARCH}.txt
curl -sfL https://get.rke2.io --output install.sh
unset kubernetes_version
chmod 755 install.sh
popd
```

#### rke2 [Installation](https://docs.rke2.io/install/methods) und [Konfiguration](https://docs.rke2.io/reference/server_config)

Zuerst stellen wir sicher, dass die Datei im Ordner `${INSTALL_DIR}` vorliegt (z.B. mittels `ls -lha` und manuellem Vergleich). Nun starten wir die Installation von `rke2` mittels:

```bash
pushd "${INSTALL_DIR}"
export KUBECONFIG="/etc/rancher/${KUBERNETES_DISTRIBUTION}/${KUBERNETES_DISTRIBUTION}.yaml"
export NODE_NAME=$(hostname)
sudo mkdir -p "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/agent/images"
# sudo cp "rke2-images-core.linux-${ARCH}.tar.zst" "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/agent/images/"
# sudo cp "rke2-images-canal.linux-${ARCH}.tar.zst" "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/agent/images/"
INSTALL_RKE2_ARTIFACT_PATH="${INSTALL_DIR}" \
INSTALL_RKE2_VERSION="${KUBERNETES_VERSION}" \
INSTALL_RKE2_TYPE="server" \
INSTALL_RKE2_METHOD="tar" \
  ./install.sh \
  --disable=rke2-metrics-server \
  --node-name="${NODE_NAME}" \
  --tls-san="${NODE_IP}" \
  --disable-cloud-controller \
  --write-kubeconfig-mode=0644 \
  --cni=canal \
  --profile=cis-1.23
systemctl enable rke2-server
systemctl start rke2-server
popd
```

Nun kann der Verlauf der Installation mit `journalctl -u rke2-server -f` überwacht werden. Nach ca. einer Minute kann mittels

```bash
sudo systemctl status rke2-server -l
```

### Alternative 2: k3s installieren

Diese Umgebung wird aus Performanz-Gründen auf Basis von `k3s` (Kubernetes 1.26.2) ausgerollt:

```bash
export KUBERNETES_DISTRIBUTION="k3s"
export KUBERNETES_VERSION="v1.27.2+k3s1"
```

#### k3s herunterladen

Nun laden wir zuerst alles notwendige herunter

```bash
pushd "${ARTIFACT_DIR}"
# v1.27.2%2Bk3s1
kubernetes_version=$(echo "${KUBERNETES_VERSION//+/$'%2B'}")
curl -OLs https://github.com/k3s-io/k3s/releases/download/${kubernetes_version}/k3s-airgap-images-${ARCH}.tar
curl -OLs https://github.com/k3s-io/k3s/releases/download/${kubernetes_version}/k3s
curl -OLs https://github.com/k3s-io/k3s/releases/download/${kubernetes_version}/sha256sum-${ARCH}.txt
curl -sfL https://get.k3s.io --output install.sh
unset kubernetes_version
chmod 755 install.sh
popd
```

#### k3s [Installation](https://docs.k3s.io/installation/requirements) und [Konfiguration](https://docs.k3s.io/installation/configuration)

Zuerst stellen wir sicher, dass die Datei im Ordner `${INSTALL_DIR}` vorliegt (z.B. mittels `ls -lha` und manuellem Vergleich). Nun starten wir die Installation von `rke2` mittels:






>---
>If your nodes do not have an interface with a default route, a default route must be configured; even a black-hole route via a dummy interface will suffice. K3s requires a default route in order to auto-detect the node's primary IP, and for kube-proxy ClusterIP routing to function properly. To add a dummy route, do the following:
>ip link add dummy0 type dummy
>ip link set dummy0 up
>ip addr add 169.254.255.254/31 dev dummy0
>ip route add default via 169.254.255.255 dev dummy0 metric 1000
> 
>---






```bash
pushd "${INSTALL_DIR}"
export KUBECONFIG="/etc/rancher/${KUBERNETES_DISTRIBUTION}/${KUBERNETES_DISTRIBUTION}.yaml"
export NODE_NAME=$(hostname)
sudo mkdir -p "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/agent/images"
sudo cp "k3s-airgap-images-${ARCH}.tar" "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/agent/images/"
sudo cp "k3s" "/usr/local/bin"
sudo chmod 755 "/usr/local/bin/k3s"
INSTALL_K3S_VERSION="${KUBERNETES_VERSION}" \
INSTALL_K3S_SKIP_DOWNLOAD=true \
  ./install.sh \
  --disable metrics-server \
  --node-name="${NODE_NAME}" \
  --tls-san="${NODE_IP}" \
  --disable-cloud-controller \
  --write-kubeconfig-mode=0644
systemctl enable k3s
systemctl start k3s
popd
```

Nach ca. einer Minute kann mittels

```bash
sudo systemctl status k3s -l
```

### Überprüfung der Installation von `rke2` oder `k3s`

Zuerst passen wir die `KUBECONFIG` an und stellen sie zur Verwendung bereitstellen:

```bash
sudo sed -i "s/127.0.0.1/${NODE_IP}/g" "${KUBECONFIG}"
printf "\nKUBECONFIG=\"${KUBECONFIG}\"\n" | sudo tee -a /etc/environment
```

Danach können wir den Status der Installation überprüfen:

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

### Modifikationen von Traefik

Damit die IngressClass `traefik` als Standard gesetzt wird, müssen wir das Helm Chart konfigurieren mittels: 

```bash
sudo mkdir -p "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/server/manifests"
sudo tee "/var/lib/rancher/${KUBERNETES_DISTRIBUTION}/server/manifests/traefik-config.yaml" <<EOF
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
```

Nun zur Sicherheit `rke2-server` mittels `sudo systemctl restart rke2-server` oder `k3s` mittels `sudo systemctl restart k3s` neustarten. Danach kann man den Status mittels `sudo systemctl status rke2-server -l` oder `sudo systemctl status k3s -l` überprüfen.

## etcdctl installieren

```bash
export ETCDCTL_VERSION="3.5.9"
```
