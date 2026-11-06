### kube-apiserver

In highly-available (HA) clusters, the newest and oldest `kube-apiserver`
instances must be within one minor version.

### kubelet

* `kubelet` must not be newer than `kube-apiserver`.
* `kubelet` may be up to three minor versions older than `kube-apiserver`
  (`kubelet` < 1.25 may only be up to two minor versions older than `kube-apiserver`).

### kube-proxy

* `kube-proxy` must not be newer than `kube-apiserver`.
* `kube-proxy` may be up to three minor versions older than `kube-apiserver`
  (`kube-proxy` < 1.25 may only be up to two minor versions older than `kube-apiserver`).
* `kube-proxy` may be up to three minor versions older or newer than the `kubelet`
  instance it runs alongside (`kube-proxy` < 1.25 may only be up to two minor
  versions older or newer than the `kubelet` instance it runs alongside).

### kube-controller-manager, kube-scheduler, and cloud-controller-manager

`kube-controller-manager`, `kube-scheduler`, and `cloud-controller-manager` must
not be newer than the `kube-apiserver` instances they communicate with. They may
be up to one minor version older.

### kubectl
