# kubernetes-master

[Kubernetes](http://kubernetes.io/) is an open source system for managing 
application containers across a cluster of hosts. The Kubernetes project was
started by Google in 2014, combining the experience of running production 
workloads combined with best practices from the community.

The Kubernetes project defines some new terms that may be unfamiliar to users
or operators. For more information please refer to the concept guide in the 
[getting started guide](http://kubernetes.io/docs/user-guide/#concept-guide).

This charm is an encapsulation of the Kubernetes master processes and the 
operations to run on any cloud for the entire lifecycle of the cluster.

This charm was built from other charm layers using the Juju reactive framework.
The other layers focus on specific subset of operations making this layer 
specific to operations of Kubernetes master processes.

This charm is one part of what is needed to model a Kubernetes cluster. If you
wish to deploy a complete cluster please look at the collection of charms that
model a [Kubernetes core](https://jujucharms.com/kubernetes-core/) cluster.

# Deployment

This charm is not self contained, other charms are needed to model a complete 
Kubernetes cluster. The cluster requires a distributed key value store such as 
[Etcd](https://coreos.com/etcd/) and the kubernetes-worker charm which delivers
the Kubernetes node services. A cluster requires a Software Defined Network 
(SDN) and Transport Layer Security (TLS) so the components in a cluster 
communicate securely. 

Please take a look at the [Canonical Distribution of Kubernetes](https://jujucharms.com/canonical-kubernetes/) 
or the [Kubernetes core](https://jujucharms.com/kubernetes-core/) bundles for 
examples of complete models of Kubernetes clusters.

# Resources

The kubernetes-master charm takes advantage of the [Juju Resources](https://jujucharms.com/docs/2.0/developer-resources) 
feature.

The resources are already attached to the Juju Charm Store, but in cases where
the charm can not contact the Charm Store or if you want to use a different 
version of Kubernetes you can attach a different resource to this charm.

Using Juju resources allows you to deploy or upgrade a kubernetes-master charm
in an environment with network restrictions and strict firewall rules. 

To attach a different resource to a deployed kubernetes-master charm, run the
following command:

```
juju attach kubernetes-master kubernetes=/path/to/kubernetes-master.tar.gz
```

# Configuration

This charm supports some configuration options to set up a Kubernetes cluster 
that works in your environment:  

#### dns_domain

The domain name to use for the Kubernetes cluster for kube-dns.

#### enable-dashboard-addons

Enables the installation of Kubernetes dashboard, Heapster, Grafana, and
InfluxDB.

# DNS for the cluster

The DNS add-on allows the pods to have a DNS names in addition to IP addresses.
The Kubernetes cluster DNS server (based off the SkyDNS library) supports 
forward lookups (A records), service lookups (SRV records) and reverse IP 
address lookups (PTR records). More information about the DNS can be obtained
from the [Kubernetes DNS admin guide](http://kubernetes.io/docs/admin/dns/).

# Adding optional storage

The kubernetes-master charm handles different persistent storage devices that
the cloud environments provide. See the 
[Juju storage](https://jujucharms.com/docs/stable/charms-storage) documentation
for more details about the supported clouds and storage pool types that are 
available.

Refer to the [Canonical Distribution of Kubernetes](https://jujucharms.com/canonical-kubernetes/) for more information
about how add the Ceph charms that handle storage.

# Additional Kubernetes information

 - [Kubernetes github project](https://github.com/kubernetes/kubernetes)
 - [Kubernetes issue tracker](https://github.com/kubernetes/kubernetes/issues)
 - [Kubernetes documentation](http://kubernetes.io/docs/)
 - [Kubernetes releases](https://github.com/kubernetes/kubernetes/releases)

# Contact

The kubernetes-master charm is free and open source operations software created
by the containers team at Canonical. 

Canonical also offers enterprise support and customisation services. Please
refer to the [Kubernetes product page](https://www.ubuntu.com/cloud/kubernetes)
for more details.
