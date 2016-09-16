
from charms.reactive import when, when_not, set_state
from charms.docker import DockerOpts
from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.fetch import apt_install
from charms.templating.jinja2 import render

import os
import subprocess


def _reconfigure_docker_for_sdn():
    ''' By default docker uses the docker0 bridge for container networking.
    This method removes the default docker bridge, and reconfigures the
    DOCKER_OPTS to use the flannel networking bridge '''

    hookenv.status_set('maintenance', 'Reconfiguring docker network bridge')
    host.service_stop('docker')
    apt_install(['bridge-utils'], fatal=True)
    # cmd = "ifconfig docker0 down"
    # ifconfig doesn't always work. use native linux networking commands to
    # mark the bridge as inactive.
    cmd = ['ip', 'link', 'set', 'docker0', 'down']
    subprocess.check_call(cmd)

    cmd = ['brctl', 'delbr', 'docker0']
    subprocess.check_call(cmd)
    set_state('docker.restart')


@when('docker.available')
@when_not('kubernetes.worker.bins.installed')
def install_kubernetes_components():
    ''' Unpack the kubernetes worker binaries '''
    kube_package = hookenv.resource_get('kubernetes')
    charm_dir = os.getenv('CHARM_DIR')

    if not kube_package:
        hookenv.status_set('blocked', 'Missing kubernetes resource')
        return

    hookenv.status_set('maintenance', 'Unpacking kubernetes')

    unpack_path = '{}/files/kubernetes'.format(charm_dir)
    os.makedirs(unpack_path, exist_ok=True)
    cmd = ['tar', 'xfz', kube_package, '-C', unpack_path]
    subprocess.check_call(cmd)

    services = ['kubelet', 'kube-proxy']

    for service in services:
        unpacked = '{}/files/kubernetes/{}'.format(charm_dir, service)
        app_path = '/usr/local/bin/{}'.format(service)
        install = ['install', '-v', unpacked, app_path]
        subprocess.call(install)

    set_state('kubernetes.worker.bins.installed')


@when('kubernetes.worker.bins.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    cmd = ['kubelet', '--version']
    version = subprocess.check_output(cmd)
    hookenv.application_version_set(version.split(b' ')[-1].rstrip())


@when('sdn-plugin.available', 'docker.available')
@when_not('sdn.configured')
def container_sdn_setup(sdn):
    ''' Receive the information from the SDN plugin, and render the docker
    engine options. '''
    hookenv.status_set('maintenance', 'Configuring docker for sdn')
    sdn_config = sdn.get_sdn_config()

    opts = DockerOpts()
    opts.add('bip', sdn_config['subnet'])
    opts.add('mtu', sdn_config['mtu'])

    with open('/etc/default/docker', 'w') as stream:
        stream.write('DOCKER_OPTS="{}"'.format(opts.to_s()))
    _reconfigure_docker_for_sdn()
    set_state('sdn.configured')


@when('kube-api-endpoint.available', 'kubernetes.worker.bins.installed')
def render_init_scripts(kube_api_endpoint):
    ''' We have related to either an api server or a load balancer connected
    to the apiserver. Render the config files and prepare for launch '''
    context = {}
    context.update(hookenv.config())
    hosts = []
    for serv in kube_api_endpoint.services():
        for unit in serv['hosts']:
            hosts.append('http://{}:{}'.format(unit['hostname'], unit['port']))
            print(hosts)
    unit_name = os.getenv('JUJU_UNIT_NAME').replace('/', '-')
    context.update({'kube_api_endpoint': ','.join(hosts),
                    'JUJU_UNIT_NAME': unit_name})

    os.makedirs('/var/lib/kubelet', exist_ok=True)
    render('kubelet-kubeconfig', '/etc/kubernetes/kubelet/kubeconfig', context)
    render('kube-default', '/etc/default/kube-default', context)
    render('kubelet.defaults', '/etc/default/kubelet', context)
    render('kube-proxy.service', '/lib/systemd/system/kube-proxy.service',
           context)
    render('kubelet.service', '/lib/systemd/system/kubelet.service', context)

    cmd = ['systemctl', 'daemon-reload']
    subprocess.check_call(cmd)

    host.service_restart('kubelet')
    host.service_restart('kube-proxy')
    hookenv.status_set('active', 'Worker ready')
