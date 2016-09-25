import os

from shlex import split
from subprocess import call
from subprocess import check_call
from subprocess import check_output

from charms import layer
from charms.docker import DockerOpts
from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not

from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.fetch import apt_install

from charms.kubernetes.flagmanager import FlagManager

from charms.templating.jinja2 import render


def _reconfigure_docker_for_sdn():
    ''' By default docker uses the docker0 bridge for container networking.
    This method removes the default docker bridge, and reconfigures the
    DOCKER_OPTS to use the flannel networking bridge '''

    hookenv.status_set('maintenance',
                       'Reconfiguring container runtime network bridge.')
    host.service_stop('docker')
    apt_install(['bridge-utils'], fatal=True)
    # cmd = "ifconfig docker0 down"
    # ifconfig doesn't always work. use native linux networking commands to
    # mark the bridge as inactive.
    cmd = ['ip', 'link', 'set', 'docker0', 'down']
    check_call(cmd)

    cmd = ['brctl', 'delbr', 'docker0']
    check_call(cmd)
    set_state('docker.restart')


@hook('upgrade-charm')
def remove_installed_state():
    remove_state('kubernetes.worker.bins.installed')


@when('docker.available')
@when_not('kubernetes.worker.bins.installed')
def install_kubernetes_components():
    ''' Unpack the kubernetes worker binaries '''
    charm_dir = os.getenv('CHARM_DIR')

    # Get the resource via resource_get
    try:
        archive = hookenv.resource_get('kubernetes')
    except Exception:
        message = 'Error fetching the kubernetes resource.'
        hookenv.log(message)
        hookenv.status_set('blocked', message)
        return

    if not archive:
        hookenv.log('Missing kubernetes resource.')
        hookenv.status_set('blocked', 'Missing kubernetes resource.')
        return

    # Handle null resource publication, we check if filesize < 1mb
    filesize = os.stat(archive).st_size
    if filesize < 1000000:
        hookenv.status_set('blocked', 'Incomplete kubernetes resource.')
        return

    hookenv.status_set('maintenance', 'Unpacking kubernetes resource.')

    unpack_path = '{}/files/kubernetes'.format(charm_dir)
    os.makedirs(unpack_path, exist_ok=True)
    cmd = ['tar', 'xfvz', archive, '-C', unpack_path]
    hookenv.log(cmd)
    check_call(cmd)

    services = ['kubelet', 'kube-proxy', 'kubectl']

    for service in services:
        unpacked = '{}/{}'.format(unpack_path, service)
        app_path = '/usr/local/bin/{}'.format(service)
        install = ['install', '-v', unpacked, app_path]
        call(install)

    set_state('kubernetes.worker.bins.installed')


@when('kubernetes.worker.bins.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    cmd = ['kubelet', '--version']
    version = check_output(cmd)
    hookenv.application_version_set(version.split(b' v')[-1].rstrip())


@when('kubernetes.worker.bins.installed')
@when_not('kube-dns.available')
def notify_user_transient_status():
    ''' Notify to the user we are in a transient state and the application
    is still converging. Potentially remotely, or we may be in a detached loop
    wait state '''

    # During deployment the worker has to start kubelet without cluster dns
    # configured. If this is the first unit online in a service pool waiting
    # to self host the dns pod, and configure itself to query the dns service
    # declared in the kube-system namespace

    hookenv.status_set('waiting',
                       'Waiting for cluster-manager to initiate start.')


@when('kubernetes.worker.bins.installed', 'kube-dns.available')
def notify_user_converging_status(kube_dns):
    ''' There are different states that the worker can be in, where we are
    waiting for dns, waiting for cluster turnup, or ready to serve
    applications'''
    # Daemon options are managed by the FlagManager class
    kubelet_opts = FlagManager('kubelet')

    # Query the FlagManager dict for the dns option, and determine if
    # kubelet is running
    if (_systemctl_is_active('kubelet') and
       '--cluster-dns' not in kubelet_opts.data):
        hookenv.status_set('waiting', 'Waiting for cluster DNS.')
    elif(_systemctl_is_active('kubelet') and
         '--cluster-dns' in kubelet_opts.data):
        hookenv.status_set('active', 'Kubernetes worker running.')
    # if kubelet is not running, we're waiting on something else to converge
    elif(not _systemctl_is_active('kubelet')):
        hookenv.status_set('waiting', 'Waiting for kubelet to start.')


@when('sdn-plugin.available', 'docker.available')
@when_not('sdn.configured')
def container_sdn_setup(sdn):
    ''' Receive the information from the SDN plugin, and render the docker
    engine options. '''
    hookenv.status_set('maintenance',
                       'Configuring container runtime with SDN.')
    sdn_config = sdn.get_sdn_config()

    opts = DockerOpts()
    opts.add('bip', sdn_config['subnet'])
    opts.add('mtu', sdn_config['mtu'])

    with open('/etc/default/docker', 'w') as stream:
        stream.write('DOCKER_OPTS="{}"'.format(opts.to_s()))
    _reconfigure_docker_for_sdn()
    set_state('sdn.configured')


@when('kubernetes.worker.bins.installed', 'kube-api-endpoint.available',
      'tls_client.ca.saved', 'tls_client.client.certificate.saved',
      'tls_client.client.key.saved')
@when_not('kube-dns.available')
def start_worker(kube_api):
    '''We have related to either an api server or a load balancer connected
    to the apiserver along with the certificate and keys. Render the init
    scripts.'''
    create_config(kube_api)
    render_init_scripts(kube_api)
    restart_unit_services()


@when('kubernetes.worker.bins.installed', 'kube-api-endpoint.available',
      'tls_client.ca.saved', 'tls_client.client.certificate.saved',
      'tls_client.client.key.saved', 'kube-dns.available')
def render_dns_scripts(kube_api, kube_dns):
    ''' The dns is now available, re-render init config with DNS data. '''
    # Fetch the DNS data on the relationship.
    dns = kube_dns.details()
    # Initialize a FlagManager object to add flags to unit data.
    opts = FlagManager('kubelet')
    # Append the DNS flags + data to the FlagManager object.
    opts.add('--cluster-dns', '{0}:{1}'.format(dns['sdn-ip'], dns['port']))
    opts.add('--cluster-domain', dns['domain'])

    create_config(kube_api)
    render_init_scripts(kube_api)
    restart_unit_services()


def create_config(kube_api):
    '''Create a kubernetes configuration for the worker unit.'''
    server = get_kube_api_server(kube_api)
    # Get the options from the tls-client layer.
    layer_options = layer.options('tls-client')
    # Get all the paths to the tls information required for kubeconfig.
    ca = layer_options.get('ca_certificate_path')
    key = layer_options.get('client_key_path')
    cert = layer_options.get('client_certificate_path')

    # Create kubernetes configuration in the default location for ubuntu.
    create_kubeconfig('/home/ubuntu/.kube/config', server, ca, key, cert,
                      user='ubuntu')
    # Make the config file readable by the ubuntu users so juju scp works.
    cmd = ['chown', 'ubuntu:ubuntu', '/home/ubuntu/.kube/config']
    check_call(cmd)
    # Create kubernetes configuration in the default location for root.
    create_kubeconfig('/root/.kube/config', server, ca, key, cert,
                      user='root')
    # Create kubernetes configuration for kubelet, and kube-proxy services.
    create_kubeconfig('/srv/kubernetes/config', server, ca, key, cert,
                      user='kubelet')


def render_init_scripts(kube_api):
    ''' We have related to either an api server or a load balancer connected
    to the apiserver. Render the config files and prepare for launch '''
    context = {}
    context.update(hookenv.config())

    # Get the tls paths from the layer data.
    layer_options = layer.options('tls-client')
    context['ca_cert_path'] = layer_options.get('ca_certificate_path')
    context['client_cert_path'] = layer_options.get('client_certificate_path')
    context['client_key_path'] = layer_options.get('client_key_path')

    hosts = []
    for serv in kube_api.services():
        for unit in serv['hosts']:
            hosts.append('https://{}:{}'.format(unit['hostname'],
                                                unit['port']))
            hookenv.log(hosts)
    unit_name = os.getenv('JUJU_UNIT_NAME').replace('/', '-')
    context.update({'kube_api_endpoint': ','.join(hosts),
                    'JUJU_UNIT_NAME': unit_name})

    # Create a flag manager for kubelet to render kubelet_opts.
    kubelet_opts = FlagManager('kubelet')
    # Declare to kubelet it needs to read from kubeconfig
    kubelet_opts.add('--require-kubeconfig', None)
    kubelet_opts.add('--kubeconfig', '/srv/kubernetes/config')
    context['kubelet_opts'] = kubelet_opts.to_s()
    # Create a flag manager for kube-proxy to render kube_proxy_opts.
    kube_proxy_opts = FlagManager('kube-proxy')
    kube_proxy_opts.add('--kubeconfig', '/srv/kubernetes/config')
    context['kube_proxy_opts'] = kube_proxy_opts.to_s()

    os.makedirs('/var/lib/kubelet', exist_ok=True)
    # Set the user when rendering config
    context['user'] = 'kubelet'
    # Set the user when rendering config
    context['user'] = 'kube-proxy'
    render('kube-default', '/etc/default/kube-default', context)
    render('kubelet.defaults', '/etc/default/kubelet', context)
    render('kube-proxy.defaults', '/etc/default/kube-proxy', context)
    render('kube-proxy.service', '/lib/systemd/system/kube-proxy.service',
           context)
    render('kubelet.service', '/lib/systemd/system/kubelet.service', context)


def create_kubeconfig(kubeconfig, server, ca, key, certificate, user='ubuntu',
                      context='juju-context', cluster='juju-cluster'):
    '''Create a configuration for Kubernetes based on path using the supplied
    arguments for values of the Kubernetes server, CA, key, certificate, user
    context and cluster.'''
    # Create the config file with the address of the master server.
    cmd = 'kubectl config --kubeconfig={0} set-cluster {1} ' \
          '--server={2} --certificate-authority={3} --embed-certs=true'
    check_call(split(cmd.format(kubeconfig, cluster, server, ca)))
    # Create the credentials using the client flags.
    cmd = 'kubectl config --kubeconfig={0} set-credentials {1} ' \
          '--client-key={2} --client-certificate={3} --embed-certs=true'
    check_call(split(cmd.format(kubeconfig, user, key, certificate)))
    # Create a default context with the cluster.
    cmd = 'kubectl config --kubeconfig={0} set-context {1} ' \
          '--cluster={2} --user={3}'
    check_call(split(cmd.format(kubeconfig, context, cluster, user)))
    # Make the config use this new context.
    cmd = 'kubectl config --kubeconfig={0} use-context {1}'
    check_call(split(cmd.format(kubeconfig, context)))


def restart_unit_services():
    '''Reload the systemd configuration and restart the services.'''
    # Tell systemd to reload configuration from disk for all daemons.
    call(['systemctl', 'daemon-reload'])

    # Ensure the services available after rebooting.
    call(['systemctl', 'enable', 'kubelet.service'])
    call(['systemctl', 'enable', 'kube-proxy.service'])
    # Restart the services.
    hookenv.log('Restarting kubelet, and kube-proxy.')
    call(['systemctl', 'restart', 'kubelet'])
    call(['systemctl', 'restart', 'kube-proxy'])


def get_kube_api_server(kube_api):
    '''Return the kubernetes api server address and port for this
    relationship.'''
    # Get the services from the relation object.
    services = kube_api.services()
    # There is a bug where Kubernetes components do not handle multiple master
    # or server addresses so only return one address from the list.
    if len(services) > 0:
        hosts = services[0]['hosts']
        if len(hosts) > 0:
            server = 'https://{0}:{1}'.format(hosts[0]['hostname'],
                                              hosts[0]['port'])
            hookenv.log('Using server: {0}'.format(server))
        else:
            hookenv.log('Unable to get "server" not enough hosts.')
    else:
        hookenv.log('Unable to get "server" not services.')
    return server


def _systemctl_is_active(application):
    ''' Poll systemctl to determine if the application is running '''
    cmd = ['systemctl', 'is-active', application]
    try:
        raw = check_output(cmd)
        return b'active' in raw
    except Exception:
        return False
