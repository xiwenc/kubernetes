import os

from shlex import split
from subprocess import call
from subprocess import check_call
from subprocess import check_output
from socket import gethostname

from charms import layer
from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not
from charms.reactive.helpers import data_changed

from charmhelpers.core import hookenv
from charmhelpers.core.host import restart_on_change

from charms.kubernetes.flagmanager import FlagManager

from charms.templating.jinja2 import render


@hook('upgrade-charm')
def remove_installed_state():
    remove_state('kubernetes-worker.components.installed')

@hook('stop')
def remove_this_node():
    ''' Deletes this unit's node when the unit is destroyed. '''
    kubectl = ['kubectl', '--kubeconfig=/srv/kubernetes/config']
    command = kubectl + ['delete', 'node', gethostname()]
    output = check_call(command, shell=False)

@when('docker.available')
@when_not('kubernetes-worker.components.installed')
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

    set_state('kubernetes-worker.components.installed')


@when('kubernetes-worker.components.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    cmd = ['kubelet', '--version']
    version = check_output(cmd)
    hookenv.application_version_set(version.split(b' v')[-1].rstrip())


@when('kubernetes-worker.components.installed')
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


@when('kubernetes-worker.components.installed', 'kube-dns.available')
def charm_status(kube_dns):
    '''Update the status message with the current status of kubelet.'''
    update_kubelet_status()


def update_kubelet_status():
    ''' There are different states that the kubelt can be in, where we are
    waiting for dns, waiting for cluster turnup, or ready to serve
    applications.'''
    # Daemon options are managed by the FlagManager class
    kubelet_opts = FlagManager('kubelet')

    # Query the FlagManager dict for the dns option, and determine if
    # kubelet is running
    if (_systemctl_is_active('kubelet') and
       '--cluster-dns' not in kubelet_opts.data):
        hookenv.status_set('waiting', 'Waiting for cluster DNS.')
    elif (_systemctl_is_active('kubelet') and
          '--cluster-dns' in kubelet_opts.data):
        hookenv.status_set('active', 'Kubernetes worker running.')
    # if kubelet is not running, we're waiting on something else to converge
    elif (not _systemctl_is_active('kubelet')):
        hookenv.status_set('waiting', 'Waiting for kubelet to start.')


@when('kubernetes-worker.components.installed', 'kube-api-endpoint.available',
      'tls_client.ca.saved', 'tls_client.client.certificate.saved',
      'tls_client.client.key.saved')
@when_not('kube-dns.available')
def start_worker(kube_api):
    '''Need to start the worker services before the api-server can schedule
    required addons like DNS inside the workers.'''
    # Get the list of kubernetes api servers from the relationship object.
    servers = get_kube_api_servers(kube_api)
    if data_changed('kube-api-servers', servers):
        create_config(servers[0])
        render_init_scripts(servers)
        restart_unit_services()
        update_kubelet_status()


@when('kubernetes-worker.components.installed', 'kube-api-endpoint.available',
      'tls_client.ca.saved', 'tls_client.client.certificate.saved',
      'tls_client.client.key.saved', 'kube-dns.available')
def render_dns_scripts(kube_api, kube_dns):
    ''' The dns is now available, re-render init config with DNS data. '''
    # GEt the list of kubernetes api servers from the relationship object.
    servers = get_kube_api_servers(kube_api)
    # Fetch the DNS data on the relationship.
    dns = kube_dns.details()
    if (data_changed('kube-api-servers', servers) or
            data_changed('kube-dns', dns)):
        # Initialize a FlagManager object to add flags to unit data.
        opts = FlagManager('kubelet')
        # Append the DNS flags + data to the FlagManager object.
        opts.add('--cluster-dns', '{0}:{1}'.format(dns['sdn-ip'], dns['port']))
        opts.add('--cluster-domain', dns['domain'])
        create_config(servers[0])
        render_init_scripts(servers)
        set_state('kubernetes-worker.config.created')
        restart_unit_services()
        update_kubelet_status()


@when('config.changed.ingress')
def toggle_ingress_state():
    ''' Ingress is a toggled state. Remove ingress.available if set when
    toggled '''
    remove_state('kubernetes-worker.ingress.available')


@when('docker.sdn.configured')
def sdn_changed():
    '''The Software Defined Network changed on the container so restart the
    kubernetes services.'''
    restart_unit_services()
    update_kubelet_status()
    remove_state('docker.sdn.configured')


@when('kubernetes-worker.config.created', 'kube-dns.available')
@when_not('kubernetes-worker.ingress.available')
def render_and_launch_ingress(kube_dns):
    ''' If configuration has ingress RC enabled, launch the ingress load
    balancer and default http backend. Otherwise attempt deletion. '''
    config = hookenv.config()
    # If ingress is enabled, launch the ingress controller and open ports
    if config.get('ingress'):
        launch_default_ingress_controller()
        hookenv.open_port(80)
        hookenv.open_port(443)
    else:
        hookenv.log('Deleting the http backend and ingress.')
        kubectl('delete', '/etc/kubernetes/addons/default-http-backend.yaml')
        kubectl('delete', '/etc/kubernetes/addons/ingress-replication-controller.yaml')  # noqa
        hookenv.close_port(80)
        hookenv.close_port(443)


def arch():
    '''Return the package architecture as a string. Raise an exception if the
    architecture is not supported by kubernetes.'''
    # Get the package architecture for this system.
    architecture = check_output(['dpkg', '--print-architecture']).rstrip()
    # Convert the binary result into a string.
    architecture = architecture.decode('utf-8')
    return architecture


def create_config(server):
    '''Create a kubernetes configuration for the worker unit.'''
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


def render_init_scripts(api_servers):
    ''' We have related to either an api server or a load balancer connected
    to the apiserver. Render the config files and prepare for launch '''
    context = {}
    context.update(hookenv.config())

    # Get the tls paths from the layer data.
    layer_options = layer.options('tls-client')
    context['ca_cert_path'] = layer_options.get('ca_certificate_path')
    context['client_cert_path'] = layer_options.get('client_certificate_path')
    context['client_key_path'] = layer_options.get('client_key_path')

    unit_name = os.getenv('JUJU_UNIT_NAME').replace('/', '-')
    context.update({'kube_api_endpoint': ','.join(api_servers),
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


def launch_default_ingress_controller():
    ''' Launch the Kubernetes ingress controller & default backend (404) '''
    context = {}
    context['arch'] = arch()
    addon_path = '/etc/kubernetes/addons/{}'
    manifest = addon_path.format('default-http-backend.yaml')
    # Render the default http backend (404) replicationcontroller manifest
    render('default-http-backend.yaml', manifest, context)
    hookenv.log('Creating the default http backend.')
    kubectl('create', manifest)
    # Render the ingress replication controller manifest
    manifest = addon_path.format('ingress-replication-controller.yaml')
    render('ingress-replication-controller.yaml', manifest, context)
    kubectl('create', manifest)
    hookenv.log('Creating the ingress replication controller.')
    set_state('kubernetes-worker.ingress.available')


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


def get_kube_api_servers(kube_api):
    '''Return the kubernetes api server address and port for this
    relationship.'''
    hosts = []
    # Iterate over every service from the relation object.
    for service in kube_api.services():
        for unit in service['hosts']:
            hosts.append('https://{0}:{1}'.format(unit['hostname'],
                                                  unit['port']))
    return hosts


def kubectl(operation, manifest):
    ''' Wrap the kubectl creation command when using filepath resources
    :param operation - one of get, create, delete, replace
    :param manifest - filepath to the manifest
     '''
    kubectl = ['kubectl', '--kubeconfig=/srv/kubernetes/config']
    # determine if the kubernetes resources have been declared already

    # Deletions are a special case
    if operation == 'delete':
        # Ensure we immediately remove requested resources with --now
        command = kubectl + [operation, '-f', manifest, '--now']
        return_code = call(command)
        hookenv.log('Executed {} got {}'.format(command, return_code))
        return return_code == 0
    else:
        # Guard against an error re-creating the same manifest multiple times
        if operation == 'create':
            found = call(kubectl + ['get', '-f', manifest])
            # If we already have the definition, its probably safe to assume
            # creation was true.
            if found == 0:
                hookenv.log('Skipping definition for {}'.format(manifest))
                return True
        # Execute the requested command that did not match any of the special
        # cases above
        command = kubectl + [operation, '-f', manifest]
        return_code = call(command)
        hookenv.log('Executed {} got {}'.format(command, return_code))
        return return_code == 0


def _systemctl_is_active(application):
    ''' Poll systemctl to determine if the application is running '''
    cmd = ['systemctl', 'is-active', application]
    try:
        raw = check_output(cmd)
        return b'active' in raw
    except Exception:
        return False
