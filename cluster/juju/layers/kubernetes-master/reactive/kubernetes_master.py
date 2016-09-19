import os
import string
import random

from shlex import split
from subprocess import call
from subprocess import check_call
from subprocess import check_output
from subprocess import CalledProcessError

# from charms.reactive import remove_state
from charms.reactive import is_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not
from charms.serveropts import FlagManager

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render


@when_not('kube_master_components.installed')
def install():
    '''Unpack the Kubernetes master binary files.'''
    # Get the resource via resource_get
    archive = hookenv.resource_get('kubernetes')
    if not archive:
        hookenv.status_set('blocked', 'Missing kubernetes resource')
        return

    # Handle null resource publication, we check if its filesize < 1mb
    filesize = os.stat(archive).st_size
    if filesize < 1000000:
        hookenv.status_set('blocked', 'Missing kubernetes resource')
        return

    hookenv.status_set('maintenance', 'Unpacking Kubernetes.')
    files_dir = os.path.join(hookenv.charm_dir(), 'files')

    os.makedirs(files_dir, exist_ok=True)

    command = 'tar -xvzf {0} -C {1}'.format(archive, files_dir)
    print(command)
    return_code = call(split(command))
    dest_dir = '/usr/local/bin/'
    # Create a list of components to install.
    services = ['kube-apiserver',
                'kube-controller-manager',
                'kube-scheduler']
    for service in services:
        # Install each one of the service binaries in /usr/local/bin.
        install = 'install -v {0}/{1} {2}'.format(files_dir, service, dest_dir)
        return_code = call(split(install))
        if return_code != 0:
            raise Exception('Unable to install {0}'.format(service))
    # Install the kubectl tool, which is not a run as a systemd service.
    install = 'install -v {0}/{1} {2}'.format(files_dir, 'kubectl', dest_dir)
    return_code = call(split(install))
    if return_code != 0:
        raise Exception('Unable to install kubectl')
    set_state('kube_master_components.installed')


@when('kube_master_components.installed')
@when_not('authentication.setup')
def setup_authentication():
    '''Setup basic authentication and token access for the cluster.'''
    api_opts = FlagManager('kube-apiserver')
    api_opts.add('--basic-auth-file', '/srv/kubernetes/basic_auth.csv')
    api_opts.add('--token-auth-file', '/srv/kubernetes/known_tokens.csv')
    hookenv.status_set('maintenance', 'Rendering authentication templates.')
    htaccess = '/srv/kubernetes/basic_auth.csv'
    if not os.path.isfile(htaccess):
        setup_basic_auth('admin', 'admin', 'admin')
    known_tokens = '/srv/kubernetes/known_tokens.csv'
    if not os.path.isfile(known_tokens):
        setup_tokens(None, 'admin', 'admin')
        setup_tokens(None, 'kubelet', 'kubelet')
        setup_tokens(None, 'kube_proxy', 'kube_proxy')
    # Generate the default service account token key
    os.makedirs('/etc/kubernetes', exist_ok=True)
    cmd = ['openssl', 'genrsa', '-out', '/etc/kubernetes/serviceaccount.key',
           '2048']
    check_call(cmd)
    set_state('authentication.setup')


@when('kube_master_components.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    version = check_output(['kube-apiserver', '--version'])
    hookenv.application_version_set(version.split(b' ')[-1].rstrip())


@when('etcd.available', 'kube_master_components.installed',
      'kube-sdn.configured')
def start_master(etcd):
    '''Run the Kubernetes master components.'''
    hookenv.status_set('maintenance',
                       'Rendering the Kubernetes master systemd files.')
    handle_etcd_relation(etcd)
    # Use the etcd relation object to render files with etcd information.
    render_files()
    hookenv.status_set('maintenance',
                       'Starting the Kubernetes master services.')
    services = ['kube-apiserver',
                'kube-controller-manager',
                'kube-scheduler']
    for service in services:
        if start_service(service):
            set_state('{0}.available'.format(service))
    hookenv.open_port(8080)
    hookenv.status_set('active', 'Kubernetes master running.')


# TODO: This needs a much better relationship name...
@when('kube-api-endpoint.available')
def push_service_data(kube_api):
    ''' Send configuration to the load balancer, and close access to the
    public interface '''
    hookenv.close_port(8080)
    kube_api.configure(port=8080)


@when('kube-api.connected')
def push_api_data(kube_api):
    ''' Send configuration to remote consumer'''
    data = {'private_address': hookenv.unit_private_ip()}

    # TODO Replace with actual TLS interface code
    if not is_state('ca.connected'):
        data['tls'] = False
        data['port'] = 8080

    kube_api.set_api_credentials(data['private_address'], data['port'],
                                 data['tls'])


@when('kube_master_components.installed', 'sdn-plugin.available')
def gather_sdn_data(sdn_plugin):
    sdn_data = sdn_plugin.get_sdn_config()
    if not sdn_data['cidr'] or not sdn_data['subnet'] or not sdn_data['mtu']:
        hookenv.status_set('waiting', 'Waiting on SDN configuration')
        return
    api_opts = FlagManager('kube-apiserver')
    api_opts.add('--service-cluster-ip-range', sdn_data['cidr'])
    set_state('kube-sdn.configured')


@when('kube_master_components.installed')
@when_not('kubernetes.dashboard.available')
def launch_kubernetes_dashboard():
    ''' Launch the Kubernetes dashboard. If not enabled, attempt deletion '''
    if hookenv.config('dashboard'):
        # TODO - make this self contained
        dashboard_manifest = 'https://rawgit.com/kubernetes/dashboard/master/src/deploy/kubernetes-dashboard.yaml' # noqa
        cmd = ['kubectl', 'create', '-f', dashboard_manifest]
        call(cmd)
        set_state('kubernetes.dashboard.available')
    else:
        cmd = ['kubectl', 'delete', 'kubernetes-dashboard',
               '--namespace=kube-system']
        try:
            call(cmd)
        except CalledProcessError:
            pass


def arch():
    '''Return the package architecture as a string. Raise an exception if the
    architecture is not supported by kubernetes.'''
    # Get the package architecture for this system.
    architecture = check_output(['dpkg', '--print-architecture']).rstrip()
    # Convert the binary result into a string.
    architecture = architecture.decode('utf-8')
    # Validate the architecture is supported by kubernetes.
    if architecture not in ['amd64', 'arm', 'arm64', 'ppc64le']:
        message = 'Unsupported machine architecture: {0}'.format(architecture)
        hookenv.status_set('blocked', message)
        raise Exception(message)
    return architecture


def handle_etcd_relation(reldata):
    ''' Save the client credentials and set appropriate daemon flags when
    etcd declares itself as available'''
    connection_string = reldata.get_connection_string()
    # Define where the etcd tls files will be kept.
    etcd_dir = '/etc/ssl/etcd'
    # Create paths to the etcd client ca, key, and cert file locations.
    ca = os.path.join(etcd_dir, 'client-ca.pem')
    key = os.path.join(etcd_dir, 'client-key.pem')
    cert = os.path.join(etcd_dir, 'client-cert.pem')

    # Save the client credentials (in relation data) to the paths provided.
    reldata.save_client_credentials(key, cert, ca)

    api_opts = FlagManager('kube-apiserver')

    # Never use stale data, always prefer whats coming in during context
    # building. if its stale, its because juju is stale
    if api_opts.data.get('--etcd-servers-strict') or api_opts.data.get('--etcd-servers'):
        api_opts.destroy('--etcd-cafile')
        api_opts.destroy('--etcd-keyfile')
        api_opts.destroy('--etcd-certfile')
        api_opts.destroy('--etcd-servers', strict=True)
        api_opts.destroy('--etcd-servers')


    # Set the apiserver flags in the options manager
    api_opts.add('--etcd-cafile', ca)
    api_opts.add('--etcd-keyfile', key)
    api_opts.add('--etcd-certfile', cert)
    api_opts.add('--etcd-servers', connection_string, strict=True)


def render_files():
    '''Use jinja templating to render the docker-compose.yml and master.json
    file to contain the dynamic data for the configuration files.'''
    context = {}
    # Add the charm configuration data to the context.
    context.update(hookenv.config())

    # Update the context with extra values: arch, and networking information
    context.update({'arch': arch(),
                    'master_address': hookenv.unit_get('private-address'),
                    'public_address': hookenv.unit_get('public-address'),
                    'private_address': hookenv.unit_get('private-address')})

    charm_dir = hookenv.charm_dir()
    rendered_manifest_dir = os.path.join(charm_dir, 'files/manifests')
    if not os.path.exists(rendered_manifest_dir):
        os.makedirs(rendered_manifest_dir)

    api_opts = FlagManager('kube-apiserver')
    controller_opts = FlagManager('kube-controller-manager')
    scheduler_opts = FlagManager('kube-scheduler')

    # Handle static options for now
    # TODO: Read these when appropriate off relationship data
    api_opts.add('--min-request-timeout', '300')
    api_opts.add('--v', '4')

    scheduler_opts.add('--v', '2')

    controller_opts.add('--min-resync-period', '3m')
    controller_opts.add('--service-account-private-key-file',
                        '/etc/kubernetes.serviceaccount.key')
    controller_opts.add('--v', '2')

    context.update({'kube_apiserver_flags': api_opts.to_s(),
                    'kube_scheduler_flags': scheduler_opts.to_s(),
                    'kube_controller_manager_flags': controller_opts.to_s()})

    # Render the configuration files that contains parameters for
    # the apiserver, scheduler, and controller-manager
    render_service('kube-apiserver', context)
    render_service('kube-controller-manager', context)
    render_service('kube-scheduler', context)

    # explicitly render the generic defaults file
    render('config.defaults', '/etc/default/kube-defaults', context)

    # when files change on disk, we need to inform systemd of the changes
    try:
        check_call(['systemctl', 'daemon-reload'])
    except CalledProcessError:
        # we failed, chances are no changes were made. so assume this is fine
        pass


def setup_basic_auth(username='admin', password='admin', user='admin'):
    '''Create the htacces file and the tokens.'''
    srv_kubernetes = '/srv/kubernetes'
    if not os.path.isdir(srv_kubernetes):
        os.makedirs(srv_kubernetes)
    htaccess = os.path.join(srv_kubernetes, 'basic_auth.csv')
    with open(htaccess, 'w') as stream:
        stream.write('{0},{1},{2}'.format(username, password, user))


def setup_tokens(token, username, user):
    '''Create a token file for kubernetes authentication.'''
    srv_kubernetes = '/srv/kubernetes'
    if not os.path.isdir(srv_kubernetes):
        os.makedirs(srv_kubernetes)
    known_tokens = os.path.join(srv_kubernetes, 'known_tokens.csv')
    if not token:
        alpha = string.ascii_letters + string.digits
        token = ''.join(random.SystemRandom().choice(alpha) for _ in range(32))
    with open(known_tokens, 'w') as stream:
        stream.write('{0},{1},{2}'.format(token, username, user))


def start_service(service_name):
    '''Start the systemd service by name return True if the command was
    successful.'''
    start = 'systemctl start {0}'.format(service_name)
    print(start)
    return_code = call(split(start))
    return return_code == 0


def render_service(service_name, context):
    '''Render the systemd service by name.'''
    unit_directory = '/lib/systemd/system'
    source = '{0}.service'.format(service_name)
    target = os.path.join(unit_directory, '{0}.service'.format(service_name))
    render(source, target, context)
    conf_directory = '/etc/default'
    source = '{0}.defaults'.format(service_name)
    target = os.path.join(conf_directory, service_name)
    render(source, target, context)
