#!/usr/bin/env python

# Copyright 2015 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import os
import re
import random
import shutil
import socket
import string
import json
import ipaddress

import charms.leadership

from shutil import move

from shlex import split
from subprocess import check_call
from subprocess import check_output
from subprocess import CalledProcessError

from charms import layer
from charms.layer import snap
from charms.reactive.helpers import data_changed, any_file_changed
from charms.kubernetes.common import get_version
from charms.kubernetes.common import retry


from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.core import unitdata
from charmhelpers.core.templating import render
from charmhelpers.fetch import apt_install
from charmhelpers.contrib.charmsupport import nrpe

# Override the default nagios shortname regex to allow periods, which we
# need because our bin names contain them (e.g. 'snap.foo.daemon'). The
# default regex in charmhelpers doesn't allow periods, but nagios itself does.
nrpe.Check.shortname_re = '[\.A-Za-z0-9-_]+$'

os.environ['PATH'] += os.pathsep + os.path.join(os.sep, 'snap', 'bin')


def add_rbac_roles():
    '''Update the known_tokens file with proper groups.'''

    tokens_fname = '/root/cdk/known_tokens.csv'
    tokens_backup_fname = '/root/cdk/known_tokens.csv.backup'
    move(tokens_fname, tokens_backup_fname)
    with open(tokens_fname, 'w') as ftokens:
        with open(tokens_backup_fname, 'r') as stream:
            for line in stream:
                record = line.strip().split(',')
                # token, username, user, groups
                if record[2] == 'admin' and len(record) == 3:
                    towrite = '{0},{1},{2},"{3}"\n'.format(record[0],
                                                           record[1],
                                                           record[2],
                                                           'system:masters')
                    ftokens.write(towrite)
                    continue
                if record[2] == 'kube_proxy':
                    towrite = '{0},{1},{2}\n'.format(record[0],
                                                     'system:kube-proxy',
                                                     'kube-proxy')
                    ftokens.write(towrite)
                    continue
                if record[2] == 'kubelet' and record[1] == 'kubelet':
                    continue

                ftokens.write('{}'.format(line))


def migrate_from_pre_snaps():
    # disable old services
    services = ['kube-apiserver',
                'kube-controller-manager',
                'kube-scheduler']
    for service in services:
        hookenv.log('Stopping {0} service.'.format(service))
        host.service_stop(service)

    # rename auth files
    os.makedirs('/root/cdk', exist_ok=True)
    rename_file_idempotent('/etc/kubernetes/serviceaccount.key',
                           '/root/cdk/serviceaccount.key')
    rename_file_idempotent('/srv/kubernetes/basic_auth.csv',
                           '/root/cdk/basic_auth.csv')
    rename_file_idempotent('/srv/kubernetes/known_tokens.csv',
                           '/root/cdk/known_tokens.csv')

    # cleanup old files
    files = [
        "/lib/systemd/system/kube-apiserver.service",
        "/lib/systemd/system/kube-controller-manager.service",
        "/lib/systemd/system/kube-scheduler.service",
        "/etc/default/kube-defaults",
        "/etc/default/kube-apiserver.defaults",
        "/etc/default/kube-controller-manager.defaults",
        "/etc/default/kube-scheduler.defaults",
        "/srv/kubernetes",
        "/home/ubuntu/kubectl",
        "/usr/local/bin/kubectl",
        "/usr/local/bin/kube-apiserver",
        "/usr/local/bin/kube-controller-manager",
        "/usr/local/bin/kube-scheduler",
        "/etc/kubernetes"
    ]
    for file in files:
        if os.path.isdir(file):
            hookenv.log("Removing directory: " + file)
            shutil.rmtree(file)
        elif os.path.isfile(file):
            hookenv.log("Removing file: " + file)
            os.remove(file)


def rename_file_idempotent(source, destination):
    if os.path.isfile(source):
        os.rename(source, destination)


def install_snaps(channel):
    hookenv.log('Installing kubectl snap')
    snap.install('kubectl', channel=channel, classic=True)
    hookenv.log('Installing kube-apiserver snap')
    snap.install('kube-apiserver', channel=channel)
    hookenv.log('Installing kube-controller-manager snap')
    snap.install('kube-controller-manager', channel=channel)
    hookenv.log('Installing kube-scheduler snap')
    snap.install('kube-scheduler', channel=channel)
    hookenv.log('Installing cdk-addons snap')
    snap.install('cdk-addons', channel=channel)


def setup_tokens(token, username, user, groups=None):
    '''Create a token file for kubernetes authentication.'''
    root_cdk = '/root/cdk'
    if not os.path.isdir(root_cdk):
        os.makedirs(root_cdk)
    known_tokens = os.path.join(root_cdk, 'known_tokens.csv')
    if not token:
        token = token_generator()
    with open(known_tokens, 'a') as stream:
        if groups:
            stream.write('{0},{1},{2},"{3}"\n'.format(token,
                                                      username,
                                                      user,
                                                      groups))
        else:
            stream.write('{0},{1},{2}\n'.format(token, username, user))


def get_password(csv_fname, user):
    '''Get the password of user within the csv file provided.'''
    root_cdk = '/root/cdk'
    tokens_fname = os.path.join(root_cdk, csv_fname)
    if not os.path.isfile(tokens_fname):
        return None
    with open(tokens_fname, 'r') as stream:
        for line in stream:
            record = line.split(',')
            if record[1] == user:
                return record[0]
    return None


def get_token(username):
    """Grab a token from the static file if present. """
    return get_password('known_tokens.csv', username)


def set_token(password, save_salt):
    ''' Store a token so it can be recalled later by token_generator.

    param: password - the password to be stored
    param: save_salt - the key to store the value of the token.'''
    db = unitdata.kv()
    db.set(save_salt, password)
    return db.get(save_salt)


def token_generator(length=32):
    ''' Generate a random token for use in passwords and account tokens.

    param: length - the length of the token to generate'''
    alpha = string.ascii_letters + string.digits
    token = ''.join(random.SystemRandom().choice(alpha) for _ in range(length))
    return token


@retry(times=3, delay_secs=10)
def all_kube_system_pods_running():
    ''' Check pod status in the kube-system namespace. Returns True if all
    pods are running, False otherwise. '''
    cmd = ['kubectl', 'get', 'po', '-n', 'kube-system', '-o', 'json']

    try:
        output = check_output(cmd).decode('utf-8')
    except CalledProcessError:
        hookenv.log('failed to get kube-system pod status')
        return False

    result = json.loads(output)
    for pod in result['items']:
        status = pod['status']['phase']
        if status != 'Running':
            return False

    return True


def apiserverVersion():
    cmd = 'kube-apiserver --version'.split()
    version_string = check_output(cmd).decode('utf-8')
    return tuple(int(q) for q in re.findall("[0-9]+", version_string)[:3])


def touch(fname):
    try:
        os.utime(fname, None)
    except OSError:
        open(fname, 'a').close()


def configure_scheduler(extra_args):
    scheduler_opts = {}

    scheduler_opts['v'] = '2'
    scheduler_opts['logtostderr'] = 'true'
    scheduler_opts['master'] = 'http://127.0.0.1:8080'

    configure_kubernetes_service('kube-scheduler', scheduler_opts,
                                 extra_args)


def configure_controller_manager(extra_args):
    controller_opts = {}

    # Get the tls paths from the layer data.
    layer_options = layer.options('tls-client')
    ca_cert_path = layer_options.get('ca_certificate_path')

    # Default to 3 minute resync. TODO: Make this configureable?
    controller_opts['min-resync-period'] = '3m'
    controller_opts['v'] = '2'
    controller_opts['root-ca-file'] = ca_cert_path
    controller_opts['logtostderr'] = 'true'
    controller_opts['master'] = 'http://127.0.0.1:8080'

    controller_opts['service-account-private-key-file'] = \
        '/root/cdk/serviceaccount.key'

    configure_kubernetes_service('kube-controller-manager', controller_opts,
                                 extra_args)


def configure_kubernetes_service(service, base_args, extra_args):
    db = unitdata.kv()

    prev_args_key = 'kubernetes-master.prev_args.' + service
    prev_args = db.get(prev_args_key) or {}

    extra_args = parse_extra_args(extra_args)

    args = {}
    for arg in prev_args:
        # remove previous args by setting to null
        args[arg] = 'null'
    for k, v in base_args.items():
        args[k] = v
    for k, v in extra_args.items():
        args[k] = v

    cmd = ['snap', 'set', service] + ['%s=%s' % item for item in args.items()]
    check_call(cmd)

    db.set(prev_args_key, args)


def parse_extra_args(args):
    elements = args.split()
    args = {}

    for element in elements:
        if '=' in element:
            key, _, value = element.partition('=')
            args[key] = value
        else:
            args[element] = 'true'

    return args


def configure_apiserver(etcd, is_privileged, auth_mode, extra_args):
    api_opts = {}

    # Get the tls paths from the layer data.
    layer_options = layer.options('tls-client')
    ca_cert_path = layer_options.get('ca_certificate_path')
    client_cert_path = layer_options.get('client_certificate_path')
    client_key_path = layer_options.get('client_key_path')
    server_cert_path = layer_options.get('server_certificate_path')
    server_key_path = layer_options.get('server_key_path')

    if is_privileged:
        api_opts['allow-privileged'] = 'true'
    else:
        api_opts['allow-privileged'] = 'false'

    # Handle static options for now
    api_opts['service-cluster-ip-range'] = service_cidr()
    api_opts['min-request-timeout'] = '300'
    api_opts['v'] = '4'
    api_opts['tls-cert-file'] = server_cert_path
    api_opts['tls-private-key-file'] = server_key_path
    api_opts['kubelet-certificate-authority'] = ca_cert_path
    api_opts['kubelet-client-certificate'] = client_cert_path
    api_opts['kubelet-client-key'] = client_key_path
    api_opts['logtostderr'] = 'true'
    api_opts['insecure-bind-address'] = '127.0.0.1'
    api_opts['insecure-port'] = '8080'
    api_opts['storage-backend'] = 'etcd2'  # FIXME: add etcd3 support

    api_opts['basic-auth-file'] = '/root/cdk/basic_auth.csv'
    api_opts['token-auth-file'] = '/root/cdk/known_tokens.csv'
    api_opts['service-account-key-file'] = '/root/cdk/serviceaccount.key'

    etcd_dir = '/root/cdk/etcd'
    etcd_ca = os.path.join(etcd_dir, 'client-ca.pem')
    etcd_key = os.path.join(etcd_dir, 'client-key.pem')
    etcd_cert = os.path.join(etcd_dir, 'client-cert.pem')

    api_opts['etcd-cafile'] = etcd_ca
    api_opts['etcd-keyfile'] = etcd_key
    api_opts['etcd-certfile'] = etcd_cert
    api_opts['etcd-servers'] = etcd.get_connection_string()

    admission_control = [
        'Initializers',
        'NamespaceLifecycle',
        'LimitRanger',
        'ServiceAccount',
        'ResourceQuota',
        'DefaultTolerationSeconds'
    ]

    if 'Node' in auth_mode:
        admission_control.append('NodeRestriction')

    api_opts['authorization-mode'] = auth_mode

    if get_version('kube-apiserver') < (1, 6):
        hookenv.log('Removing DefaultTolerationSeconds from admission-control')
        admission_control.remove('DefaultTolerationSeconds')
    if get_version('kube-apiserver') < (1, 7):
        hookenv.log('Removing Initializers from admission-control')
        admission_control.remove('Initializers')
    api_opts['admission-control'] = ','.join(admission_control)

    configure_kubernetes_service('kube-apiserver', api_opts, extra_args)


def service_cidr(cidr):
    ''' Return the charm's service-cidr config '''
    db = unitdata.kv()
    frozen_cidr = db.get('kubernetes-master.service-cidr')
    return frozen_cidr or cidr


def freeze_service_cidr(cidr):
    ''' Freeze the service CIDR. Once the apiserver has started, we can no
    longer safely change this value. '''
    db = unitdata.kv()
    db.set('kubernetes-master.service-cidr', cidr)


def master_services_down():
    """Ensure master services are up and running.

    Return: list of failing services"""
    services = ['kube-apiserver',
                'kube-controller-manager',
                'kube-scheduler']
    failing_services = []
    for service in services:
        daemon = 'snap.{}.daemon'.format(service)
        if not host.service_running(daemon):
            failing_services.append(service)
    return failing_services

def arch():
    '''Return the package architecture as a string. Raise an exception if the
    architecture is not supported by kubernetes.'''
    # Get the package architecture for this system.
    architecture = check_output(['dpkg', '--print-architecture']).rstrip()
    # Convert the binary result into a string.
    architecture = architecture.decode('utf-8')
    return architecture


def build_kubeconfig(server):
    '''Gather the relevant data for Kubernetes configuration objects and create
    a config object with that information.'''
    # Get the options from the tls-client layer.
    layer_options = layer.options('tls-client')
    # Get all the paths to the tls information required for kubeconfig.
    ca = layer_options.get('ca_certificate_path')
    ca_exists = ca and os.path.isfile(ca)
    client_pass = get_password('basic_auth.csv', 'admin')
    # Do we have everything we need?
    if ca_exists and client_pass:
        # Create an absolute path for the kubeconfig file.
        kubeconfig_path = os.path.join(os.sep, 'home', 'ubuntu', 'config')
        # Create the kubeconfig on this system so users can access the cluster.

        create_kubeconfig(kubeconfig_path, server, ca,
                          user='admin', password=client_pass)
        # Make the config file readable by the ubuntu users so juju scp works.
        cmd = ['chown', 'ubuntu:ubuntu', kubeconfig_path]
        check_call(cmd)


def create_kubeconfig(kubeconfig, server, ca, key=None, certificate=None,
                      user='ubuntu', context='juju-context',
                      cluster='juju-cluster', password=None, token=None):
    '''Create a configuration for Kubernetes based on path using the supplied
    arguments for values of the Kubernetes server, CA, key, certificate, user
    context and cluster.'''
    if not key and not certificate and not password and not token:
        raise ValueError('Missing authentication mechanism.')

    # token and password are mutually exclusive. Error early if both are
    # present. The developer has requested an impossible situation.
    # see: kubectl config set-credentials --help
    if token and password:
        raise ValueError('Token and Password are mutually exclusive.')
    # Create the config file with the address of the master server.
    cmd = 'kubectl config --kubeconfig={0} set-cluster {1} ' \
          '--server={2} --certificate-authority={3} --embed-certs=true'
    check_call(split(cmd.format(kubeconfig, cluster, server, ca)))
    # Delete old users
    cmd = 'kubectl config --kubeconfig={0} unset users'
    check_call(split(cmd.format(kubeconfig)))
    # Create the credentials using the client flags.
    cmd = 'kubectl config --kubeconfig={0} ' \
          'set-credentials {1} '.format(kubeconfig, user)

    if key and certificate:
        cmd = '{0} --client-key={1} --client-certificate={2} '\
              '--embed-certs=true'.format(cmd, key, certificate)
    if password:
        cmd = "{0} --username={1} --password={2}".format(cmd, user, password)
    # This is mutually exclusive from password. They will not work together.
    if token:
        cmd = "{0} --token={1}".format(cmd, token)
    check_call(split(cmd))
    # Create a default context with the cluster.
    cmd = 'kubectl config --kubeconfig={0} set-context {1} ' \
          '--cluster={2} --user={3}'
    check_call(split(cmd.format(kubeconfig, context, cluster, user)))
    # Make the config use this new context.
    cmd = 'kubectl config --kubeconfig={0} use-context {1}'
    check_call(split(cmd.format(kubeconfig, context)))


def get_dns_ip():
    '''Get an IP address for the DNS server on the provided cidr.'''
    interface = ipaddress.IPv4Interface(service_cidr())
    # Add .10 at the end of the network
    ip = interface.network.network_address + 10
    return ip.exploded


def get_kubernetes_service_ip():
    '''Get the IP address for the kubernetes service based on the cidr.'''
    interface = ipaddress.IPv4Interface(service_cidr())
    # Add .1 at the end of the network
    ip = interface.network.network_address + 1
    return ip.exploded


def handle_etcd_relation(reldata):
    ''' Save the client credentials and set appropriate daemon flags when
    etcd declares itself as available'''
    # Define where the etcd tls files will be kept.
    etcd_dir = '/root/cdk/etcd'

    # Create paths to the etcd client ca, key, and cert file locations.
    ca = os.path.join(etcd_dir, 'client-ca.pem')
    key = os.path.join(etcd_dir, 'client-key.pem')
    cert = os.path.join(etcd_dir, 'client-cert.pem')

    # Save the client credentials (in relation data) to the paths provided.
    reldata.save_client_credentials(key, cert, ca)


def setup_ceph(ceph_admin):
    '''Ceph on kubernetes will require a few things - namely a ceph
    configuration, and the ceph secret key file used for authentication.
    This method will install the client package, and render the requisit files
    in order to consume the ceph-storage relation.'''
    ceph_context = {
        'mon_hosts': ceph_admin.mon_hosts(),
        'fsid': ceph_admin.fsid(),
        'auth_supported': ceph_admin.auth(),
        'use_syslog': "true",
        'ceph_public_network': '',
        'ceph_cluster_network': '',
        'loglevel': 1,
        'hostname': socket.gethostname(),
    }
    # Install the ceph common utilities.
    apt_install(['ceph-common'], fatal=True)
    etc_ceph_directory = '/etc/ceph'
    if not os.path.isdir(etc_ceph_directory):
        os.makedirs(etc_ceph_directory)
    charm_ceph_conf = os.path.join(etc_ceph_directory, 'ceph.conf')
    # Render the ceph configuration from the ceph conf template
    render('ceph.conf', charm_ceph_conf, ceph_context)
    # The key can rotate independently of other ceph config, so validate it
    admin_key = os.path.join(etc_ceph_directory,
                             'ceph.client.admin.keyring')
    try:
        with open(admin_key, 'w') as key_file:
            key_file.write("[client.admin]\n\tkey = {}\n".format(
                ceph_admin.key()))
    except IOError as err:
        hookenv.log("IOError writing admin.keyring: {}".format(err))

    # Enlist the ceph-admin key as a kubernetes secret
    if ceph_admin.key():
        encoded_key = base64.b64encode(ceph_admin.key().encode('utf-8'))
    else:
        # We didn't have a key, and cannot proceed. Do not set state and
        # allow this method to re-execute
        return False
    context = {'secret': encoded_key.decode('ascii')}
    render('ceph-secret.yaml', '/tmp/ceph-secret.yaml', context)
    try:
        # At first glance this is deceptive. The apply stanza will create if
        # it doesn't exist, otherwise it will update the entry, ensuring our
        # ceph-secret is always reflective of what we have in /etc/ceph
        # assuming we have invoked this anytime that file would change.
        cmd = ['kubectl', 'apply', '-f', '/tmp/ceph-secret.yaml']
        check_call(cmd)
        os.remove('/tmp/ceph-secret.yaml')
    except:  # NOQA
        # the enlistment in kubernetes failed, return and prepare for re-exec
        return False

    # when complete, set a state relating to configuration of the storage
    # backend that will allow other modules to hook into this and verify we
    # have performed the necessary pre-req steps to interface with a ceph
    # deployment.
    return True


def setup_basic_auth(password=None, username='admin', uid='admin',
                     groups=None):
    '''Create the htacces file and the tokens.'''
    root_cdk = '/root/cdk'
    if not os.path.isdir(root_cdk):
        os.makedirs(root_cdk)
    htaccess = os.path.join(root_cdk, 'basic_auth.csv')
    if not password:
        password = token_generator()
    with open(htaccess, 'w') as stream:
        if groups:
            stream.write('{0},{1},{2},"{3}"'.format(password,
                                                    username, uid, groups))
        else:
            stream.write('{0},{1},{2}'.format(password, username, uid))


def setup_leader_auth(reconfigure):
    '''Setup basic authentication and token access for the cluster.'''
    service_key = '/root/cdk/serviceaccount.key'
    basic_auth = '/root/cdk/basic_auth.csv'
    known_tokens = '/root/cdk/known_tokens.csv'
    keys = [service_key, basic_auth, known_tokens]
    # Try first to fetch data from an old leadership broadcast.
    if not get_keys_from_leader(keys) \
            or reconfigure:
        last_pass = get_password('basic_auth.csv', 'admin')
        setup_basic_auth(last_pass, 'admin', 'admin', 'system:masters')

        if not os.path.isfile(known_tokens):
            touch(known_tokens)

        # Generate the default service account token key
        os.makedirs('/root/cdk', exist_ok=True)
        if not os.path.isfile(service_key):
            cmd = ['openssl', 'genrsa', '-out', service_key,
                   '2048']
            check_call(cmd)

    # read service account key for syndication
    leader_data = {}
    for f in [known_tokens, basic_auth, service_key]:
        with open(f, 'r') as fp:
            leader_data[f] = fp.read()

    # this is slightly opaque, but we are sending file contents under its file
    # path as a key.
    # eg:
    # {'/root/cdk/serviceaccount.key': 'RSA:2471731...'}
    charms.leadership.leader_set(leader_data)


def setup_non_leader_auth(re_apply):
    service_key = '/root/cdk/serviceaccount.key'
    basic_auth = '/root/cdk/basic_auth.csv'
    known_tokens = '/root/cdk/known_tokens.csv'

    keys = [service_key, basic_auth, known_tokens]
    # The source of truth for non-leaders is the leader.
    # Therefore we overwrite_local with whatever the leader has.
    if not get_keys_from_leader(keys, overwrite_local=True):
        # the keys were not retrieved. Non-leaders have to retry.
        return False

    if not any_file_changed(keys) and re_apply:
        # No change detected and we have already setup the authentication
        return False

    return True


def get_keys_from_leader(keys, overwrite_local=False):
    """
    Gets the broadcasted keys from the leader and stores them in
    the corresponding files.

    Args:
        keys: list of keys. Keys are actually files on the FS.

    Returns: True if all key were fetched, False if not.

    """
    # This races with other codepaths, and seems to require being created first
    # This block may be extracted later, but for now seems to work as intended
    os.makedirs('/root/cdk', exist_ok=True)

    for k in keys:
        # If the path does not exist, assume we need it
        if not os.path.exists(k) or overwrite_local:
            # Fetch data from leadership broadcast
            contents = charms.leadership.leader_get(k)
            # Default to logging the warning and wait for leader data to be set
            if contents is None:
                hookenv.log('Missing content for file {}'.format(k))
                return False
            # Write out the file and move on to the next item
            with open(k, 'w+') as fp:
                fp.write(contents)
                fp.write('\n')

    return True


def set_addons_args(dashboards_enabled, dns_domain):
    dbEnabled = str(dashboards_enabled).lower()
    args = [
        'arch=' + arch(),
        'dns-ip=' + get_dns_ip(),
        'dns-domain=' + dns_domain,
        'enable-dashboard=' + dbEnabled
    ]
    check_call(['snap', 'set', 'cdk-addons'] + args)


@retry(times=3, delay_secs=20)
def addons_ready():
    """
    Test if the add ons got installed

    Returns: True is the addons got applied

    """
    try:
        check_call(['cdk-addons.apply'])
        return True
    except CalledProcessError:
        hookenv.log("Addons are not ready yet.")
        return False


def create_configs(kube_control):
    """Create the users for kubelet"""
    should_restart = False
    # generate the username/pass for the requesting unit
    proxy_token = get_token('system:kube-proxy')
    if not proxy_token:
        setup_tokens(None, 'system:kube-proxy', 'kube-proxy')
        proxy_token = get_token('system:kube-proxy')
        should_restart = True
    client_token = get_token('admin')
    if not client_token:
        setup_tokens(None, 'admin', 'admin', "system:masters")
        client_token = get_token('admin')
        should_restart = True
    requests = kube_control.auth_user()
    for request in requests:
        username = request[1]['user']
        group = request[1]['group']
        kubelet_token = get_token(username)
        if not kubelet_token and username and group:
            # Usernames have to be in the form of system:node:<nodeName>
            userid = "kubelet-{}".format(request[0].split('/')[1])
            setup_tokens(None, username, userid, group)
            kubelet_token = get_token(username)
            kube_control.sign_auth_request(request[0], username,
                                           kubelet_token, proxy_token,
                                           client_token)
            should_restart = True
    return should_restart


