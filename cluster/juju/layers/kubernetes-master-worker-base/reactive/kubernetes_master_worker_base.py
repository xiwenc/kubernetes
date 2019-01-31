import os
import shutil
import subprocess
from subprocess import check_call, check_output, CalledProcessError
from charms.reactive import endpoint_from_flag, set_state, remove_state, \
    when, when_not
from charms.docker import DockerOpts
from charms.layer.kubernetes_common import client_crt_path, client_key_path
from charmhelpers.core import hookenv, unitdata
from charmhelpers.core.host import install_ca_cert


db = unitdata.kv()


@when('endpoint.docker-registry.ready')
@when_not('kubernetes-master-worker-base.registry.configured')
def configure_registry():
    '''Add docker registry config when present.'''
    registry = endpoint_from_flag('endpoint.docker-registry.ready')
    netloc = registry.registry_netloc

    # handle tls data
    cert_subdir = netloc
    insecure_opt = {'insecure-registry': netloc}
    if registry.has_tls():
        # ensure the CA that signed our registry cert is trusted
        install_ca_cert(registry.tls_ca, name='juju-docker-registry')
        # remove potential insecure docker opts related to this registry
        manage_docker_opts(insecure_opt, remove=True)
        manage_registry_certs(cert_subdir, remove=False)
    else:
        manage_docker_opts(insecure_opt, remove=False)
        manage_registry_certs(cert_subdir, remove=True)

    # handle auth data
    if registry.has_auth_basic():
        hookenv.log('Logging into docker registry: {}.'.format(netloc))
        cmd = ['docker', 'login', netloc,
               '-u', registry.basic_user, '-p', registry.basic_password]
        try:
            check_output(cmd, stderr=subprocess.STDOUT)
        except CalledProcessError as e:
            if b'http response' in e.output.lower():
                # non-tls login with basic auth will error like this:
                #  Error response ... server gave HTTP response to HTTPS client
                msg = 'docker login requires a TLS-enabled registry'
            elif b'unauthorized' in e.output.lower():
                # invalid creds will error like this:
                #  Error response ... 401 Unauthorized
                msg = 'Incorrect credentials for docker registry'
            else:
                msg = 'docker login failed, see juju debug-log'
            hookenv.status_set('blocked', msg)
    else:
        hookenv.log('Disabling auth for docker registry: {}.'.format(netloc))
        # NB: it's safe to logout of a registry that was never logged in
        check_call(['docker', 'logout', netloc])

    # NB: store our netloc so we can clean up if the registry goes away
    db.set('registry_netloc', netloc)
    set_state('kubernetes-master-worker-base.registry.configured')


@when('endpoint.docker-registry.changed',
      'kubernetes-master-worker-base.registry.configured')
def reconfigure_registry():
    '''Signal to update the registry config when something changes.'''
    remove_state('kubernetes-master-worker-base.registry.configured')


@when('kubernetes-master-worker-base.registry.configured')
@when_not('endpoint.docker-registry.joined')
def remove_registry():
    '''Remove registry config when the registry is no longer present.'''
    netloc = db.get('registry_netloc', None)

    if netloc:
        # remove tls-related data
        cert_subdir = netloc
        insecure_opt = {'insecure-registry': netloc}
        manage_docker_opts(insecure_opt, remove=True)
        manage_registry_certs(cert_subdir, remove=True)

        # remove auth-related data
        hookenv.log('Disabling auth for docker registry: {}.'.format(netloc))
        # NB: it's safe to logout of a registry that was never logged in
        check_call(['docker', 'logout', netloc])

    remove_state('kubernetes-master-worker-base.registry.configured')


def manage_docker_opts(opts, remove=False):
    '''Add or remove docker daemon options.

    Options here will be merged with configured docker-opts when layer-docker
    processes a daemon restart.

    :param: dict opts: option keys/values; use None value if the key is a flag
    :param: bool remove: True to remove the options; False to add them
    '''
    docker_opts = DockerOpts()
    for k, v in opts.items():
        # Always remove existing option
        if docker_opts.exists(k):
            docker_opts.pop(k)
        if not remove:
            docker_opts.add(k, v)
    hookenv.log('DockerOpts daemon options changed. Requesting a restart.')
    # State will be removed by layer-docker after restart
    set_state('docker.restart')


def manage_registry_certs(subdir, remove=False):
    '''Add or remove TLS data for a specific registry.

    When present, the docker client will use certificates when communicating
    with a specific registry.

    :param: str subdir: subdirectory to store the client certificates
    :param: bool remove: True to remove cert data; False to add it
    '''
    cert_dir = '/etc/docker/certs.d/{}'.format(subdir)

    if remove:
        if os.path.isdir(cert_dir):
            hookenv.log('Disabling registry TLS: {}.'.format(cert_dir))
            shutil.rmtree(cert_dir)
    else:
        os.makedirs(cert_dir, exist_ok=True)
        client_tls = {
            client_crt_path: '{}/client.cert'.format(cert_dir),
            client_key_path: '{}/client.key'.format(cert_dir),
        }
        for f, link in client_tls.items():
            try:
                os.remove(link)
            except FileNotFoundError:
                pass
            hookenv.log('Creating registry TLS link: {}.'.format(link))
            os.symlink(f, link)
