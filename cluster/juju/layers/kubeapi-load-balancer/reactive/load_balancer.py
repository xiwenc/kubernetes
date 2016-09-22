from charms import layer
from charms.reactive import when
from charmhelpers.core import hookenv

from charms.layer import nginx

from subprocess import Popen
from subprocess import PIPE
from subprocess import STDOUT

import os
import socket


@when('certificates.available')
def request_server_certificates(tls):
    '''Send the data that is required to create a server certificate for
    this server.'''
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()
    # Create SANs that the tls layer will add to the server cert.
    sans = [
        hookenv.unit_public_ip(),
        hookenv.unit_private_ip(),
        socket.gethostname(),
    ]
    # Create a path safe name by removing path characters from the unit name.
    certificate_name = hookenv.local_unit().replace('/', '_')
    # Request a server cert with this information.
    tls.request_server_cert(common_name, sans, certificate_name)


@when('nginx.available', 'apiserver.available',
      'certificates.server.cert.available')
def install_load_balancer(apiserver, tls):
    ''' Create the default vhost template for load balancing '''
    hookenv.open_port(hookenv.config('port'))
    services = apiserver.services()

    layer_options = layer.options('tls-client')
    certificates_directory = layer_options.get('certificates-directory')
    server_certificate = os.path.join(certificates_directory,
                                      'server.crt')
    server_key = os.path.join(certificates_directory, 'server.key')
    nginx.configure_site(
            'apilb',
            'apilb.conf',
            server_name='_',
            services=services,
            port=hookenv.config('port'),
            server_certificate=server_certificate,
            server_key=server_key,
    )
    hookenv.status_set('active', 'Loadbalancer ready.')


@when('nginx.available')
def set_nginx_version():
    ''' Surface the currently deployed version of nginx to Juju '''
    cmd = 'nginx -v'
    p = Popen(cmd, shell=True,
              stdin=PIPE,
              stdout=PIPE,
              stderr=STDOUT,
              close_fds=True)
    raw = p.stdout.read()
    # The version comes back as:
    # nginx version: nginx/1.10.0 (Ubuntu)
    version = raw.split(b'/')[-1].split(b' ')[0]
    hookenv.application_version_set(version.rstrip())


@when('website.available')
def provide_application_details(website):
    ''' re-use the nginx layer website relation to relay the hostname/port
    to any consuming kubernetes-workers, or other units that require the
    kubernetes API '''
    website.configure(port=hookenv.config('port'))


@when('loadbalancer.available')
def provide_loadbalancing(loadbalancer):
    '''Send the public address and port to the public-address interface, so
    the subordinates can get the public address of this loadbalancer.'''
    loadbalancer.set_address_port(hookenv.unit_get('public-address'),
                                  hookenv.config('port'))
