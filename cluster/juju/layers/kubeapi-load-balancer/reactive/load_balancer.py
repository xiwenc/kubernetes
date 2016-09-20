from charms.reactive import when
from charmhelpers.core import hookenv
from charms.reactive.helpers import data_changed

from charms.layer import nginx

from subprocess import Popen
from subprocess import PIPE
from subprocess import STDOUT


@when('nginx.available', 'apiserver.available')
def install_load_balancer(apiserver):
    ''' Create the default vhost template for load balancing '''
    hookenv.open_port(hookenv.config('port'))
    services = apiserver.services()
    if not data_changed('apiserver.services', services):
        return

    nginx.configure_site(
            'apilb',
            'apilb.conf',
            server_name='_',
            services=services,
            port=hookenv.config('port')
    )
    hookenv.status_set('active', 'Loadbalancer ready.')


@when('apiserver.available', 'nginx.available', 'config.port.changed')
def render_host(apiserver):
    ''' Cycle the port change and re-render the vhost template '''
    config = hookenv.config()
    hookenv.close_port(config.previous('port'))
    hookenv.open_port(config['port'])
    services = apiserver.services()
    nginx.configure_site(
            'apilb',
            'apilb.conf',
            server_name='_',
            services=services,
            port=hookenv.config('port')
    )
    hookenv.status_set('active', 'Loadbalancer ready.')


@when('nginx.available')
def set_nginx_version():
    ''' Surface the currently deployed version of flannel to Juju '''
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
