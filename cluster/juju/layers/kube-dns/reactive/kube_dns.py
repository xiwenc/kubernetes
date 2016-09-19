from charms.reactive import when, when_not, set_state, remove_state, hook
from charms.templating.jinja2 import render
from charmhelpers.core import host
from charmhelpers.core import hookenv
import os
import subprocess


@hook('upgrade-charm')
def reset_state():
    remove_state('kube-dns.installed')


@when_not('kube-dns.installed')
def install_kube_dns():
    hookenv.status_set('maintenance', 'Installing kube-dns')
    filepath = hookenv.resource_get('kube-dns')
    if filepath:
        subprocess.check_call(['install', filepath, '/usr/local/bin/kube-dns'])

    set_state('kube-dns.installed')


@when('kube-dns.installed', 'kube-api.available')
@when_not('kube-dns.configured')
def render_kubedns_templates(kube_api):
    ''' Gather context and render templates '''
    context = hookenv.config()
    if kube_api.is_secure():
        creds = kube_api.get_full_credentials()
        url = "https://{0}:{1}".format(creds['private_address'], creds['port'])
        context.update({'kube_master_url': url})
    else:
        creds = kube_api.get_basic_credentials()
        url = "http://{0}:{1}".format(creds['private_address'], creds['port'])
        context.update({'kube_master_url': url})

    render('kube-dns.service', '/lib/systemd/system/kube-dns.service',
           context)
    subprocess.call(['systemctl', 'daemon-reload'])
    hookenv.status_set('active', 'KubeDNS Ready')
    host.service_start('kube-dns.service')


@when('cluster-dns.connected')
def send_cluster_dns(cluster):
    config = hookenv.config()
    cluster.set_dns_info(port=config['port'], domain=config['domain'])


@hook('stop')
def self_cleanup():
    _wipe('/lib/systemd/system/kube-dns.service')
    _wipe('/usr/local/bin/kubelet')
    _wipe('/etc/default/kubelet')


def _wipe(filepath):
    if os.path.exists(filepath):
        os.remove(filepath)
