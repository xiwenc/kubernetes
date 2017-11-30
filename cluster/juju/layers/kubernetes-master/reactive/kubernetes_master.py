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

# Do not do that
from master_works import *


import socket
from subprocess import check_output

from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import is_state
from charms.reactive import when, when_any, when_not, when_all
from charms.reactive.helpers import data_changed, any_file_changed

from charms.layer import tls_client

from charmhelpers.core import hookenv
from charmhelpers.core import host
from charmhelpers.core.host import service_stop
from charmhelpers.contrib.charmsupport import nrpe


# 'kubernetes-master.upgrade-needed' an upgrade is ongoing
# 'kubernetes-master.upgrade-specified' upgrade should continue without the need to call the upgrade action OR the upgrade action is already called
# 'kubernetes.components.installed' unused
# 'kubernetes.dashboard.available' unused
# 'kube-dns.available' unused
# 'kubernetes-master.app_version.set' unused
# 'reconfigure.authentication.setup' this state is set when we trigger the configurating of the authorization facilities and signals that this is not the first time we configure auth.
# 'authentication.setup' the authorisation configuration is done
# 'kubernetes-master.components.started' all components of master have started. Remove this to cause a restart of the master
# 'client.password.initialised' password initialsed and different from "" aka set to random
# 'cdk-addons.configured' configured and running
# 'kubernetes-master.snaps.installed' snaps are installed
# 'kube-controller-manager.do-restart' cause a restart to controller manager
# 'kube-apiserver.do-restart' cause a restart of api server
# 'kube-scheduler.do-restart' cause a restart of scheduler

def set_upgrade_needed():
    set_state('kubernetes-master.upgrade-needed')
    config = hookenv.config()
    previous_channel = config.previous('channel')
    require_manual = config.get('require-manual-upgrade')
    hookenv.log('set upgrade needed')
    if previous_channel is None or not require_manual:
        hookenv.log('forcing upgrade')
        set_state('kubernetes-master.upgrade-specified')


@when('config.changed.channel')
def channel_changed():
    set_upgrade_needed()


@hook('upgrade-charm')
def check_for_upgrade_needed():
    '''An upgrade charm event was triggered by Juju, react to that here.'''
    hookenv.status_set('maintenance', 'Checking resources')
    # remove old states
    remove_state('kubernetes.components.installed')
    remove_state('kubernetes.dashboard.available')
    remove_state('kube-dns.available')
    remove_state('kubernetes-master.app_version.set')

    migrate_from_pre_snaps()
    add_rbac_roles()
    set_state('reconfigure.authentication.setup')
    remove_state('authentication.setup')

    resources = ['kubectl', 'kube-apiserver', 'kube-controller-manager',
                 'kube-scheduler', 'cdk-addons']
    paths = [hookenv.resource_get(resource) for resource in resources]
    if any_file_changed(paths):
        set_upgrade_needed()


@when('kubernetes-master.upgrade-needed')
@when_not('kubernetes-master.upgrade-specified')
def upgrade_needed_status():
    msg = 'Needs manual upgrade, run the upgrade action'
    hookenv.status_set('blocked', msg)


@when('kubernetes-master.upgrade-specified')
def do_upgrade():
    hookenv.status_set('maintenance', 'Installing kubectl snap')
    channel = hookenv.config('channel')
    install_snaps(channel)
    set_state('kubernetes-master.snaps.installed')
    remove_state('kubernetes-master.components.started')
    remove_state('kubernetes-master.upgrade-needed')
    remove_state('kubernetes-master.upgrade-specified')


@when('config.changed.client_password', 'leadership.is_leader')
def password_changed():
    """Handle password change via the charms config."""
    password = hookenv.config('client_password')
    if password == "" and is_state('client.password.initialised'):
        # password_changed is called during an upgrade. Nothing to do.
        return
    elif password == "":
        # Password not initialised
        password = token_generator()
    setup_basic_auth(password, "admin", "admin")
    set_state('reconfigure.authentication.setup')
    remove_state('authentication.setup')
    set_state('client.password.initialised')


@when('cni.connected')
@when_not('cni.configured')
def configure_cni(cni):
    ''' Set master configuration on the CNI relation. This lets the CNI
    subordinate know that we're the master so it can respond accordingly. '''
    cni.set_config(is_master=True, kubeconfig_path='')


@when('leadership.is_leader')
@when_not('authentication.setup')
def setup_leader_authentication():
    reconfigure = is_state('reconfigure.authentication.setup')
    hookenv.status_set('maintenance', 'Rendering authentication templates.')
    setup_leader_auth(reconfigure)
    remove_state('reconfigure.authentication.setup')
    remove_state('kubernetes-master.components.started')
    set_state('authentication.setup')


@when_not('leadership.is_leader')
def setup_non_leader_authentication():
    if setup_non_leader_auth(is_state('authentication.setup')):
        hookenv.status_set('maintenance', 'Rendering authentication templates.')
        remove_state('kubernetes-master.components.started')
        set_state('authentication.setup')
    else:
        msg = "Waiting on leaders crypto keys."
        hookenv.status_set('waiting', msg)


@when('kubernetes-master.snaps.installed')
def set_app_version():
    ''' Declare the application version to juju '''
    version = check_output(['kube-apiserver', '--version'])
    hookenv.application_version_set(version.split(b' v')[-1].rstrip())


@when('cdk-addons.configured', 'kube-api-endpoint.available',
      'kube-control.connected')
def idle_status(kube_api, kube_control):
    ''' Signal at the end of the run that we are running. '''
    if not all_kube_system_pods_running():
        hookenv.status_set('waiting', 'Waiting for kube-system pods to start')
    elif hookenv.config('service-cidr') != service_cidr():
        msg = 'WARN: cannot change service-cidr, still using ' + service_cidr()
        hookenv.status_set('active', msg)
    else:
        # All services should be up and running at this point. Double-check...
        failing_services = master_services_down()
        if len(failing_services) == 0:
            hookenv.status_set('active', 'Kubernetes master running.')
        else:
            msg = 'Stopped services: {}'.format(','.join(failing_services))
            hookenv.status_set('blocked', msg)


@when('etcd.available', 'tls_client.server.certificate.saved',
      'authentication.setup')
@when_not('kubernetes-master.components.started')
def start_master(etcd):
    '''Run the Kubernetes master components.'''
    hookenv.status_set('maintenance',
                       'Configuring the Kubernetes master services.')
    freeze_service_cidr(hookenv.config('service-cidr'))
    if not etcd.get_connection_string():
        # etcd is not returning a connection string. This happens when
        # the master unit disconnects from etcd and is ready to terminate.
        # No point in trying to start master services and fail. Just return.
        return

    # TODO: Make sure below relation is handled on change
    # https://github.com/kubernetes/kubernetes/issues/43461
    handle_etcd_relation(etcd)

    # Add CLI options to all components
    privileged = is_privileged()
    if privileged:
        set_state('kubernetes-master.privileged')
    else:
        remove_state('kubernetes-master.privileged')

    extra_args = hookenv.config().get('api-extra-args', '')
    auth_mode = hookenv.config('authorization-mode')
    configure_apiserver(etcd, privileged, auth_mode, extra_args)
    set_state('kube-apiserver.do-restart')
    extra_args = hookenv.config().get('controller-manager-extra-args', '')
    configure_controller_manager(extra_args)
    set_state('kube-controller-manager.do-restart')
    extra_args = hookenv.config().get('scheduler-extra-args', '')
    configure_scheduler(extra_args)
    set_state('kube-scheduler.do-restart')

    hookenv.open_port(6443)


@when('etcd.available')
def etcd_data_change(etcd):
    ''' Etcd scale events block master reconfiguration due to the
        kubernetes-master.components.started state. We need a way to
        handle these events consistenly only when the number of etcd
        units has actually changed '''

    # key off of the connection string
    connection_string = etcd.get_connection_string()

    # If the connection string changes, remove the started state to trigger
    # handling of the master components
    if data_changed('etcd-connect', connection_string):
        remove_state('kubernetes-master.components.started')


@when('kube-control.connected')
@when('cdk-addons.configured')
def send_cluster_dns_detail(kube_control):
    ''' Send cluster DNS info '''
    # Note that the DNS server doesn't necessarily exist at this point. We know
    # where we're going to put it, though, so let's send the info anyway.
    dns_ip = get_dns_ip()
    kube_control.set_dns(53, hookenv.config('dns_domain'), dns_ip)


@when('kube-control.connected')
@when('snap.installed.kubectl')
@when('leadership.is_leader')
def create_service_configs(kube_control):
    if create_configs(kube_control):
        host.service_restart('snap.kube-apiserver.daemon')
        remove_state('authentication.setup')


@when_not('kube-control.connected')
def missing_kube_control():
    """Inform the operator master is waiting for a relation to workers.

    If deploying via bundle this won't happen, but if operator is upgrading a
    a charm in a deployment that pre-dates the kube-control relation, it'll be
    missing.

    """
    hookenv.status_set('blocked', 'Waiting for workers.')


@when('kube-api-endpoint.available')
def push_service_data(kube_api):
    ''' Send configuration to the load balancer, and close access to the
    public interface '''
    kube_api.configure(port=6443)


@when('certificates.available')
def send_data(tls):
    '''Send the data that is required to create a server certificate for
    this server.'''
    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = hookenv.unit_public_ip()

    # Get the SDN gateway based on the cidr address.
    kubernetes_service_ip = get_kubernetes_service_ip()

    domain = hookenv.config('dns_domain')
    # Create SANs that the tls layer will add to the server cert.
    sans = [
        hookenv.unit_public_ip(),
        hookenv.unit_private_ip(),
        socket.gethostname(),
        kubernetes_service_ip,
        'kubernetes',
        'kubernetes.{0}'.format(domain),
        'kubernetes.default',
        'kubernetes.default.svc',
        'kubernetes.default.svc.{0}'.format(domain)
    ]

    # maybe they have extra names they want as SANs
    extra_sans = hookenv.config('extra_sans')
    if extra_sans and not extra_sans == "":
        sans.extend(extra_sans.split())

    # Create a path safe name by removing path characters from the unit name.
    certificate_name = hookenv.local_unit().replace('/', '_')
    # Request a server cert with this information.
    tls.request_server_cert(common_name, sans, certificate_name)


@when('config.changed.extra_sans', 'certificates.available')
def update_certificate(tls):
    # Using the config.changed.extra_sans flag to catch changes.
    # IP changes will take ~5 minutes or so to propagate, but
    # it will update.
    send_data(tls)


@when('certificates.server.cert.available',
      'kubernetes-master.components.started',
      'tls_client.server.certificate.written')
def kick_api_server(tls):
    # need to be idempotent and don't want to kick the api server
    # without need
    if data_changed('cert', tls.get_server_cert()):
        # certificate changed, so restart the api server
        hookenv.log("Certificate information changed, restarting api server")
        set_state('kube-apiserver.do-restart')
    tls_client.reset_certificate_write_flag('server')


@when('kubernetes-master.components.started')
def configure_cdk_addons():
    ''' Configure CDK addons '''
    remove_state('cdk-addons.configured')
    dbEnabled = hookenv.config('enable-dashboard-addons')
    dns_domain= hookenv.config('dns_domain')

    set_addons_args(dbEnabled, dns_domain)
    if not addons_ready():
        hookenv.status_set('waiting', 'Waiting to retry addon deployment')
        remove_state('cdk-addons.configured')
        return

    set_state('cdk-addons.configured')


@when('loadbalancer.available', 'certificates.ca.available',
      'certificates.client.cert.available', 'authentication.setup')
def loadbalancer_kubeconfig(loadbalancer, ca, client):
    # Get the potential list of loadbalancers from the relation object.
    hosts = loadbalancer.get_addresses_ports()
    # Get the public address of loadbalancers so users can access the cluster.
    address = hosts[0].get('public-address')
    # Get the port of the loadbalancer so users can access the cluster.
    port = hosts[0].get('port')
    server = 'https://{0}:{1}'.format(address, port)
    build_kubeconfig(server)


@when('certificates.ca.available', 'certificates.client.cert.available',
      'authentication.setup')
@when_not('loadbalancer.available')
def create_self_config(ca, client):
    '''Create a kubernetes configuration for the master unit.'''
    server = 'https://{0}:{1}'.format(hookenv.unit_get('public-address'), 6443)
    build_kubeconfig(server)


@when('ceph-storage.available')
def ceph_state_control(ceph_admin):
    ''' Determine if we should remove the state that controls the re-render
    and execution of the ceph-relation-changed event because there
    are changes in the relationship data, and we should re-render any
    configs, keys, and/or service pre-reqs '''

    ceph_relation_data = {
        'mon_hosts': ceph_admin.mon_hosts(),
        'fsid': ceph_admin.fsid(),
        'auth_supported': ceph_admin.auth(),
        'hostname': socket.gethostname(),
        'key': ceph_admin.key()
    }

    # Re-execute the rendering if the data has changed.
    if data_changed('ceph-config', ceph_relation_data):
        remove_state('ceph-storage.configured')


@when('ceph-storage.available')
@when_not('ceph-storage.configured')
def ceph_storage(ceph_admin):
    if setup_ceph(ceph_admin):
        set_state('ceph-storage.configured')


@when('nrpe-external-master.available')
@when_not('nrpe-external-master.initial-config')
def initial_nrpe_config(nagios=None):
    set_state('nrpe-external-master.initial-config')
    update_nrpe_config(nagios)


@when('config.changed.authorization-mode',
      'kubernetes-master.components.started')
def switch_auth_mode():
    config = hookenv.config()
    mode = config.get('authorization-mode')
    if data_changed('auth-mode', mode):
        remove_state('kubernetes-master.components.started')


@when('kubernetes-master.components.started')
@when('nrpe-external-master.available')
@when_any('config.changed.nagios_context',
          'config.changed.nagios_servicegroups')
def update_nrpe_config(unused=None):
    services = (
        'snap.kube-apiserver.daemon',
        'snap.kube-controller-manager.daemon',
        'snap.kube-scheduler.daemon'
    )
    hostname = nrpe.get_nagios_hostname()
    current_unit = nrpe.get_nagios_unit_name()
    nrpe_setup = nrpe.NRPE(hostname=hostname)
    nrpe.add_init_service_checks(nrpe_setup, services, current_unit)
    nrpe_setup.write()


@when_not('nrpe-external-master.available')
@when('nrpe-external-master.initial-config')
def remove_nrpe_config(nagios=None):
    remove_state('nrpe-external-master.initial-config')

    # List of systemd services for which the checks will be removed
    services = (
        'snap.kube-apiserver.daemon',
        'snap.kube-controller-manager.daemon',
        'snap.kube-scheduler.daemon'
    )

    # The current nrpe-external-master interface doesn't handle a lot of logic,
    # use the charm-helpers code for now.
    hostname = nrpe.get_nagios_hostname()
    nrpe_setup = nrpe.NRPE(hostname=hostname)

    for service in services:
        nrpe_setup.remove_check(shortname=service)


def is_privileged():
    """Return boolean indicating whether or not to set allow-privileged=true.

    """
    privileged = hookenv.config('allow-privileged')
    if privileged == 'auto':
        return is_state('kubernetes-master.gpu.enabled')
    else:
        return privileged == 'true'


@when('config.changed.allow-privileged')
@when('kubernetes-master.components.started')
def on_config_allow_privileged_change():
    """React to changed 'allow-privileged' config value.

    """
    remove_state('kubernetes-master.components.started')
    remove_state('config.changed.allow-privileged')


@when('config.changed.api-extra-args')
@when('kubernetes-master.components.started')
@when('etcd.available')
def on_config_api_extra_args_change(etcd):
    privileged = is_privileged()
    if privileged:
        set_state('kubernetes-master.privileged')
    else:
        remove_state('kubernetes-master.privileged')
    extra_args = hookenv.config().get('api-extra-args', '')
    auth_mode = hookenv.config('authorization-mode')
    configure_apiserver(etcd, privileged, auth_mode, extra_args)
    set_state('kube-apiserver.do-restart')



@when('config.changed.controller-manager-extra-args')
@when('kubernetes-master.components.started')
def on_config_controller_manager_extra_args_change():
    extra_args = hookenv.config().get('controller-manager-extra-args', '')
    configure_controller_manager(extra_args)
    set_state('kube-controller-manager.do-restart')


@when('config.changed.scheduler-extra-args')
@when('kubernetes-master.components.started')
def on_config_scheduler_extra_args_change():
    extra_args = hookenv.config().get('scheduler-extra-args', '')
    configure_scheduler(extra_args)
    set_state('kube-scheduler.do-restart')


@when('kube-control.gpu.available')
@when('kubernetes-master.components.started')
@when_not('kubernetes-master.gpu.enabled')
def on_gpu_available(kube_control):
    """The remote side (kubernetes-worker) is gpu-enabled.

    We need to run in privileged mode.

    """
    config = hookenv.config()
    if config['allow-privileged'] == "false":
        hookenv.status_set(
            'active',
            'GPUs available. Set allow-privileged="auto" to enable.'
        )
        return

    remove_state('kubernetes-master.components.started')
    set_state('kubernetes-master.gpu.enabled')


@when('kubernetes-master.gpu.enabled')
@when_not('kubernetes-master.privileged')
def disable_gpu_mode():
    """We were in gpu mode, but the operator has set allow-privileged="false",
    so we can't run in gpu mode anymore.

    """
    remove_state('kubernetes-master.gpu.enabled')


@hook('stop')
def shutdown():
    """ Stop the kubernetes master services

    """
    service_stop('snap.kube-apiserver.daemon')
    service_stop('snap.kube-controller-manager.daemon')
    service_stop('snap.kube-scheduler.daemon')


@when('kube-apiserver.do-restart')
def restart_apiserver():
    prev_state, prev_msg = hookenv.status_get()
    hookenv.status_set('maintenance', 'Restarting kube-apiserver')
    host.service_restart('snap.kube-apiserver.daemon')
    hookenv.status_set(prev_state, prev_msg)
    remove_state('kube-apiserver.do-restart')
    set_state('kube-apiserver.started')


@when('kube-controller-manager.do-restart')
def restart_controller_manager():
    prev_state, prev_msg = hookenv.status_get()
    hookenv.status_set('maintenance', 'Restarting kube-controller-manager')
    host.service_restart('snap.kube-controller-manager.daemon')
    hookenv.status_set(prev_state, prev_msg)
    remove_state('kube-controller-manager.do-restart')
    set_state('kube-controller-manager.started')


@when('kube-scheduler.do-restart')
def restart_scheduler():
    prev_state, prev_msg = hookenv.status_get()
    hookenv.status_set('maintenance', 'Restarting kube-scheduler')
    host.service_restart('snap.kube-scheduler.daemon')
    hookenv.status_set(prev_state, prev_msg)
    remove_state('kube-scheduler.do-restart')
    set_state('kube-scheduler.started')


@when_all('kube-apiserver.started',
          'kube-controller-manager.started',
          'kube-scheduler.started')
@when_not('kubernetes-master.components.started')
def componenets_started():
    set_state('kubernetes-master.components.started')
