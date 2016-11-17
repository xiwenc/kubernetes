#!/usr/bin/python2

description = """
Update addon manifests for the charm.

This will clone the kubernetes repo and place the addons in
<charm>/templates/addons.

Can be run with no arguments and from any folder.
"""

import argparse
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager

import charmtools.utils
from charmtools.build.tactics import Tactic

def sh(cmd):
    """ Alias for subprocess calls """
    subprocess.check_call(cmd.split())

def clean_addon_dir(addon_dir):
    """ Remove and recreate the addons folder """
    print("Cleaning " + addon_dir)
    shutil.rmtree(addon_dir, ignore_errors=True)
    os.makedirs(addon_dir)

@contextmanager
def kubernetes_repo():
    """ Shallow clone kubernetes repo and clean up when we are done """
    print("Cloning https://github.com/kubernetes/kubernetes.git")
    path = tempfile.mkdtemp(prefix="kubernetes")
    try:
        sh("git clone --depth 1 https://github.com/kubernetes/kubernetes.git " + path)
        yield path
    finally:
        shutil.rmtree(path)

def add_addon(source, dest):
    """ Add an addon manifest from the given source.

    Any occurrences of 'amd64' are replaced with '{{ arch }}' so the charm can
    fill it in during deployment. """
    if os.path.isdir(dest):
        dest = os.path.join(dest, os.path.basename(source))
    print("'%s' -> '%s'" % (source, dest))
    with open(source, "r") as f:
        content = f.read()
    content = content.replace("amd64", "{{ arch }}")
    with open(dest, "w") as f:
        f.write(content)

def update_addons(dest):
    """ Update addons. This will clean the addons folder and add new manifests
    from upstream. """
    clean_addon_dir(dest)
    with kubernetes_repo() as repo:
        add_addon(repo + "/cluster/addons/dashboard/dashboard-controller.yaml", dest)
        add_addon(repo + "/cluster/addons/dashboard/dashboard-service.yaml", dest)
        add_addon(repo + "/cluster/addons/dns/skydns-rc.yaml.in", dest + "/kubedns-rc.yaml")
        add_addon(repo + "/cluster/addons/dns/skydns-svc.yaml.in", dest + "/kubedns-svc.yaml")
        add_addon(repo + "/cluster/addons/cluster-monitoring/influxdb/grafana-service.yaml", dest)
        add_addon(repo + "/cluster/addons/cluster-monitoring/influxdb/heapster-controller.yaml", dest)
        add_addon(repo + "/cluster/addons/cluster-monitoring/influxdb/heapster-service.yaml", dest)
        add_addon(repo + "/cluster/addons/cluster-monitoring/influxdb/influxdb-grafana-controller.yaml", dest)
        add_addon(repo + "/cluster/addons/cluster-monitoring/influxdb/influxdb-service.yaml", dest)

# Entry points

class UpdateAddonsTactic(Tactic):
    """ This tactic is used by charm-tools to dynamically populate the
    template/addons folder at `charm build` time. """

    @classmethod
    def trigger(cls, relpath):
        """ Determines which files the tactic should apply to. We only want
        this tactic to trigger once, so let's use the templates/ folder
        """
        return relpath == "templates"

    @property
    def dest(self):
        """ The destination we are writing to. This isn't a Tactic thing,
        it's just a helper for UpdateAddonsTactic """
        return self.target / "templates" / "addons"

    def __call__(self):
        """ When the tactic is called, update addons and put them directly in
        our build destination """
        update_addons(self.dest)

    def sign(self):
        """ Return signatures for the charm build manifest. We need to do this
        because the addon template files were added dynamically """
        sigs = {}
        for file in os.listdir(self.dest):
            path = self.dest / file
            relpath = path.relpath(self.target.directory)
            sigs[relpath] = (
                self.current.url,
                "dynamic",
                charmtools.utils.sign(path)
            )
        return sigs

def parse_args():
    """ Parse args. This is solely done for the usage output with -h """
    parser = argparse.ArgumentParser(description=description)
    parser.parse_args()

def main():
    """ Update addons into the layer's templates/addons folder """
    parse_args()
    dest = os.path.abspath(os.path.join(os.path.dirname(__file__), "../templates/addons"))
    update_addons(dest)

if __name__ == "__main__":
    main()
