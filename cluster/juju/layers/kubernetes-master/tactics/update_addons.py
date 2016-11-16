import shutil
import subprocess
from charmtools.build.tactics import Tactic

class UpdateAddonsTactic(Tactic):
    @classmethod
    def trigger(cls, relpath):
        return relpath == "build"

    def __call__(self):
        subprocess.check_call("build/update-addons")
        dest = self.target.directory + "/templates/addons"
        shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree("build/addons", dest)
