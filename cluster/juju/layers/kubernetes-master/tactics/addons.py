import subprocess
from charmtools.build.tactics import Tactic

class AddonsTactic(Tactic):
    @classmethod
    def trigger(cls, relpath):
        return relpath == "templates/addons"

    def __call__(self):
        subprocess.check_call("build/update-addons")
