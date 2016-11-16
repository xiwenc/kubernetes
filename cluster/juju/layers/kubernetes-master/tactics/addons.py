import subprocess
from charmtools.build.tactics import Tactic

class AddonsTactic(Tactic):
    """ Dirty hack tactic to update addon templates before we walk the
    templates/ folder """

    @classmethod
    def trigger(cls, relpath):
        if relpath == "templates":
            subprocess.check_call("build/update-addons")
        return False
