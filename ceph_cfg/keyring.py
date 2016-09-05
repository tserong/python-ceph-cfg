# Import Python Libs
from __future__ import absolute_import
import logging
import os
import shutil
import tempfile
import os.path

# Local imports
from . import utils
from . import constants
from . import util_which


KEYRINGS = {
    "admin": {
        "path": "/etc/ceph/%s.client.admin.keyring",
        "name": "client.admin",
        "caps": { "mon": "allow *", "osd": "allow *", "mds": "allow *" },
    },
    "mon": {
        "path": os.path.join(constants._path_ceph_lib, "bootstrap-mon/%s.keyring"),
        "name": "mon.",
        "caps": { "mon": "allow *" },
    },
    "osd": {
        "path": os.path.join(constants._path_ceph_lib, "bootstrap-osd/%s.keyring"),
        "name": "client.bootstrap-osd",
        "caps": { "mon": "allow profile bootstrap-osd" },
    },
    "mds": {
        "path": os.path.join(constants._path_ceph_lib, "bootstrap-mds/%s.keyring"),
        "name": "client.bootstrap-mds",
        "caps": { "mon": "allow profile bootstrap-mds" },
    },
    "rgw": {
        "path": os.path.join(constants._path_ceph_lib, "bootstrap-rgw/%s.keyring"),
        "name": "client.bootstrap-rgw",
        "caps": { "mon": "allow profile bootstrap-rgw" },
    },
}

log = logging.getLogger(__name__)

class Error(Exception):
    """
    Error
    """

    def __str__(self):
        doc = self.__doc__.strip()
        return ': '.join([doc] + [str(a) for a in self.args])

def _keyring_read(key_path):
    output = ""
    with open(key_path, 'r') as infile:
        output = infile.read()
    return output

def _keyring_write(key_path,content):
    dirname = os.path.dirname(key_path)
    if not os.path.isdir(dirname):
        os.makedirs(dirname)
    with open(key_path, 'w') as infile:
        for line in content.split('\n'):
            stripped = line.strip()
            if len(stripped) == 0:
                continue
            if stripped[0] == '[':
                infile.write('%s\n' % (stripped))
                continue
            infile.write('\t%s\n' % (stripped))
    return


class keyring_facard(object):
    key_type = None

    def __init__(self, mdl):
        self.model = mdl

    def invoke_ceph_authtool(self, keyring_name, keyring_path, caps, secret=None, extra_args=[]):
        """create arguments for invoking the ceph authtool, this simplifies most of
        the ways that ceph authtool could be invoked.

        Args:
            keyring_name: The name of keyring to be created
            keyring_path: path where keyring is to be created
            caps: A dictionary containing various k-v pairs of components and their respective auth
                  permission eg:
                  {'mon':'allow *'}
            secret: The base64 secret to create keyring from, if this is set we will use this secret
                    instead to create the keyring, otherwise authtool itself will generate one
            extra_args: any other extra arguments to be passed to ceph authtool"""

        args=[
            util_which.which_ceph_authtool.path,
            "-n", keyring_name,
            "--create-keyring", keyring_path
            ]

        if secret:
            args += ["--add-key", secret.strip()]
        else:
            args.append("--gen-key")

        args += extra_args

        for component,permission in caps.items():
            args += ["--cap", component, permission]
        return args


    def get_arguments_create(self, path, secret=None):
        extra_args=[]
        # Not sure why this special case is necessary for the admin key
        if self.key_type == "admin":
            if self.model.ceph_version.major == 0:
                if self.model.ceph_version.minor < 95:
                    extra_args+=["--set-uid=0"]
        return self.invoke_ceph_authtool(self.keyring_identity_get(), path, KEYRINGS[self.key_type]["caps"], secret=secret, extra_args=extra_args)


    def present(self):
        """
        Check if keyring is present
        """
        return os.path.isfile(self.keyring_path_get())


    def create(self, secret = None):
        """
        Create keyring
        """
        if self.present():
            return _keyring_read(self.keyring_path_get())
        try:
            tmpd = tempfile.mkdtemp()
            key_path = os.path.join(tmpd,"keyring")
            arguments = self.get_arguments_create(key_path, secret)
            cmd_out = utils.execute_local_command(arguments)
            if cmd_out["retcode"] != 0:
                raise Error("Failed executing '%s' Error rc=%s, stdout=%s stderr=%s" % (
                    " ".join(arguments),
                    cmd_out["retcode"],
                    cmd_out["stdout"],
                    cmd_out["stderr"])
                    )
            output = _keyring_read(key_path)
        finally:
            shutil.rmtree(tmpd)
        return output


    def write_content(self, key_content):
        """
        Persist keyring
        """
        if self.present():
            return True
        _keyring_write(self.keyring_path_get(), key_content)
        return True


    def write_secret(self, secret):
        """
        Persist keyring
        """
        if os.path.isfile(self.keyring_path_get()):
            return True
        if secret is None:
            raise Error("Keyring secret is invalid")
        keyring_dir = os.path.dirname(self.keyring_path_get())
        if not os.path.isdir(keyring_dir):
            os.makedirs(keyring_dir)
        arguments = self.get_arguments_create(self.keyring_path_get(), secret)
        cmd_out = utils.execute_local_command(arguments)
        if cmd_out["retcode"] != 0:
            raise Error("Failed executing '%s' Error rc=%s, stdout=%s stderr=%s" % (
                " ".join(arguments),
                cmd_out["retcode"],
                cmd_out["stdout"],
                cmd_out["stderr"])
                )
        return True


    def remove(self):
        """
        Remove keyring
        """
        if self.present():
            log.info("Removing: %s" % (self.keyring_path_get()))
            try:
                os.remove(self.keyring_path_get())
            except OSError:
                raise Error("Keyring could not be deleted")
        return True


    def keyring_path_get(self):
        """
        Get keyring path
        """
        return KEYRINGS[self.key_type]["path"] % self.model.cluster_name


    def keyring_identity_get(self):
        """
        Get keyring name
        """
        return KEYRINGS[self.key_type]["name"]

