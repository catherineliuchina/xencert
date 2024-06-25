# Copyright (c) 2005-2022 Citrix Systems Inc.
# Copyright (c) 2023 Cloud Software Group, Inc.
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
# *   Redistributions of source code must retain the above
#     copyright notice, this list of conditions and the
#     following disclaimer.
# *   Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the
#     following disclaimer in the documentation and/or other
#     materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import XenAPI
import time, os
import syslog
import paramiko
import xml.dom.minidom
import errno
import glob

IORETRY_MAX = 20 
DEFAULT_NFSVERSION = '3'
LOG_INFO = syslog.LOG_INFO
_SM_SYSLOG_FACILITY = syslog.LOG_LOCAL2
NO_LOGGING_STAMPFILE = '/etc/xensource/no_sm_log'
LOGGING = not (os.path.exists(NO_LOGGING_STAMPFILE))
SHOWMOUNT_BIN = "/usr/sbin/showmount"
IORETRY_PERIOD = 1.0  # seconds
CMD_DD = "/bin/dd"
NFS_SERVICE_RETRY = 6
NFS_SERVICE_WAIT = 30
RPCINFO_BIN = "/usr/sbin/rpcinfo"


def get_xapi_session(ip, username, password):
    """Login to Xapi locally. This will only work if this script is being run 
    on Dom0. For this, no credentials are required. Wait until session connected successfully."""
    for i in range(10):
        if i > 0:
            time.sleep(15)
        try:
            session = XenAPI.Session(f"http://{ip}/")
            session.xenapi.login_with_password(username, password)
            return session
        except Exception as e:
            log.debug("Get xapi session error: '%s', retry: %d" % (e, i))
    else:
        raise e
    
def get_ssh_client(ip, username, password, port=22):
    for i in range(10):
        if i > 0:
            time.sleep(15)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port, username, password)
            return client
        except Exception as e:
            log.debug("Get ssh session error: '%s', retry: %d" % (e, i))
    else:
        raise e    

def get_xapi_version(session):
    pass

def get_certkit_version():
    pass

def execSSH(ssh, cmd, inputtext=None, new_env=None, text=True):
    """Execute a cmdlist, then return its return code, stdout and stderr"""
    env = None
    if new_env:
        env = dict(os.environ)
        env.update(new_env)

    _, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
    rc = stdout.channel.recv_exit_status()
    
    return rc, stdout, stderr
    
def get_ssh_output(ssh, cmd, new_env=None, text=True):
    _, stdout, stderr = execSSH(ssh, cmd, new_env=None, text=True)
    result = stdout if stdout else stderr
    return result.read().decode('utf-8').strip()

# These are partially tested functions that replicate the behaviour of
# the original pread,pread2 and pread3 functions. Potentially these can
# replace the original ones at some later date.
#
# cmdlist is a list of either single strings or pairs of strings. For
# each pair, the first component is passed to exec while the second is
# written to the logs.
def pread(ssh, cmdlist, close_stdin=False, scramble=None, expect_rc=0,
          quiet=False, new_env=None, text=True):
    cmdlist_for_exec = []
    cmdlist_for_log = []
    for item in cmdlist:
        if is_string(item):
            cmdlist_for_exec.append(item)
            if scramble:
                if item.find(scramble) != -1:
                    cmdlist_for_log.append("<filtered out>")
                else:
                    cmdlist_for_log.append(item)
            else:
                cmdlist_for_log.append(item)
        else:
            cmdlist_for_exec.append(item[0])
            cmdlist_for_log.append(item[1])

    if not quiet:
        SMlog(cmdlist_for_log)
    (rc, stdout, stderr) = execSSH(ssh, " ".join(cmdlist_for_exec), new_env=new_env, text=text)
    if rc != expect_rc:
        SMlog("FAILED in utils.pread: (rc %d) stdout: '%s', stderr: '%s'" % \
                (rc, stdout, stderr))
        if quiet:
            SMlog("Command was: %s" % cmdlist_for_log)
        if '' == stderr:
            stderr = stdout
        raise CommandException(rc, str(cmdlist), stderr.read().decode('utf-8'))
    if not quiet:
        SMlog("  pread SUCCESS")
    return stdout.read().decode('utf-8')

#Read STDOUT from cmdlist and discard STDERR output
def pread2(ssh, cmdlist, quiet=False, text=True):
    return pread(ssh, cmdlist, quiet=quiet, text=text)

def is_string(value):
    return isinstance(value, str)

def parse_xensource_inventory(ssh, key):
    filename = '/etc/xensource-inventory'
    cmd = f"cat {filename} | grep {key}"
    output = get_ssh_output(ssh, cmd)
    result = output.split("=")[-1].strip().strip("'")
    return result

def get_build_info(ssh):
    output = parse_xensource_inventory(ssh, "BUILD_NUMBER")
    build = output.split("'")
    if 'stream'in output:
        version = parse_xensource_inventory(ssh, "PRODUCT_VERSION=")
        build.append(version)
    return " ".join(build)

def getrootdev(ssh):
    return parse_xensource_inventory(ssh, "PRIMARY_DISK")

def get_this_host(ssh):
    return parse_xensource_inventory(ssh, "INSTALLATION_UUID")

def get_this_host_ref(session, ssh):
    host_uuid = get_this_host(ssh)
    host_ref = session.xenapi.host.get_by_uuid(host_uuid)
    return host_ref
    
def get_localhost_ref(ssh, session):
    domid = parse_xensource_inventory(ssh, "CONTROL_DOMAIN_UUID")

    if not domid:
        raise xs_errors.XenError('APILocalhost')

    vms = session.xenapi.VM.get_all_records_where('field "uuid" = "%s"' % domid)
    for vm in vms:
        record = vms[vm]
        if record["uuid"] == domid:
            hostid = record["resident_on"]
            return hostid
    raise xs_errors.XenError('APILocalhost')

def makedirs(ssh, path, mode=777):
    head, tail = os.path.split(path)
    if not tail:
        head, tail = os.path.split(head)

    if head and tail and not pathexists(ssh, head):
        makedirs(ssh, head, mode)
        if tail == os.curdir:
            return
    try:
        ssh.exec_command(f"mkdir -m {mode} {path}")
    except OSError as exc:
        if exc.errno == errno.EEXIST and isdir(ssh, path):
            if mode:
                ssh.exec_command(f"chmod {mode} {path}")
            pass
        else:
            raise

def remove(ssh, file):
    execSSH(ssh, f"rm -f {file}")

def rmdir(ssh, dir):
    execSSH(ssh, f"rm -rf {dir}")

def listdir(ssh, path, quiet=False):
    cmd = ["ls", path, "-1", "--color=never"]
    try:
        text = pread2(ssh, cmd, quiet=quiet)[:-1]
        if len(text) == 0:
            return []
        return text.split('\n')
    except CommandException as inst:
        if inst.code == errno.ENOENT:
            raise CommandException(errno.EIO, inst.cmd, inst.reason)
        else:
            raise CommandException(inst.code, inst.cmd, inst.reason)

def pathexists(ssh, path):
    try:
        rc, _, _=ssh.exec_command("test -d {path}")
        return rc == 0
    except OSError as inst:
        if inst.errno == errno.EIO:
            time.sleep(1)
            try:
                listdir(ssh, os.path.realpath(os.path.dirname(path)))
                os.lstat(path)
                return True
            except:
                pass
            raise CommandException(errno.EIO, "os.lstat(%s)" % path, "failed")
        return False
        
def listdir(ssh, path, quiet=False):
    cmd = ["ls", path, "-1", "--color=never"]
    try:
        text = pread2(ssh, cmd, quiet=quiet)[:-1]
        if len(text) == 0:
            return []
        return text.split('\n')
    except CommandException as inst:
        if inst.code == errno.ENOENT:
            raise CommandException(errno.EIO, inst.cmd, inst.reason)
        else:
            raise CommandException(inst.code, inst.cmd, inst.reason)

def pathexists(ssh, path):
    try:
        rc, _, _=ssh.exec_command("test -d {path}")
        return rc == 0
    except OSError as inst:
        if inst.errno == errno.EIO:
            time.sleep(1)
            try:
                listdir(ssh, os.path.realpath(os.path.dirname(path)))
                os.lstat(path)
                return True
            except:
                pass
            raise CommandException(errno.EIO, "os.lstat(%s)" % path, "failed")
        return False

def SMlog(message, ident="SM", priority=LOG_INFO):
    if LOGGING:
        for message_line in str(message).split('\n'):
            _logToSyslog(ident, _SM_SYSLOG_FACILITY, priority, message_line)

def roundup(divisor, value):
    """Retruns the rounded up value so it is divisible by divisor."""

    if value == 0:
        value = 1
    if value % divisor != 0:
        return ((int(value) // divisor) + 1) * divisor
    return value

def statvfs(ssh, path):
    output = get_ssh_output(ssh, f"stat -f {path}")
    result ={}
    for line in output.splitlines():
        if line.startswith('  File:'):
            result['file'] = line.split('"')[1]
        elif line.startswith('    ID:'):
            parts = line.split()
            result['ID'] = parts[1]
            result['Namelen'] = parts[3]
            result['Type'] = parts[5]
        elif line.startswith('Block size:'):
            parts = line.split()
            result['Block size'] = parts[2]
            result['Fundamental block size'] = parts[6]
        elif line.startswith('Blocks:'):
            parts = line.split()
            result['Total blocks'] = parts[2]
            result['Free blocks'] = parts[4]
            result['Available blocks'] = parts[6]
        elif line.startswith('Inodes:'):
            parts = line.split()
            result['Total inodes'] = parts[2]
            result['Free inodes'] = parts[4]
    #print(result)
    return result

def ioretry_stat(ssh, path, maxretry=IORETRY_MAX):
    # this ioretry is similar to the previous method, but
    # stat does not raise an error -- so check its return
    retries = 0
    while retries < maxretry:
        stat = statvfs(ssh, path)
        if stat["Total blocks"] != -1:
            return stat
        time.sleep(1)
        retries += 1
    raise CommandException(errno.EIO, "os.statvfs")

def get_fs_size(ssh, path):
    st = ioretry_stat(ssh, path)
    return int(st["Total blocks"]) * int(st["Fundamental block size"])

def get_fs_utilisation(ssh, path):
    st = ioretry_stat(ssh, path)
    return (int(st["Total blocks"]) - int(st["Free blocks"])) * int(st["Fundamental block size"])

def check_server_service(ssh, server):
    """Ensure NFS service is up and available on the remote server.

    Returns False if fails to detect service after
    NFS_SERVICE_RETRY * NFS_SERVICE_WAIT
    """
    retries = 0
    errlist = [errno.EPERM, errno.EPIPE, errno.EIO]

    while True:
        try:
            services = pread(ssh, [RPCINFO_BIN, "-s", "%s" % server])
            services = services.split("\n")
            for i in range(len(services)):
                if services[i].find("nfs") > 0:
                    return True
        except CommandException as inst:
            if not int(inst.code) in errlist:
                raise

        SMlog("NFS service not ready on server %s" % server)
        retries += 1
        if retries >= NFS_SERVICE_RETRY:
            break

        time.sleep(NFS_SERVICE_WAIT)

    return False

def soft_mount(ssh, mountpoint, remoteserver, remotepath, transport, useroptions='',
               timeout=None, nfsversion=DEFAULT_NFSVERSION, retrans=None):
    """Mount the remote NFS export at 'mountpoint'.

    The 'timeout' param here is in deciseconds (tenths of a second). See
    nfs(5) for details.
    """
    try:
        if not ioretry(lambda: isdir(ssh, mountpoint)):
            ioretry(lambda: makedirs(ssh, mountpoint))
    except CommandException as inst:
        raise NfsException("Failed to make directory: code is %d" %
                           inst.code)

    # Wait for NFS service to be available
    try:
        if not check_server_service(ssh, remoteserver):
            raise CommandException(
                code=errno.EOPNOTSUPP,
                reason='No NFS service on server: `%s`' % remoteserver
            )
    except CommandException as inst:
        raise NfsException("Failed to detect NFS service on server `%s`"
                           % remoteserver)

    mountcommand = 'mount.nfs'

    options = "soft,proto=%s,vers=%s" % (
        transport,
        nfsversion)
    options += ',acdirmin=0,acdirmax=0'

    if timeout is not None:
        options += ",timeo=%s" % timeout
    if retrans is not None:
        options += ",retrans=%s" % retrans
    if useroptions != '':
        options += ",%s" % useroptions

    try:
        if transport in ['tcp6', 'udp6']:
            remoteserver = '[' + remoteserver + ']'
        ioretry(lambda:
                     pread(ssh, [mountcommand, "%s:%s" % (remoteserver, remotepath),mountpoint, "-o", options]),
                     errlist=[errno.EPIPE, errno.EIO],
                     maxretry=2, 
                     nofail=True)
    except CommandException as inst:
        raise NfsException(
            "mount failed on server `%s` with return code %d" % (
                remoteserver, inst.code
            )
        )


def unmount(ssh, mountpoint, rmmountpoint):
    """Unmount the mounted mountpoint"""
    try:
        pread(ssh, ["umount", mountpoint])
    except CommandException as inst:
        raise NfsException("umount failed with return code %d" % inst.code)

    if rmmountpoint:
        try:
            ssh.exec_command(f"rm -f {mountpoint}")
        except OSError as inst:
            raise NfsException("rmdir failed with error '%s'" % inst.strerror)

def SMlog(message, ident="SM", priority=LOG_INFO):
    if LOGGING:
        for message_line in str(message).split('\n'):
            _logToSyslog(ident, _SM_SYSLOG_FACILITY, priority, message_line)

def _logToSyslog(ident, facility, priority, message):
    syslog.openlog(ident, 0, facility)
    syslog.syslog(priority, "[%d] %s" % (os.getpid(), message))
    syslog.closelog()

def is_string(value):
    return isinstance(value, str)

def inject_ssh_key(session, args):
    """Inject Dom0's public SSH key into a guest VM"""
    vm_ref = validate_exists(args, 'vm_ref')
    mip = validate_exists(args, 'mip')
    username = validate_exists(args, 'username')
    password = validate_exists(args, 'password')

    log.debug("Call to Inject Dom0's SSH key into %s" % vm_ref)
    install_ssh_key(session, vm_ref, mip, username, password)
    return json_dumps("OK")
    
def ioretry(f, errlist=[errno.EIO], maxretry=IORETRY_MAX, period=IORETRY_PERIOD, **ignored):
    retries = 0
    while True:
        try:
            return f()
        except OSError as ose:
            err = int(ose.errno)
            if not err in errlist:
                raise CommandException(err, str(f), "OSError")
        except CommandException as ce:
            if not int(ce.code) in errlist:
                raise

        retries += 1
        if retries >= maxretry:
            break

        time.sleep(period)

    raise CommandException(errno.ETIMEDOUT, str(f), "Timeout")

def isdir(ssh, path):
    try:
        rc, _, _ = execSSH(ssh, "test -d {path}}")
        print(rc)
        return rc
    except OSError as inst:
        if inst.errno == errno.EIO:
            raise CommandException(errno.EIO, "os.stat(%s)" % path, "failed")
        return False

def zeroOut(ssh, path, fromByte, bytes):
    """write 'bytes' zeros to 'path' starting from fromByte (inclusive)"""
    blockSize = 4096

    fromBlock = fromByte // blockSize
    if fromByte % blockSize:
        fromBlock += 1
        bytesBefore = fromBlock * blockSize - fromByte
        if bytesBefore > bytes:
            bytesBefore = bytes
        bytes -= bytesBefore
        cmd = [CMD_DD, "if=/dev/zero", "of=%s" % path, "bs=1",
               "seek=%s" % fromByte, "count=%s" % bytesBefore]
        try:
            pread2(ssh, cmd)
        except CommandException:
            return False

    blocks = bytes // blockSize
    bytes -= blocks * blockSize
    fromByte = (fromBlock + blocks) * blockSize
    if blocks:
        cmd = [CMD_DD, "if=/dev/zero", "of=%s" % path, "bs=%s" % blockSize,
               "seek=%s" % fromBlock, "count=%s" % blocks]
        try:
            pread2(ssh, cmd)
        except CommandException:
            return False

    if bytes:
        cmd = [CMD_DD, "if=/dev/zero", "of=%s" % path, "bs=1",
               "seek=%s" % fromByte, "count=%s" % bytes]
        try:
            pread2(ssh, cmd)
        except CommandException:
            return False

    return True

def wait_for_path_multi(path, timeout):
    for i in range(0, timeout):
        paths = glob.glob(path)
        SMlog("_wait_for_paths_multi: paths = %s" % paths)
        if len(paths):
            SMlog("_wait_for_paths_multi: return first path: %s" % paths[0])
            return paths[0]
        time.sleep(1)
    return ""

def get_single_entry(path):
    f = open(path, 'r')
    line = f.readline()
    f.close()
    return line.rstrip()

class XenError(Exception):
    def __new__(self, key, opterr=None):
        # Check the XML definition file exists
        if not os.path.exists(XML_DEFS):
            raise Exception("No XML def file found")

        # Read the definition list
        errorlist = self._fromxml('SM-errorcodes')

        ########DEBUG#######
        #for val in self.errorlist.keys():
        #    subdict = self.errorlist[val]
        #    print "KEY [%s]" % val
        #    for subval in subdict.keys():
        #        print "\tSUBKEY: %s, VALUE: %s" % (subval,subdict[subval])
        ########END#######

        # Now find the specific error
        if key in errorlist:
            subdict = errorlist[key]
            errorcode = int(subdict['value'])
            errormessage = subdict['description']
            if opterr is not None:
                errormessage += " [opterr=%s]" % opterr
            SMlog("Raising exception [%d, %s]" % (errorcode, errormessage))
            return SROSError(errorcode, errormessage)

        # development error
        return SROSError(1, "Error reporting error, unknown key %s" % key)

class SRException(Exception):
    """Exception raised by storage repository operations"""
    errno = errno.EINVAL

    def __init__(self, reason):
        Exception.__init__(self, reason)

    def toxml(self):
        return xmlrpc.client.dumps(xmlrpc.client.Fault(int(self.errno), str(self)), "", True)

    @staticmethod
    def _fromxml(tag):
        dom = xml.dom.minidom.parse(XML_DEFS)
        objectlist = dom.getElementsByTagName(tag)[0]

        errorlist = {}
        for node in objectlist.childNodes:
            taglist = {}
            newval = False
            for n in node.childNodes:
                if n.nodeType == n.ELEMENT_NODE and node.nodeName == 'code':
                    taglist[n.nodeName] = ""
                    for e in n.childNodes:
                        if e.nodeType == e.TEXT_NODE:
                            newval = True
                            taglist[n.nodeName] += e.data
            if newval:
                name = taglist['name']
                errorlist[name] = taglist
        return errorlist

class SROSError(SRException):
    """Wrapper for OSError"""

    def __init__(self, errno, reason):
        self.errno = errno
        Exception.__init__(self, reason)

class SMException(Exception):
    """Base class for all SM exceptions for easier catching & wrapping in 
    XenError"""
    pass

class CommandException(SMException):
    def error_message(self, code):
        if code > 0:
            return os.strerror(code)
        elif code < 0:
            return "Signalled %s" % (abs(code))
        return "Success"

    def __init__(self, code, cmd="", reason='exec failed'):
        self.code = code
        self.cmd = cmd
        self.reason = reason
        Exception.__init__(self, self.error_message(code))