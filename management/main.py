#!/usr/bin/python3
import json
import sys
import pwd
import grp
import os
from common import *
import storage
import accounts
import host
import web_access
import sharing
import module_manager
import module_sources
import module_catalog
import network
import job_control
import job_recovery


def dispatch(mode, user, request):
    account = pwd.getpwnam(user)
    accounts.normal(account)
    admin = grp.getgrnam('sudo').gr_gid in os.getgrouplist(user, account.pw_gid)
    policy = accounts.account_policy.entry(account)
    require(not policy.get('disabled') and policy.get('panel', admin), 'Panel access is disabled')
    require(not accounts.account_policy.expired(accounts.account_policy.shadow(user)) and not accounts.account_policy.password_inactive(accounts.account_policy.shadow(user)), 'Linux account has expired')
    own_files = {'file.mkdir','file.copy','file.move','file.rename','file.trash','file.restore','file.delete'}
    if not admin:
        if mode == 'query':
            require(request.get('view') in ('files','modules','account-sessions','account-details','storage-options'), 'Administrator permissions required')
            if request.get('view') in ('account-sessions','account-details'): request['target'] = user
        else:
            require(request.get('action') in own_files or (request.get('action') == 'user.session.end' and request.get('params',{}).get('target') == user), 'Administrator permissions required')
    if mode == "recover":
        if not admin:
            os.initgroups(user,account.pw_gid);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
        return job_recovery.inspect(request)
    if mode == "query":
        view = request.get("view")
        target = request.get("target", "")
        if view == "web-access": return web_access.query()
        if view == 'accounts': return accounts.query()
        if view == 'account-details': return accounts.query(target)
        if view == 'account-sessions': return accounts.account_sessions.sessions(target)
        if view == "sharing": return sharing.query()
        if view == "share-folders": return sharing.folders(target)
        if view == "home-folders": return accounts.folder_locations.folders(target)
        if view == "mount-folders": return accounts.folder_locations.mount_folders(target)
        if view == "network":
            return network.query()
        if view == "homes-check":
            return accounts.homes.preflight(target)
        if view == "homes":
            return accounts.homes.query()
        if view == "modules":
            result = module_manager.list_modules()
            if not admin: result['installed'] = [m for m in result['installed'] if m['id'] == 'files']
            return result
        if view == "module-sources": return {"sources": module_sources.sources()}
        if view == "module-catalog":
            return module_catalog.list_available()
        extensions = module_manager.load_operations("queries", view)
        if extensions:
            return extensions[0].query(user, target)
        require(view != "files", 'File manager is not installed or is disabled')
        if view in ("storage-options", "raid-candidates", "smart"):
            return storage.query(view, target)
        return host.query(view, target)
    action = request.get("action")
    params = request.get("params")
    require(isinstance(params, dict), 'Parameters must be an object')
    extensions = module_manager.load_operations("actions", action)
    module = next(
        (m for m in (storage, accounts, host, web_access, sharing, network, module_manager, module_catalog, module_sources, *extensions) if action in m.ACTIONS),
        None,
    )
    require(module, 'Unknown operation')
    if mode == "execute":
        job_control.capability(True)
        job_control.checkpoint()
    plan = module.plan(action, params, user) if module != storage else module.plan(action, params)
    if mode == "plan":
        return plan
    require(mode == "execute", 'Unknown mode')
    require(
        request.get("fingerprint") == plan["fingerprint"],
        'State has changed. Review a new operation plan.',
    )
    require(
        request.get("confirmation") == plan["confirmation"], 'The exact operation target was not confirmed'
    )
    job_control.capability(False)
    job_control.checkpoint()
    os.environ["PANASMS_OPERATION"] = "1"
    return (
        module.execute(action, params, user)
        if module != accounts
        else module.execute(action, params)
    )


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, 'Mode or user not specified')
        raw = sys.stdin.read(1048577)
        require(len(raw) <= 1048576, 'Request too large')
        result = dispatch(sys.argv[1], sys.argv[2], json.loads(raw))
    except job_control.Cancelled:
        result = {"cancelled": True}
    except Rejected as e:
        result = {"error": str(e)}
    except subprocess.TimeoutExpired:
        result = {
            "error": 'Operation timed out. Check the actual state before retrying.'
        }
    except Exception:
        result = {
            "error": 'Could not process the operation. Check parameters, object availability and the system journal.'
        }
    print(json.dumps(result, ensure_ascii=False))
