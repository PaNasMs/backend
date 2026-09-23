#!/usr/bin/python3
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time

CONFIG = Path('/etc/panasms-cooling/config.json')
STATUS = Path('/run/panasms-cooling/status.json')
CPU_PROFILES={'quiet':(50000,60000,67500,75000),'balanced':(45000,55000,64000,70000),'performance':(40000,50000,60000,65000)}
STARTUP_SECONDS = 120
STARTUP_RETRY_SECONDS = 5

PROFILES = {'quiet': (40, 45, 50), 'balanced': (35, 40, 45), 'performance': (30, 35, 40)}


def apply_cpu_profile(profile, root=Path('/sys/class/thermal/thermal_zone0')):
    if profile not in CPU_PROFILES: raise ValueError('Unknown CPU profile')
    if (root/'type').read_text().strip()!='cpu-thermal': raise ValueError('Unknown thermal zone')
    paths=[root/f'trip_point_{i}_temp' for i in range(1,5)]
    if any((root/f'trip_point_{i}_type').read_text().strip()!='active' for i in range(1,5)):
        raise ValueError('Unexpected cooling trip mapping')
    original=[p.read_text() for p in paths]
    try:
        for p,value in zip(paths,CPU_PROFILES[profile]): p.write_text(str(value))
    except OSError:
        for p,value in zip(paths,original): p.write_text(value)
        raise
    return {'available':True,'profile':profile,'thresholds':list(CPU_PROFILES[profile])}


def duty(profile, disks, sensor_temperature):
    if not disks or any(d['state'] in ('unknown','unavailable') for d in disks):
        return 1.0, 'sensor-unavailable'
    if sensor_temperature is None or sensor_temperature >= 70:
        return 1.0, 'system-temperature'
    if all(d['state'] == 'sleeping' for d in disks):
        return (0.0, 'all-disks-sleeping') if sensor_temperature < 65 else (0.5, 'system-temperature')
    temperatures = [d['temperature'] for d in disks if d['state'] == 'active']
    if any(t is None for t in temperatures):
        return 1.0, 'sensor-unavailable'
    temp = max(temperatures)
    if temp < 30 and sensor_temperature < 65:
        return 0.0, 'disks-cool'
    a, b, c = PROFILES[profile]
    return (0.25 if temp < a else 0.5 if temp < b else 0.75 if temp < c else 1.0), 'automatic'


def control_target(profile, disks, sensor_temperature, starting, elapsed, stale=False, invalid=False):
    target, reason = duty(profile, disks, sensor_temperature)
    hot = any(d.get('temperature') is not None and d['temperature'] >= PROFILES[profile][2]
              for d in disks if d['state'] == 'active')
    if invalid or (sensor_temperature is not None and sensor_temperature >= 70) or hot:
        return 1.0, 'stale-or-invalid-data' if invalid else 'system-temperature' if not hot else 'automatic'
    if starting and elapsed < STARTUP_SECONDS and reason == 'sensor-unavailable':
        return 0.5, 'initializing-sensors'
    if stale:
        return 1.0, 'stale-or-invalid-data'
    return target, reason


def disk_read(path):
    try:
        p = subprocess.run(['/usr/sbin/smartctl', '-n', 'standby,3,5', '-d', 'ata', '-H', '-A', '-j', path], capture_output=True, text=True, timeout=10)
        if p.returncode == 3:
            data = json.loads(p.stdout)
            # Exit 3 alone can also mean a command error; require the explicit power mode.
            messages = ' '.join(x.get('string', '') for x in data.get('smartctl', {}).get('messages', []))
            if any(mode in messages.upper() for mode in ('STANDBY', 'SLEEP')):
                return {'path': path, 'state': 'sleeping', 'temperature': None}
            raise ValueError('SMART command exited 3 without standby confirmation')
        if p.returncode & 7:
            raise ValueError(f'SMART command failed (exit {p.returncode})')
        data = json.loads(p.stdout)
        temp = data.get('temperature', {}).get('current')
        if temp is None:
            temp = next((x['raw']['value'] for x in data.get('ata_smart_attributes', {}).get('table', []) if x['id'] == 194), None)
        if not isinstance(temp, (int, float)) or not 0 <= temp <= 100:
            raise ValueError('temperature unavailable')
        attributes=data.get('ata_smart_attributes',{}).get('table',[])
        warnings=[]
        for attribute in attributes:
            if attribute.get('id') in (5,187,188,197,198,199) and attribute.get('raw',{}).get('value',0)>0:
                warnings.append(attribute.get('name',str(attribute['id'])))
        if p.returncode & 0xF0: warnings.append('SMART reports attribute or error-log warnings')
        passed=data.get('smart_status',{}).get('passed')
        health='failed' if passed is False or p.returncode & 8 else 'warning' if warnings else 'passed' if passed is True else 'unknown'
        return {'path':path,'state':'active','temperature':temp,'health':health,'warnings':warnings,'attributes':attributes,
                'powerOnHours':data.get('power_on_time',{}).get('hours'),'observedAt':time.time(),'stale':False}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        return {'path': path, 'state': 'unknown', 'temperature': None, 'error': str(error)}


def system_temperature():
    readings = []
    for hw in Path('/sys/class/hwmon').glob('hwmon*'):
        try:
            if (hw/'name').read_text().strip() in ('cpu_thermal', 'rp1_adc'):
                readings.append(int((hw/'temp1_input').read_text())/1000)
        except (OSError, ValueError):
            continue
    return max(readings) if readings else None


def notify(message):
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect('\0'+address[1:] if address.startswith('@') else address)
            s.sendall(message.encode())


def main():
    import gpiod
    from gpiod.line import Direction, Value
    config = json.loads(CONFIG.read_text())
    with gpiod.Chip('/dev/gpiochip0') as chip:
        if chip.get_info().label != 'pinctrl-rp1' or chip.get_line_info(27).name != 'GPIO27':
            raise RuntimeError('Unrecognized GPIO mapping; refusing control')
    request = gpiod.request_lines('/dev/gpiochip0', consumer='panasms-cooling', config={27:gpiod.LineSettings(direction=Direction.OUTPUT, output_value=Value.ACTIVE)})
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    started = time.monotonic()
    shared = {'disks': [], 'sampled': 0.0, 'initialized': False}
    lock = threading.Lock()

    cached={}
    errors={}
    def sample():
        while not stopped.is_set():
            paths=set(config['disks'])
            paths.update(str(path) for path in Path('/dev/disk/by-id').glob('ata-*') if '-part' not in path.name)
            disks=[]
            for path in sorted(paths):
                row=disk_read(path)
                if row['state']=='active': cached[path]=row.copy()
                elif path in cached:
                    row={**cached[path],**row,'temperature':cached[path]['temperature'],'stale':True}
                else: row.update(health='unknown',warnings=[],attributes=[],observedAt=None,stale=True)
                row['device']=str(Path(path).resolve())
                if not Path(path).exists():
                    row.update(state='unavailable', error='Device path is not available')
                error = row.get('error') if row['state'] in ('unknown', 'unavailable') else None
                if errors.get(path) != error:
                    print(f"Cooling sensor {path}: {error or 'recovered'}", flush=True)
                    errors[path] = error
                disks.append(row)
            with lock:
                required = [d for d in disks if d['path'] in config['disks']]
                ready = bool(required) and all(d['state'] in ('active', 'sleeping') for d in required)
                shared.update(disks=disks, sampled=time.monotonic(), initialized=shared['initialized'] or ready)
                initialized = shared['initialized']
            retry = not initialized and time.monotonic()-started < STARTUP_SECONDS
            stopped.wait(STARTUP_RETRY_SECONDS if retry else config['sampleSeconds'])

    threading.Thread(target=sample, daemon=True).start()
    duty_value = 0.5
    last_update = 0
    lower_since = None
    previous_target = None
    kick_until = 0
    cpu_applied=None
    cpu_status={'available':False}
    notify('READY=1')
    try:
        while not stopped.is_set():
            now = time.monotonic()
            if now-last_update >= 1:
                last_update = now
                config_error = False
                try:
                    new = json.loads(CONFIG.read_text())
                    if new['profile'] not in PROFILES or not 30 <= new['sampleSeconds'] <= 600 or new['disks'] != config['disks']:
                        raise ValueError('invalid config')
                    config = new
                except (OSError, ValueError, KeyError, TypeError):
                    config_error = True
                cpu_profile=config.get('cpuProfile','balanced')
                try:
                    if cpu_profile != cpu_applied:
                        cpu_status=apply_cpu_profile(cpu_profile)
                        cpu_applied=cpu_profile
                except (OSError,ValueError):
                    cpu_status={'available':False,'profile':cpu_profile,'error':'Cannot apply kernel thermal thresholds'}
                with lock:
                    disks, sampled = shared['disks'], shared['sampled']
                    initialized = shared['initialized']
                target, reason = control_target(
                    config['profile'], [d for d in disks if d['path'] in config['disks']],
                    system_temperature(), not initialized, now-started,
                    stale=now-sampled > config['sampleSeconds']+60, invalid=config_error)
                if target < duty_value:
                    if previous_target != target:
                        lower_since = now
                    if lower_since is not None and now-lower_since >= 20:
                        duty_value = target
                else:
                    if duty_value == 0 and target > 0:
                        kick_until = now+2
                    duty_value = target
                    lower_since = None
                previous_target = target
                actual = 1.0 if now < kick_until else duty_value
                status = {'profile':config['profile'], 'sampleSeconds':config['sampleSeconds'], 'dutyPercent':round(actual*100), 'reason':reason,
                          'disks':disks, 'observedAt':time.time(), 'sampleAgeSeconds':round(now-sampled) if sampled else None,
                          'controller':'GPIO27 / MOSFET / 40 Hz', 'rpm':None,'cpu':cpu_status}
                tmp = STATUS.with_suffix('.tmp'); tmp.write_text(json.dumps(status)); os.chmod(tmp,0o644); tmp.replace(STATUS)
                notify('WATCHDOG=1')
            actual = 1.0 if now < kick_until else duty_value
            request.set_value(27, Value.ACTIVE if actual else Value.INACTIVE)
            if actual in (0.0, 1.0):
                stopped.wait(0.025)
            else:
                stopped.wait(0.025*actual)
                request.set_value(27, Value.INACTIVE)
                stopped.wait(0.025*(1-actual))
    finally:
        request.set_value(27, Value.ACTIVE)
        request.release()


if __name__ == '__main__':
    main()
