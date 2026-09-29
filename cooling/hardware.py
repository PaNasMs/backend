import json
import subprocess
import time
from pathlib import Path

PWM_PINS = {12: (0, 'a0'), 13: (1, 'a0'), 18: (2, 'a3'), 19: (3, 'a3')}
MARKER = Path('/run/panasms-cooling/hardware.json')


def normalize(config):
    result = dict(config)
    result.setdefault('hardwareMode', 'external-pwm')
    result.setdefault('controlGPIO', 18 if result['hardwareMode'] == 'internal-pwm' else 27)
    result.setdefault('tachGPIO', 24 if result['hardwareMode'] == 'internal-pwm' else None)
    return result


def validate(config):
    mode = config['hardwareMode']
    if mode not in ('none', 'external-pwm', 'internal-pwm'):
        raise ValueError('Unknown cooling hardware mode')
    if mode == 'none':
        return
    pin, tach = config['controlGPIO'], config['tachGPIO']
    if type(pin) is not int or not 2 <= pin <= 27:
        raise ValueError('Control GPIO must be a BCM GPIO between 2 and 27')
    if mode == 'internal-pwm' and pin not in PWM_PINS:
        raise ValueError('Hardware PWM requires GPIO12, GPIO13, GPIO18 or GPIO19 on Raspberry Pi 5')
    if tach is not None and (type(tach) is not int or not 2 <= tach <= 27 or tach == pin):
        raise ValueError('Tachometer GPIO must be distinct from control GPIO, between 2 and 27')


def tach_pulses(events):
    return sum(event.event_type.name == 'FALLING_EDGE' for event in events)


def signature(config):
    return {key: config[key] for key in ('hardwareMode', 'controlGPIO', 'tachGPIO')}


def gpio_chip():
    import gpiod
    if 'Raspberry Pi 5' not in Path('/proc/device-tree/model').read_text():
        raise ValueError('GPIO cooling currently supports Raspberry Pi 5 only')
    for path in sorted(Path('/dev').glob('gpiochip[0-9]*')):
        with gpiod.Chip(str(path)) as chip:
            if chip.get_info().label == 'pinctrl-rp1':
                return str(path)
    raise ValueError('RP1 GPIO controller is unavailable')


def pwm_chip():
    def find():
        return next((p for p in Path('/sys/class/pwm').glob('pwmchip*')
                     if p.resolve().parent.parent.name == '1f00098000.pwm'), None)
    chip = find()
    if chip is None:
        target = Path('/run/panasms-cooling/pwm-enable.dtbo')
        subprocess.run(['dtc', '-@', '-I', 'dts', '-O', 'dtb', '-o', str(target),
                        str(Path(__file__).with_name('pwm-enable.dts'))], check=True, capture_output=True, timeout=5)
        subprocess.run(['dtoverlay', str(target)], check=True, capture_output=True, timeout=5)
        chip = find()
    if chip is None:
        raise ValueError('RP1 PWM0 controller is unavailable')
    return chip


def failsafe():
    if not MARKER.exists():
        return
    data = json.loads(MARKER.read_text())
    pin = data['controlGPIO']
    validate(data)
    if data['hardwareMode'] != 'none':
        subprocess.run(['pinctrl', 'set', str(pin), 'op', 'dh'], check=True, timeout=5)
    if data['hardwareMode'] == 'internal-pwm':
        chip = pwm_chip()
        channel = PWM_PINS[pin][0]
        path = chip / f'pwm{channel}'
        if path.exists():
            (path / 'enable').write_text('0')
            (chip / 'unexport').write_text(str(channel))
    MARKER.unlink(missing_ok=True)


class Hardware:
    def __init__(self, config):
        validate(config)
        self.config = signature(config)
        self.request = None
        self.pwm = None
        self.chip = None
        self.rpm = None
        self.pulses = 0
        self.rpm_since = time.monotonic()
        self.actual = None
        self.mode = config['hardwareMode']
        self.pin = config['controlGPIO']
        self.tach = config['tachGPIO']
        if self.mode == 'none':
            return
        import gpiod
        from gpiod.line import Direction, Value, Bias, Edge
        chip_path = gpio_chip()
        pins = [self.pin] + ([self.tach] if self.tach is not None else [])
        with gpiod.Chip(chip_path) as chip:
            for pin in pins:
                line = chip.get_line_info(pin)
                if line.used:
                    raise ValueError(f'GPIO{pin} is used by {line.consumer or "another device"}')
                state = subprocess.run(['pinctrl', 'get', str(pin)], check=True, capture_output=True, text=True, timeout=5).stdout
                if any(f' a{i} ' in state for i in range(9)):
                    raise ValueError(f'GPIO{pin} is assigned to a peripheral')
        if self.mode == 'internal-pwm':
            self.chip = pwm_chip()
            self.channel, self.function = PWM_PINS[self.pin]
            path = self.chip / f'pwm{self.channel}'
            if path.exists():
                raise ValueError(f'PWM channel {self.channel} is already in use')
        settings = {self.pin: gpiod.LineSettings(direction=Direction.OUTPUT, output_value=Value.ACTIVE)}
        if self.tach is not None:
            # RP1 single-edge mode can report opposite transitions; classify both edges instead.
            settings[self.tach] = gpiod.LineSettings(direction=Direction.INPUT, bias=Bias.PULL_UP, edge_detection=Edge.BOTH)
        self.request = gpiod.request_lines(chip_path, consumer='panasms-cooling', config=settings)
        try:
            MARKER.write_text(json.dumps(self.config))
            if self.mode == 'internal-pwm':
                (self.chip / 'export').write_text(str(self.channel))
                self.pwm = path
                (path / 'period').write_text('40000')
                (path / 'duty_cycle').write_text('40000')
                (path / 'enable').write_text('1')
                subprocess.run(['pinctrl', 'set', str(self.pin), self.function], check=True, timeout=5)
        except Exception:
            self.close()
            raise

    def tick(self, actual, stopped):
        from gpiod.line import Value
        if self.mode == 'none':
            stopped.wait(0.025)
            return
        if self.mode == 'internal-pwm':
            if actual != self.actual:
                (self.pwm / 'duty_cycle').write_text(str(round(actual * 40000)))
            stopped.wait(0.025)
        else:
            self.request.set_value(self.pin, Value.ACTIVE if actual else Value.INACTIVE)
            if actual in (0, 1):
                stopped.wait(0.025)
            else:
                stopped.wait(0.025 * actual)
                self.request.set_value(self.pin, Value.INACTIVE)
                stopped.wait(0.025 * (1 - actual))
        self.actual = actual
        if self.tach is not None:
            while self.request.wait_edge_events(0):
                self.pulses += tach_pulses(self.request.read_edge_events())
            elapsed = time.monotonic() - self.rpm_since
            if elapsed >= 2:
                self.rpm = round(self.pulses * 30 / elapsed)
                self.pulses = 0
                self.rpm_since = time.monotonic()

    def close(self):
        if self.request is not None:
            try:
                failsafe()
            finally:
                self.request.release()
                self.request = None
