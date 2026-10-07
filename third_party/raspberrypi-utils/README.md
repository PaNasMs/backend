# Raspberry Pi hardware helpers

Unmodified build sources for `pinctrl` and `dtoverlay`, from
https://github.com/raspberrypi/utils at commit
`e0484c848f9c9d1aecc7bd0738930db97bcf18df`.

Only these two executables are packaged, privately under
`/usr/lib/panasms-cooling`. Their internal libraries are linked statically;
`libfdt1` and libc remain normal distribution dependencies. This avoids
requiring the Raspberry Pi OS repository on Armbian/Debian. See `LICENCE`.
The cooling daemon itself is Go and uses the Linux GPIO character-device API.
