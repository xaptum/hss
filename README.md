# Host Socket Sharing

This repository contains the HSS specification as well as Xaptum's
implementation for both hosts and devices.

HSS is a protocol that allows a USB host to share its internet connection with
devices. This allows USB devices to access external networks without knowing
any details or requiring any configuration with network hardware. USB devices
are given virtual control over sockets opened by the host. This also allows for
the device to be constrained by the same firewall rules as the host.

See `HSS_protocol.pdf` for information regarding the HSS standard.

# HSS Host Driver

The `host` directory contains the driver required for an HSS host to sit
between the USB device and the external network.

## Debian Installation

Xaptum maintains an Apt repository for HSS, so all Debian users need to do is
add Xaptums repo and install.

```
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys c615bfaa7fe1b4ca
echo "deb http://dl.bintray.com/xaptum/deb <dist> main" | sudo tee /etc/apt/sources.list.d/xaptum.list
sudo apt-get update
sudo apt-get install xaptum-hss-host
```
Replace <dist> with your Debian distrobuation (Stretch, Buster, ect)



## DKMS install

The preferred installation method for non-Debian users is using DKMS, otherwise
this driver will have to be manually rebuild every time the kernel is changed.
A script is provided in the host directory to automate the DKMS install process.

```
git clone git@github.com:xaptum/hss.git
cd hss/host
sudo ./dkms-install
```

## Manual installation

If neither our APT repos or DKMS are available the module can be independently
built and managed.

Note: Required packages: kernel-devel, git, build-essential, kernel-headers-$(
uname -r), sudo

```
git clone git@github.com:xaptum/hss.git
cd hss/host/src
make
sudo make install
```

# HSS Device Drivers

HSS requires out-of-tree modifications to the kernel of the USB device, as such
patches must be applied to the kernel as it is build. Luckily, the patches are
relatively simple. They are located in the `device/kernel` directory. The patch
`hss-includes.patch` creates new headers to define HSS packet objects within the
kernel, `hss-socket.patch` creates a new type of socket `AF_HSS`, and `hss-selinux.patch`
adds this new sockets definitions to SELinux's compile time checks. The second
two patches may require some amount of customization to fit around a given version
of Linux, but the addition is very simple.

We are working towards upstreaming these changes to remove the patching altogether. 

The HSS Device directory contains two more directories, each containing a loadable module.

The `device/gadget` directory contains the USB driver responsible for communicating with the host.

The `device/net` directory contains the Linux network layer driver responsible
for handling socket communications, as well as software responsible for
packetizing the data and communicating with the USB driver.

Both loadable modules require a kernel with the included patches. The `f_hss`
driver requires the `net` driver to be built first and compile-time access to
its `Modules.symvers`.

Xaptum maintains a Buildroot [project](https://github.com/xaptum/xaptum-
buildroot) for our hardware that integrates HSS, this can be used as an example
for integrating HSS into your project.

## License
Copyright (c) 2020 Xaptum, Inc.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
