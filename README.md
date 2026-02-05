# tpm-fido2

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

## Dependencies

- [PinEntry](https://gnupg.org/software/pinentry/) - for prompting for PINs
- A TPM 2.0 device

## Running

### 1. Install PinEntry

You must have PinEntry to prompt for PINs. On Debian, you can install it with:

```sh
$ sudo apt install pinentry
```

However, it usually is already installed as a dependency of GPG. You can verify that it is installed by running:

```sh
$ pinentry --version
```

### 2. User Permissions

To access the TPM device, your user needs to have permission to read and write to `/dev/tpmrm0`. In Debian and Arch, this is done by adding your user to the `tss` group. In Debian, you can do this with:

```sh
$ sudo usermod -aG tss $USER
```

### 3. Set UHID Permissions

Emulating a USB HID device requires access to `/dev/uhid`. You need to set the appropriate permissions so that your user can read and write to this device.

To achieve this, you can create a udev rule. Create a file at `/etc/udev/rules.d/99-uhid.rules` with the following content:

```
KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="SOME_UHID_GROUP_MY_USER_BELONGS_TO", MODE="0660"
```

### 4. Load UHID Module at Boot

To ensure that the `uhid` module is loaded at boot, create a file at `/etc/modules-load.d/uhid.conf` with the following content:

```
uhid
```

### 5. Install tpm-fido as a service

You can install `tpm-fido` as a systemd service so that it starts automatically at boot. This is possible by running `install.sh` script provided in the repository.

```sh
$ sh install.sh
```

> [!NOTE]
> Currently only systemd is supported. PRs for other init systems are welcome.

## Building

To build tpm-fido, ensure you have Go installed (version 1.16 or later). Then, clone the repository and navigate to the project directory. Run the following command to build the project:

```sh
$ go build
```
