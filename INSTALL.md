# Install SysinternalsEBPF
Please see the history of this file for instructions for older, unsupported versions.

## Ubuntu 20.04, 22.04, 23.04
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysinternalsEBPF
```sh
sudo apt-get update
sudo apt-get install sysinternalsebpf
```

## Debian 11
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysinternalsEBPF
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysinternalsebpf
```

## Debian 12
#### 1. Register Microsoft key and feed
```sh
wget -q https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
```

#### 2. Install SysinternalsEBPF
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysinternalsebpf
```

## Fedora 37
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/37/packages-microsoft-prod.rpm
```

#### 2. Install SysinternalsEBPF
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysinternalsebpf
```

## Fedora 38
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/fedora/38/packages-microsoft-prod.rpm
```

#### 2. Install SysinternalsEBPF
```sh
sudo apt-get update
sudo apt-get install apt-transport-https
sudo apt-get update
sudo apt-get install sysinternalsebpf
```

## RHEL 8
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/8/packages-microsoft-prod.rpm
```

#### 2. Install SysinternalsEBPF
```sh
sudo yum install sysinternalsebpf
```

## RHEL 9
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/rhel/9/packages-microsoft-prod.rpm
```

#### 2. Install SysinternalsEBPF
```sh
sudo yum install sysinternalsebpf
```

## openSUSE 15
#### 1. Register Microsoft key and feed
```sh
sudo zypper install libicu
sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
wget -q https://packages.microsoft.com/config/opensuse/15/prod.repo
sudo mv prod.repo /etc/zypp/repos.d/microsoft-prod.repo
sudo chown root:root /etc/zypp/repos.d/microsoft-prod.repo
```

#### 2. Install SysinternalsEBPF
```sh
sudo zypper install sysinternalsebpf
```

## SLES 15
#### 1. Register Microsoft key and feed
```sh
sudo rpm -Uvh https://packages.microsoft.com/config/sles/15/packages-microsoft-prod.rpm
```

#### 2. Install SysinternalsEBPF
```sh
sudo zypper install sysinternalsebpf
```

