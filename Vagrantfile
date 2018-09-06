# Fedora 26 Vagrant Machine

# Update and install packages.
$packages = <<SCRIPT
dnf update -y

# From https://cilium.readthedocs.io/en/latest/bpf/#llvm
dnf install -y git gcc ncurses-devel elfutils-libelf-devel bc \
  openssl-devel libcap-devel clang llvm

# jq because isn't convenient.
dnf install -y jq

dnf clean all
SCRIPT

# Setup and install Go development environment.
$gvm = <<SCRIPT
mkdir -p ~/bin
curl -sL -o ~/bin/gvm https://github.com/andrewkroh/gvm/releases/download/v0.1.0/gvm-linux-amd64
chmod +x ~/bin/gvm

echo 'export GOPATH=~/go' >> ~/.bashrc
echo 'export PATH=~/bin:$GOPATH/bin:$PATH' >> ~/.bashrc
echo 'eval "$(gvm 1.11)"' >> ~/.bashrc
echo 'alias vim=vi' >> ~/.bashrc
mkdir -p ~/go/src/github.com/andrewkroh
ln -s /vagrant ~/go/src/github.com/andrewkroh/go-ebpf
SCRIPT

Vagrant.configure("2") do |config|
  # https://alt.fedoraproject.org/cloud/
  config.vm.box_url = "https://download.fedoraproject.org/pub/fedora/linux/releases/26/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-26-1.5.x86_64.vagrant-virtualbox.box"
  config.vm.box = "fedora-26-url"

  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  # Requires vbguest plugin (run 'vagrant plugin install vagrant-vbguest').
  # https://github.com/dotless-de/vagrant-vbguest
  config.vbguest.auto_update = true
  config.vbguest.no_remote = true

  config.vm.provision "shell", inline: $packages
  config.vm.provision "shell", inline: $gvm, privileged: false
end
