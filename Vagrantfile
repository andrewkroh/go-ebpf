# Fedora Vagrant Machines

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

boxes = {
  "fedora-26" => {
    :url => 'https://download.fedoraproject.org/pub/fedora/linux/releases/26/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-26-1.5.x86_64.vagrant-virtualbox.box',
    :ip  => '10.0.2.15',
    :cpu => "100",
    :ram => "512",
  },
  "fedora-28" => {
    :url => 'https://download.fedoraproject.org/pub/fedora/linux/releases/28/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-28-1.1.x86_64.vagrant-virtualbox.box',
    :ip  => '10.0.2.16',
    :cpu => "100",
    :ram => "512",
  },
}

Vagrant.configure("2") do |config|
  boxes.each do |box_name, box|
    config.vm.define box_name do |machine|
      machine.vm.box_url = box[:url]
      machine.vm.box = "%s" % box_name
      machine.vm.hostname = "%s" % box_name

      machine.vm.provider "virtualbox" do |v|
        v.customize ["modifyvm", :id, "--cpuexecutioncap", box[:cpu]]
        v.customize ["modifyvm", :id, "--memory",          box[:ram]]
      end

      # Requires vbguest plugin (run 'vagrant plugin install vagrant-vbguest').
      # https://github.com/dotless-de/vagrant-vbguest
      machine.vbguest.auto_update = true
      machine.vbguest.no_remote = true

      machine.vm.synced_folder ".", "/vagrant", type: "virtualbox"

      machine.vm.provision "shell", inline: $packages
      machine.vm.provision "shell", inline: $gvm, privileged: false
    end
  end
end
