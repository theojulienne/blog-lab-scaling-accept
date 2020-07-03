# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/buster64"
  config.vm.hostname = "blog-lab-scaling-accept"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y docker.io bpfcc-tools nginx net-tools tcpdump linux-headers-$(uname -r)
  SHELL
end
