# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
    config.vm.synced_folder ".", "/vagrant", disabled: true

    machine_names = ["bak", "log", "ca", "db", "web", "client"]
    servers = ["bak", "log", "ca", "db", "web"]
    clients = ["client"]

    ENABLE_GUI = ENV['ENABLE_GUI'] == 'true'

    machine_names.each do |machine_name|
        config.vm.define machine_name do |machine|
            machine.vm.box = "ubuntu/focal64"
            machine.vm.hostname = machine_name

            machine.vm.provider "virtualbox" do |vb|
                vb.name = machine_name

                if servers.include?(machine_name)
                    vb.memory = "1024"
                    vb.cpus = 2
                end

                if clients.include?(machine_name)
                    vb.memory = "4096"
                    vb.cpus = 2
                    vb.gui = ENABLE_GUI
                    vb.customize ["modifyvm", :id, "--vram", "128"]
                    vb.customize ["modifyvm", :id, "--accelerate3d", "on"]
                end
            end

            if servers.include?(machine_name)
                main_ip = "192.168.56.#{servers.length() - servers.index(machine_name)}"
                machine.vm.network "private_network", ip: main_ip, hostname: true
            end

            case machine_name
            when "web" then machine.vm.network "private_network", ip: "192.168.57.2"
            when "client" then machine.vm.network "private_network", ip: "192.168.57.3"
            end

            if machine_name == machine_names.last
                machine.vm.provision "ansible" do |ansible|
                    ansible.galaxy_role_file = "requirements.yaml"
                    ansible.playbook = "playbook.yaml"
                    ansible.compatibility_mode = "2.0"
                    ansible.version = "latest"
                    ansible.limit = "all"
                    ansible.groups = {
                        "servers" => servers,
                        "clients" => clients
                    }
                end
            end
        end
    end
end
