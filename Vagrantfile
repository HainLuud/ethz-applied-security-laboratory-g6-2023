Vagrant.configure("2") do |config|
    config.vm.provider "virtualbox" do |vb|
        vb.memory = "1024"
    end

    # machine_names = ["bak", "log", "ca", "db", "web", "vpn", "client"]
    machine_names = ["bak", "log", "ca", "db", "web", "client"]

    machine_names.each do |machine_name|
        config.vm.define machine_name do |machine|
            machine.vm.box = "ubuntu/focal64"
            machine.vm.hostname = machine_name

            case machine_name
            when "bak"
                machine.vm.network "private_network", ip: "192.168.56.5", hostname: true
            when "log"
                machine.vm.network "private_network", ip: "192.168.56.4", hostname: true
            when "ca"
                machine.vm.network "private_network", ip: "192.168.56.3", hostname: true
            when "db"
                machine.vm.network "private_network", ip: "192.168.56.2", hostname: true
            when "web"
                machine.vm.network "private_network", ip: "192.168.56.1", hostname: true
                machine.vm.network "private_network", ip: "192.168.57.1"
            # when "vpn"
            #     machine.vm.network "private_network", ip: "192.168.56.10", hostname: true
            #     machine.vm.network "forwarded_port", guest: 51820, host: 51820, protocol: "udp"
            when "client"
                machine.vm.network "private_network", ip: "192.168.57.2"
                machine.vm.provider "virtualbox" do |vb|
                    vb.gui = true
                end
            end

            machine.vm.provision "ansible_local" do |ansible|
                ansible.playbook = "#{machine_name}/local_playbook.yml"
            end

            if machine_name == machine_names.last
                machine.vm.provision "ansible" do |ansible|
                    ansible.limit = "all"
                    ansible.playbook = "playbook.yml"
                end
            end
        end
    end
end
