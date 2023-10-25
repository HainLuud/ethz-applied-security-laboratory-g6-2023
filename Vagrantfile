Vagrant.configure("2") do |config|
    # config.vm.synced_folder '.', '/vagrant', disabled: true # Uncomment when creating machines for submission
    # it removes the ability to do vagrant ssh <box> but it also removes the shared folder /vagrant from the machine
    
    # Define the bak server machine
    config.vm.define "bak" do |bak|
        bak.vm.box = "ubuntu/focal64"
        bak.vm.host_name = "bak.imovies.ch"
        bak.vm.network "private_network", ip: "192.168.56.14", hostname: true
        bak.vm.provider "virtualbox" do |vb|
            vb.memory = "1024"
        end
        bak.vm.provision "ansible" do |ansible|
            ansible.playbook = "playbooks/bak_playbook.yml"
        end
    end
    # Define the bak server machine
    config.vm.define "log" do |log|
        log.vm.box = "ubuntu/focal64"
        log.vm.host_name = "log.imovies.ch"
        log.vm.network "private_network", ip: "192.168.56.15", hostname: true
        log.vm.provider "virtualbox" do |vb|
            vb.memory = "1024"
        end
        log.vm.provision "ansible" do |ansible|
            ansible.playbook = "playbooks/log_playbook.yml"
        end
    end
    # Define the bak server machine
    config.vm.define "ca" do |ca|
        ca.vm.box = "ubuntu/focal64"
        ca.vm.host_name = "ca.imovies.ch"
        ca.vm.network "private_network", ip: "192.168.56.13", hostname: true
        ca.vm.provider "virtualbox" do |vb|
            vb.memory = "1024"
        end
        ca.vm.provision "ansible" do |ansible|
            ansible.playbook = "playbooks/ca_playbook.yml"
        end
    end
    # Define the db server machine
    config.vm.define "db" do |db|
        db.vm.box = "ubuntu/focal64"
        db.vm.host_name = "db.imovies.ch"
        db.vm.network "private_network", ip: "192.168.56.12", hostname: true
        db.vm.provider "virtualbox" do |vb|
            vb.memory = "1024"
        end
        db.vm.provision "ansible" do |ansible|
            ansible.playbook = "playbooks/db_playbook.yml"
        end
    end

    # Define the web server machine
    config.vm.define "web" do |web|
        web.vm.box = "ubuntu/focal64"
        web.vm.host_name = "imovies.ch"
        web.vm.network "private_network", ip: "192.168.56.11", hostname: true
        web.vm.network "public_network", bridge: "wlp4s0" # YOU MAY NEED TO CHANGE THIS INTERFACE NAME
        web.vm.network "forwarded_port", guest: 443, host: 443
        web.vm.provider "virtualbox" do |vb|
            vb.memory = "1024"
        end
        web.vm.provision "ansible" do |ansible|
            ansible.playbook = "playbooks/web_playbook.yml"
        end
    end

    # # Define the WireGuard server machine
    # config.vm.define "wireguard" do |wg|
    #     wg.vm.box = "ubuntu/focal64"
    #     wg.vm.host_name = "wg.imovies.ch"
    #     wg.vm.network "public_network", ip: "10.5.35.90", bridge: "wlp4s0"
    #     wg.vm.network "private_network", ip: "192.168.56.10", hostname: true
    #     # Open UDP port 51820 to the outside network
    #     wg.vm.network "forwarded_port", guest: 51820, host: 51820, protocol: "udp"
    #     wg.vm.provider "virtualbox" do |vb|
    #         vb.memory = "1024"
    #     end
    #     # Provision the machine with WireGuard
    #     wg.vm.provision "ansible" do |ansible|
    #         ansible.playbook = "wireguard_playbook.yml"
    #     end
    # end
end
