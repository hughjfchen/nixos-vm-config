# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).

{ config, lib, pkgs, ... }:
let
  username = "chenjf";
  # To generate a hashed password run `mkpasswd`.
  # this is the hash of the my personal password
  hashedPassword = "$y$j9T$U.t7m6E8cELNNcY4yatIx1$XfaRrx7xZch1tfnZo16oCboW1wtp7ujnTLe70nSwCA.";
  # TODO replace this with your own public key!
  # Done at 2024-03-08
  publickey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDouazcY0grLX8lAz/XrtDS1ZIo0s91BS7VrCKlzfRZtmcoI041vz+SBCCWbtnOMmWRFtA948aGtCN6EKD3JSREmrmJU1JfTIoekYzemdbjMbsTnIw0czP7weFtfFgdwhn8vro11k3uy0uG/32+aUYNUx+CNaDKulBRtg+oXRmjkrHCtapCHpN9/FMsvZjP0NbqVKtbf5Jem6Pqx8Himo3cZq3SKSYG8UIC/mAebEz793M5rR4FSvzXlfgiwCBn07F3+0rQAL6ZtsNEE521iJyU88tk6VsewPsZNvguCY21y3eKGYsny+ITMfR4liZjToIkrJGt3l7EMJawsAUemMWz hugh.jf.chen@gmail.com";
in {

  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
      ./myrabbitmq.nix
    ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # add following line to make fsType=fuse.bindfs happy
  security.pam.mount.additionalSearchPaths = [ pkgs.bindfs ];

  # mount the share folder
  fileSystems."/mnt/utmshare" = 
    { device = "share";
      fsType = "9p";
      options = [ "trans=virtio,version=9p2000.L,rw,_netdev,nofail,noexec,auto" ];
    };

  fileSystems."/home/${username}/macHome" =
    { device = "/mnt/utmshare";
      fsType = "fuse.bindfs";
      options = [ "map=501/chenjf:@20/@100,x-systemd.requires=/mnt/utmshare,rw,_netdev,nofail,noexec,auto" ];
    };

  # nix settings
  nix.settings = {
    experimental-features = ["nix-command" "flakes"];
    # Binary Cache for Haskell.nix
    trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
    ];
    substituters = [
      "https://cache.iog.io"
    ];
  };

  # Set your time zone.
  time.timeZone = "Asia/Shanghai";

  # List packages installed in system profile. To search, run:
  # $ nix search wget
  environment.systemPackages = with pkgs; [
    git # used by nix flakes
    vim
    wget
    bindfs
    mosh
    sshuttle

    btop # monitor system resources

    # for terminal and ssh session
    screen
    reptyr

    # some utils
    file
    binutils
    tree
    psmisc
    jq

    # some dev tools
    # let every one manage this part with home-manager
    # emacs
    # efm-langserver
    # shellcheck
  ];

  # fonts
  fonts.packages = with pkgs; [
    noto-fonts
    noto-fonts-extra
    noto-fonts-cjk-sans
    noto-fonts-cjk-serif
    noto-fonts-emoji
  ];

  # Disable IPv6 to test Cloud Haskell
  networking.enableIPv6  = false;

  # add some extra hosts I known off
  networking.extraHosts =
    ''
      127.0.0.1 cjfhost
      104.208.72.114 detachmentsoft.top
      194.233.66.103 detachment-soft.top
    '';

  # Open ports in the firewall.
  networking.firewall.allowedTCPPorts = [ 22 80 443 8883 5432 4369 5672 15672 25672 35672 35197 12300 22222 33333 44444 ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;
  # Enable the OpenSSH daemon.

  services.openssh = {
    enable = lib.mkDefault true;
    settings = {
      ClientAliveInterval = 30;
      TCPKeepAlive = true;
      X11Forwarding = lib.mkDefault true;
      PasswordAuthentication = lib.mkDefault true;
    };
    openFirewall = lib.mkDefault true;
  };

  # also set epmd to listen to IPv4
  #services.epmd.listenStream = "0.0.0.0:4369";

  # rabbitmq
  #services.myrabbitmq = {
  #  enable = lib.mkDefault true;
  #  managementPlugin.enable = lib.mkDefault true;
  #  nodename = "rabbit1@cjfhost";
  #};

  # postgresql
  #services.postgresql = {
  #  enable = lib.mkDefault true;
  #};

  # =========================================================================
  #      Users & Groups NixOS Configuration
  # =========================================================================

  # TODO Define a user account. Don't forget to update this!
  users.users."${username}" = {
    inherit hashedPassword;
    isNormalUser = true;
    home = "/home/${username}";
    extraGroups = ["users" "wheel"];

    # add pub key for ssh to login
    openssh.authorizedKeys.keys = [
      publickey
    ];
  };

  users.users.root.openssh.authorizedKeys.keys = [
    publickey
  ];

  users.groups = {
    "${username}" = {};
    docker = {};
  };

  # config NOPASSWORD for the user
  security.sudo.extraRules= [
    { users = [ "${username}" ];
      commands = [
        { command = "ALL" ;
           options= [ "NOPASSWD" ]; # "SETENV" # Adding the following could be a good idea
        }
      ];
    }
  ];

  # some env settting for shell
  environment.interactiveShellInit = ''
    alias 'ls=ls --color=always'
    alias 'll=ls -l'
    alias 'ltr=ls -ltr'
    alias 'ltra=ls -ltra'
    export 'TERM=xterm-256color'
  '';

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "24.11"; # Did you read the comment?


  # add a service unit to save out the IP address so that tools from outside
  # can use it
  systemd.services.save-out-my-ip = {
    description = "save out the IP address to a mounted shared folder";
    wantedBy = [ "multi-user.target" ]; # starts after login
    after = [ "mnt-utmshare.mount" "network-online.target" ];
    wants = [ "mnt-utmshare.mount" "network-online.target" ];
    script = ''
      [ -d "/mnt/utmshare" ] && ${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local' > "/mnt/utmshare/.the.vm.ipv4.address.$(${pkgs.nettools}/bin/hostname)"
    '';
    serviceConfig = {
      Type = "oneshot";
      ExecStartPre = "${pkgs.coreutils-full}/bin/sleep 3";
    };
  };

  # add a service unit to start the sshuttle poor man's VPN service
  systemd.services.sshuttle = {
    description = "the poor man's VPN";
    wantedBy = [ "multi-user.target" ]; # starts after login
    after = [ "mnt-utmshare.mount" "network-online.target" ];
    wants = [ "mnt-utmshare.mount" "network-online.target" ];
    script = ''
      # prepare the private key for ssh connection
      if [ -f "/root/.ssh/id_rsa" ]; then
        echo "ssh private key already on the VM, skip trying to locate it"
      else
        echo "No ssh private key on the VM ssh folder"
        echo "Will try to locate ssh private key from the host ssh folder"
        if [ -f "/mnt/utmshare/.ssh/id_rsa" ]; then
          mkdir -p /root/.ssh
          cp /mnt/utmshare/.ssh/id_rsa.pub /root/.ssh/
          cp /mnt/utmshare/.ssh/id_rsa /root/.ssh/
          cp /mnt/utmshare/.ssh/known_hosts /root/.ssh/
          chmod 700 /root/.ssh
          chmod 600 /root/.ssh/id_rsa /root/.ssh/known_hosts
          chmod 644 /root/.ssh/id_rsa.pub
        else
          echo "No ssh private key on the mounted host ssh folder, cannot continue"
	  exit 111
        fi
      fi

      LOCAL_ADDRESS=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local')
      SUBNET_PRE_LENGTH=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --arg JQ_LOCAL_ADDRESS "$LOCAL_ADDRESS" --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet" and .local==$JQ_LOCAL_ADDRESS) | .prefixlen')
      SUBNET_ADDRESS=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local' | ${pkgs.gawk}/bin/awk -F'.' '{print $1"."$2"."$3".""0"}')
      ${pkgs.sshuttle}/bin/sshuttle -x $SUBNET_ADDRESS/$SUBNET_PRE_LENGTH -x detachmentsoft.top -x detachment-soft.top --latency-buffer-size 65536 --disable-ipv6 --dns -r chenjf@detachmentsoft.top 0/0
    '';
    serviceConfig = {
      Restart = "on-failure";
      StartLimitIntervalSec=30;
      StartLimitBurst=5;
      ExecStartPre = "${pkgs.coreutils-full}/bin/sleep 1";
    };
  };

  # add a periodly running command to make sshuttle tunnel active
  systemd.services."check-sshuttle-tunnel" = {
    script = ''
      set -eu
      if ${pkgs.curl}/bin/curl --connect-timeout 3 https://www.twitter.com > /dev/null 2>&1; then
        echo "can access internet through sshuttle"
      else
        if ${pkgs.curl}/bin/curl --connect-timeout 3 https://detachment-soft.top > /dev/null 2>&1; then
          echo "cannot access internet through sshuttle"
          echo "but can access internet directly"
          echo "so try to restart the sshuttle service to see if this problem solved"
          ${pkgs.systemd}/bin/systemctl restart sshuttle.service
        else
          # not sure what to do in this case, ignore for now
          echo "cannot access internet through sshuttle"
          echo "cannot access internet directly either"
          echo "maybe really cannot access outside world due to network offline"
          echo "so do nothing for now"
        fi
      fi
    '';
    serviceConfig = {
      Type = "oneshot";
    };
  };

  systemd.timers."check-sshuttle-tunnel" = {
    wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "3m";
        OnUnitActiveSec = "3m";
        Unit = "check-sshuttle-tunnel.service";
      };
  };
}

