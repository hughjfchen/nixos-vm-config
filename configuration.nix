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

  # mount the share folder

  fileSystems."/home/${username}/macHome" =
    { device = "share";
      fsType = "virtiofs";
      options = [ "rw,nofail,noexec" ];
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
    wget
    mosh
    sshuttle

    btop # monitor system resources

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
      209.145.56.16 detachment-soft.top
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
      X11Forwarding = lib.mkDefault true;
      PasswordAuthentication = lib.mkDefault true;
    };
    openFirewall = lib.mkDefault true;
  };

  # also set epmd to listen to IPv4
  services.epmd.listenStream = "0.0.0.0:4369";

  # rabbitmq
  services.myrabbitmq = {
    enable = lib.mkDefault true;
    managementPlugin.enable = lib.mkDefault true;
    nodename = "rabbit1@cjfhost";
  };

  # postgresql
  services.postgresql = {
    enable = lib.mkDefault true;
  };

  # =========================================================================
  #      Users & Groups NixOS Configuration
  # =========================================================================

  # TODO Define a user account. Don't forget to update this!
  users.users."${username}" = {
    inherit hashedPassword;
    isNormalUser = true;
    home = "/home/${username}";
    extraGroups = ["users" "wheel"];
  };

  #users.users."${username}".openssh.authorizedKeys.keys = [
  #  publickey
  #];
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
  system.stateVersion = "24.05"; # Did you read the comment?


  # add a service unit to save out the IP address so that tools from outside
  # can use it
  systemd.services.save-out-my-ip = {
    description = "save out the IP address to a mounted shared folder";
    wantedBy = [ "multi-user.target" ]; # starts after login
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    script = ''
      [ -d "/home/${username}/macHome/${username}" ] && ${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local' > "/home/${username}/macHome/${username}/.the.vm.ipv4.address.$(${pkgs.nettools}/bin/hostname)"
    '';
    serviceConfig = {
      Type = "oneshot";
      User = "${username}";
      ExecStartPre = "${pkgs.coreutils-full}/bin/sleep 3";
    };
  };

  # add a service unit to start the sshuttle poor man's VPN service
  systemd.services.sshuttle = {
    description = "the poor man's VPN";
    wantedBy = [ "multi-user.target" ]; # starts after login
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    script = ''
      LOCAL_ADDRESS=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local')
      SUBNET_PRE_LENGTH=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --arg JQ_LOCAL_ADDRESS "$LOCAL_ADDRESS" --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet" and .local==$JQ_LOCAL_ADDRESS) | .prefixlen')
      SUBNET_ADDRESS=$(${pkgs.iproute2}/bin/ip -json address | ${pkgs.jq}/bin/jq --raw-output '.[] | select(.operstate=="UP") | .addr_info[] | select(.family=="inet") | .local' | ${pkgs.gawk}/bin/awk -F'.' '{print $1"."$2"."$3".""0"}')
      ${pkgs.sshuttle}/bin/sshuttle -x $SUBNET_ADDRESS/$SUBNET_PRE_LENGTH -x detachmentsoft.top -x detachment-soft.top --latency-buffer-size 65536 --disable-ipv6 --dns -r root@detachment-soft.top 0/0
    '';
    serviceConfig = {
      Restart = "on-failure";
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

