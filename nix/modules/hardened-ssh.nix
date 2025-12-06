# Barbican Security Module: Hardened SSH
# Addresses: CRT-010 (SSH without rate limiting)
# Standards: NIST AC-7, IA-5(1), CIS 5.2.x
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.barbican.hardenedSSH;
in {
  options.barbican.hardenedSSH = {
    enable = mkEnableOption "Barbican SSH hardening";

    maxAuthTries = mkOption {
      type = types.int;
      default = 3;
      description = "Maximum authentication attempts before disconnect";
    };

    maxSessions = mkOption {
      type = types.int;
      default = 2;
      description = "Maximum concurrent sessions per connection";
    };

    clientAliveInterval = mkOption {
      type = types.int;
      default = 300;
      description = "Seconds between keepalive messages";
    };

    enableFail2ban = mkOption {
      type = types.bool;
      default = true;
      description = "Enable fail2ban SSH jail";
    };

    fail2banMaxRetry = mkOption {
      type = types.int;
      default = 3;
      description = "Fail2ban max retries before ban";
    };

    fail2banBanTime = mkOption {
      type = types.int;
      default = 3600;
      description = "Fail2ban ban duration in seconds";
    };
  };

  config = mkIf cfg.enable {
    services.openssh = {
      enable = true;
      settings = {
        # Authentication
        PasswordAuthentication = false;
        PermitRootLogin = "prohibit-password";
        PermitEmptyPasswords = false;
        PubkeyAuthentication = true;
        AuthenticationMethods = "publickey";

        # Session limits
        MaxAuthTries = cfg.maxAuthTries;
        MaxSessions = cfg.maxSessions;
        ClientAliveInterval = cfg.clientAliveInterval;
        ClientAliveCountMax = 2;

        # Disable dangerous features
        X11Forwarding = false;
        AllowTcpForwarding = false;
        AllowAgentForwarding = false;
        PermitTunnel = false;

        # Strong cryptography only
        Ciphers = [
          "chacha20-poly1305@openssh.com"
          "aes256-gcm@openssh.com"
          "aes128-gcm@openssh.com"
        ];

        KexAlgorithms = [
          "curve25519-sha256"
          "curve25519-sha256@libssh.org"
          "diffie-hellman-group-exchange-sha256"
        ];

        Macs = [
          "hmac-sha2-512-etm@openssh.com"
          "hmac-sha2-256-etm@openssh.com"
        ];
      };

      # Banner
      banner = config.barbican.secureUsers.loginBanner or ''
        AUTHORIZED ACCESS ONLY
      '';
    };

    # Fail2ban for brute force protection
    services.fail2ban = mkIf cfg.enableFail2ban {
      enable = true;
      maxretry = cfg.fail2banMaxRetry;
      bantime = toString cfg.fail2banBanTime;

      jails = {
        sshd = {
          settings = {
            enabled = true;
            port = "ssh";
            filter = "sshd";
            logpath = "/var/log/auth.log";
            maxretry = cfg.fail2banMaxRetry;
            findtime = 600;
            bantime = cfg.fail2banBanTime;
          };
        };
      };
    };
  };
}
