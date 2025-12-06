# Barbican PKI Library
# Provides helpers for certificate generation
{ lib }:

with lib;

{
  # Generate OpenSSL commands for a CA
  mkCAScript = { name, days ? 3650, keySize ? 4096, algorithm ? "secp384r1" }:
    if algorithm == "rsa" then ''
      # Generate RSA CA
      openssl genrsa -out ${name}-ca-key.pem ${toString keySize}
      openssl req -new -x509 -sha384 -key ${name}-ca-key.pem \
        -out ${name}-ca.pem -days ${toString days} \
        -subj "/C=US/O=${name}/CN=${name} CA"
    '' else ''
      # Generate EC CA
      openssl ecparam -name ${algorithm} -genkey -out ${name}-ca-key.pem
      openssl req -new -x509 -sha384 -key ${name}-ca-key.pem \
        -out ${name}-ca.pem -days ${toString days} \
        -subj "/C=US/O=${name}/CN=${name} CA"
    '';

  # Generate server certificate with SANs
  mkServerCertScript = {
    name,
    caName,
    commonName,
    sans ? [],
    days ? 365,
    algorithm ? "secp384r1"
  }:
    let
      sanList = concatStringsSep "," (
        (map (ip: "IP:${ip}") (filter (s: hasPrefix "10." s || hasPrefix "192." s || hasPrefix "172." s) sans)) ++
        (map (dns: "DNS:${dns}") (filter (s: !(hasPrefix "10." s || hasPrefix "192." s || hasPrefix "172." s)) sans))
      );
    in if algorithm == "rsa" then ''
      # Generate RSA server certificate
      openssl genrsa -out ${name}-key.pem 4096
      openssl req -new -key ${name}-key.pem -out ${name}.csr \
        -subj "/C=US/O=${caName}/CN=${commonName}"

      openssl x509 -req -in ${name}.csr \
        -CA ${caName}-ca.pem -CAkey ${caName}-ca-key.pem \
        -CAcreateserial -out ${name}.pem -days ${toString days} -sha384 \
        -extfile <(cat <<EOF
      subjectAltName=${sanList}
      keyUsage=critical,digitalSignature,keyEncipherment
      extendedKeyUsage=serverAuth
      EOF
      )
      rm ${name}.csr
    '' else ''
      # Generate EC server certificate
      openssl ecparam -name ${algorithm} -genkey -out ${name}-key.pem
      openssl req -new -key ${name}-key.pem -out ${name}.csr \
        -subj "/C=US/O=${caName}/CN=${commonName}"

      openssl x509 -req -in ${name}.csr \
        -CA ${caName}-ca.pem -CAkey ${caName}-ca-key.pem \
        -CAcreateserial -out ${name}.pem -days ${toString days} -sha384 \
        -extfile <(cat <<EOF
      subjectAltName=${sanList}
      keyUsage=critical,digitalSignature,keyEncipherment
      extendedKeyUsage=serverAuth
      EOF
      )
      rm ${name}.csr
    '';

  # Generate client certificate for mTLS
  mkClientCertScript = {
    name,
    caName,
    commonName,
    days ? 365,
    algorithm ? "secp384r1"
  }:
    if algorithm == "rsa" then ''
      # Generate RSA client certificate
      openssl genrsa -out ${name}-key.pem 4096
      openssl req -new -key ${name}-key.pem -out ${name}.csr \
        -subj "/C=US/O=${caName}/CN=${commonName}"

      openssl x509 -req -in ${name}.csr \
        -CA ${caName}-ca.pem -CAkey ${caName}-ca-key.pem \
        -CAcreateserial -out ${name}.pem -days ${toString days} -sha384 \
        -extfile <(cat <<EOF
      keyUsage=critical,digitalSignature
      extendedKeyUsage=clientAuth
      EOF
      )
      rm ${name}.csr
    '' else ''
      # Generate EC client certificate
      openssl ecparam -name ${algorithm} -genkey -out ${name}-key.pem
      openssl req -new -key ${name}-key.pem -out ${name}.csr \
        -subj "/C=US/O=${caName}/CN=${commonName}"

      openssl x509 -req -in ${name}.csr \
        -CA ${caName}-ca.pem -CAkey ${caName}-ca-key.pem \
        -CAcreateserial -out ${name}.pem -days ${toString days} -sha384 \
        -extfile <(cat <<EOF
      keyUsage=critical,digitalSignature
      extendedKeyUsage=clientAuth
      EOF
      )
      rm ${name}.csr
    '';

  # Generate a complete PKI setup script
  mkPKISetupScript = {
    name,
    servers ? [],
    clients ? [],
    outputDir ? "./certs"
  }:
    let
      serverScripts = concatMapStringsSep "\n\n" (server:
        "# Server: ${server.name}\n" +
        (mkServerCertScript {
          inherit (server) name commonName;
          caName = name;
          sans = server.sans or [];
        })
      ) servers;

      clientScripts = concatMapStringsSep "\n\n" (client:
        "# Client: ${client.name}\n" +
        (mkClientCertScript {
          inherit (client) name commonName;
          caName = name;
        })
      ) clients;
    in ''
      #!/usr/bin/env bash
      set -euo pipefail

      mkdir -p ${outputDir}
      cd ${outputDir}

      echo "Generating ${name} PKI..."

      # Generate CA
      ${mkCAScript { inherit name; }}

      # Generate server certificates
      ${serverScripts}

      # Generate client certificates
      ${clientScripts}

      echo "PKI generation complete. Certificates in ${outputDir}/"
      ls -la
    '';
}
