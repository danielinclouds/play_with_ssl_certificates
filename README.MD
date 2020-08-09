
# Playing with SSL/TLS Certificates
This repository contains examples that help with understanding SSL/TLS certificates.

Change example.com to your domain.


# Certificate with two hosts
## Scenario:  
- Create CA  
- Sign SSL cert with CA and deploy
    - 2 SANs  
        - public domain  
        - private domain  

## Commands:  
```sh
cd ./cert_with_two_hosts
cfssl gencert -initca csr_ca.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config config_ca.json -profile server csr_www.json | cfssljson -bare www
```
1. Put ca.pem to mac keychain  
1. Put www.pem with ca.pem to AWS Cert Manager
1. Deploy terraform from `test_infrastructure` folder
1. Test connection to instance from browser
1. Check that both hostnames are in certificate


# Intermediate Certificate
## Scenario:  
- Create CA  
- Create Intermediate CA  
- Sign SSL cert sign it with Intermediate CA and deploy  

## Commands:  
```sh
cfssl gencert -initca csr_ca.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config config_inter.json csr_inter.json | cfssljson -bare inter
cfssl gencert -ca inter.pem -ca-key inter-key.pem -config config_ca.json -profile server csr_www.json | cfssljson -bare www
```
1. Put ca.pem to mac keychain  
1. Put www.pem with inter.pem to AWS Cert Manager  
1. Deploy terraform from `test_infrastructure` folder  
1. Test connection to instance from browser  
1. Check that server and intermediate certificates are in certificate chain  


# Self-signed Certificate
## Scenario:  
- Create self signed certificate and deploy  
- Configure browser to trust it  

## Commands:  
```sh
cfssl selfsign www.example.pri csr_self.json | cfssljson -bare self
```
1. Put self.pem to mac keychain  
1. Put self.pem to AWS Cert Manager  
1. Deploy terraform from `test_infrastructure` folder  
1. Test connection to instance from browser  


# Docker container that trusts certificate from internal CA
## Scenario:  
- Create certificates and infra from "Certificate with two hosts"
- Copy ca.pem to `docker_trusting_internal_ca` folder
- Create docker contaier that trusts internal CA
- Test connection from container to server

## Commands:  
```sh
docker build --no-cache -t client .
```
