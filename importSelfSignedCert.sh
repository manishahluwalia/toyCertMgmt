#!/usr/bin/env bash

## WORK IN PROGRESS

set -e

# Global constants that determine behavior

# Requires gnu-getopt
eval set -- $(getopt --name `basename $0` --long help "" -- "$@")
while [[ $# -gt 1 ]]
do
  opt="$1"
  shift
  case "$opt" in
    --help)
      cat <<EOF | sed 's/^        //g'
        Usage
         Import a given self-signed certificate and its private key.

        WORK IN PROGRESS
EOF
     exit 0
     ;;
    --)
     break
     ;;
    *)
     echo "ERROR: Unknown option: $opt" >&2
     exit 1
     ;;
  esac
done

if [[ $# -ne 3 ]]
then
  echo "Incorrect Usage. Check --help" >&2
  exit 1
fi

entityName="$1"
cert="$2"
key="$3"

# Validate input
: ${entityName:?ERROR: Must provide entity name}
: ${cert:?ERROR: Must provide path to cert}
: ${key:?ERROR: Must provide path to key}

if [[ ! -r "$cert" ]]
then
   echo "ERROR: Can't read file $cert" >&2
   exit 1
fi

if [[ ! -r "$key" ]]
then
   echo "ERROR: Can't read file $cert" >&2
   exit 1
fi


# Verify that cert is self-signed
if ! openssl verify -CAfile $cert $cert
then
  echo "ERROR: $cert must be a valid self-signed x509 cert in PEM format" >&2
  exit 1
fi

# Verify that private key matches cert. For all types of keys!!!
if ! cmp <(openssl x509 -pubkey -in $cert -noout) <(openssl pkey -pubout -in $key -outform PEM)
then
  echo "ERROR: private key does not match public key in certificate" >&2
  exit 1
fi

# Verifications done


mkdir $entityName
pushd $entityName

# Make subdirs and files
mkdir certs private ca-stuff
chmod 700 private
pushd ca-stuff
  mkdir crl newcerts
  touch index.txt
  touch index.txt.attr
  echo 1000 > serial
  echo 1000 > crlnumber
popd

popd

# Transfer the cert and key from the given location to our own location. Do this via openssl, so any passwords can be prompted for and removed. Also, we get to convert the input to PEM format
openssl x509 -in $cert -outform PEM -out $entityName/certs/cert.pem
openssl pkey -outform PEM -in $key -out $entityName/private/key.pem
cp $entityName/certs/cert.pem $entityName/certs/chain.pem


# Convenience concatenations of private key with cert/chain
cat $entityName/private/key.pem $entityName/certs/chain.pem > $entityName/private/key-chain.pem
cat $entityName/private/key.pem $entityName/certs/cert.pem > $entityName/private/key-cert.pem

# Note, this is the single cert for this entity, not the entire chain rooted at a self-signed cert
keytool -import -alias ca -file $entityName/certs/cert.pem -keystore $entityName/certs/truststore.jks -storepass password -noprompt

openssl pkcs12 -export -in $entityName/certs/chain.pem -inkey $entityName/private/key.pem -out $entityName/private/keystore.p12 -passout pass:password
keytool -importkeystore -srckeystore $entityName/private/keystore.p12 -srcstoretype pkcs12 -destkeystore $entityName/private/keystore.jks -deststorepass password -srcstorepass password

chmod 444 $entityName/certs/*.pem
chmod 400 $entityName/private/*.pem
