#!/usr/bin/env bash

set -e

# Global constants that determine behavior

# Set to something you want ALL certificates to get by default
subjectPrefix='/C=US/ST=CA'


# Setup defaults
isCA=FALSE
keyUsage=
extendedKeyUsage=
subjectName=
keySpec=rsa:1024
startdate=
enddate=
# Requires gnu-getopt
eval set -- $(getopt --name `basename $0` --long help,ca,server,client,subjectName:,key:,key-usage:,extended-key-usage:,extension:,startdate:,enddate: --options "" -- "$@")
while [[ $# -gt 1 ]]
do
  opt="$1"
  shift
  case "$opt" in
    --ca) 
      isCA=TRUE
      keyUsage="keyUsage = critical, cRLSign, keyCertSign"
      extendedKeyUsage=
      ;;
    --server) 
      isCA=FALSE
      keyUsage="keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement"
      extendedKeyUsage="extendedKeyUsage = critical, serverAuth"
      ;;
    --client) 
      isCA=FALSE
      keyUsage="keyUsage = critical, digitalSignature, keyAgreement"
      extendedKeyUsage="extendedKeyUsage = critical, clientAuth"
      ;;
    --client-server) 
      isCA=FALSE
      keyUsage="keyUsage = critical, digitalSignature, keyEncipherment, keyAgreement"
      extendedKeyUsage="extendedKeyUsage = critical, serverAuth, clientAuth"
      ;;
    --key)
      keySpec="$1"
      shift
      ;;
    --key-usage)
      keyUsage="keyUsage = $1"
      shift
      ;;
    --extended-key-usage)
      extendedKeyUsage="extendedKeyUsage = $1"
      shift
      ;;
    --subjectName)
      subjectName="$1"
      shift
      ;;
    --extension)
      extensions="$extensions"$'\n'"$1"
      shift
      ;;
    --startdate)
      startdate="-startdate $1"
      shift
      ;;
    --enddate)
      enddate="-enddate $1"
      shift
      ;;
    --)
      break
      ;;
    --help)
      cat <<EOF | sed 's/^        //g'
        Usage
         Run from a directory for the entity you are creating certs for. It will create a directory for this entity and substructure below
           makeCerts [options] <entityName> <commonName> <parentCa>
             Options:
               --ca     This is a CA cert. Will get a critical keyusage section of keyCertSign and cRLSign, and no extendedKeyUsage
               --server This is a TLS server cert. It will not be a CA cert, with a critical keyUsage of 'digitalSignature, keyEncipherment, keyAgreement'
                        and a critical extendedKeyUsage of 'serverAuth'
               --client This is a TLS client cert. It will not be a CA cert, with a critical keyUsage of 'digitalSignature, keyAgreement'
                        and a critical extendedKeyUsage of 'clientAuth'
               --client-server Combines the keyUsage and extendedKeyUsage of both --client and --server options above, so the certificate
                        can be used for either.

               --subjectName <subjectName> The subject name, explicitly specified. e.g. "/CN=www.example.com"
               --key-usage <usage>  Give it the given keyUsage (e.g. "digitalSignature, nonRepudiation"; note that this must be comma separated
                                    and will likely need to be quoted. To make it critical, add "critical, digitalSignature" etc.
                                    (Per RFC5280 a conforming CA SHOULD mark this as critical)
               --extended-key-usage <usage> Give it the extended key usage. Specification rules are similar to --key-usage.
               --extension <extensionSpec> Any, generic openssl x509v3 extension specification:
                             e.g. "subjectAltName=DNS:www.example.com" or "nameConstraints=critical, excluded;email:.com"
                             Multiple --extension arguments may be provided
               --key <key-type>:<key-args>
                        Generate a private key of type "<key-type>", which can be "rsa", "dh", "dsa", or "ec". The valid values of <key-args>
                        depend on <key-type>. For "rsa", "dh" and "dsa" it is the number of bits in the key, e.g. "1024". For "ec" it is the name
                        of the curve (see openssl ecparam -list_curves). Defaults to $keySpec
                        Examples: "dsa:1024" or "ec:secp521r1" 
               --startdate <date>
               --enddate <date>
                        Respectively, the start and end dates of the certificate. Needs to be provided in the format that openssl needs. See ca(1) man page.
                        (Doesn't work with DH keys. You just get a certificate that starts now and goes for a year)

             <entityName> The entity we are creating certs for. e.g. "root1" or "intermediateCa3" or "web-server" or "signer"
                        This name is only used to create the subdirectory that holds the structure of files for this entity. It has
                        nothing to do with any contents of the certs for this entity. This name is used by the script to refer to this
                        entity in other invocations
             <commonName> The common name to use for the subject of the cert (unless --subjectName is explicitly specified)
             <parentCa> The CA entity to use as a parent. Must have a substructure created via makeCerts <parentCa> ...
                        "" if no parentCa, meaning this is a self-signed cert

        Examples:
           makeCerts --ca root1 "Root One" <--- make a root CA called 'root1', subject name is /..../CN=Root\ One
           makeCerts --ca intermediateCa3 "Intrmdt CA" root1  <-- make an intermediate CA using root1 as the CA that signs this CA's cert
           makeCerts --server "web-server "foo.bar.com" intermediateCa3 server_cert <-- make a TLS server cert for web-server using intermediateCA to sign this cert
           makeCerts --key-usage "critical, digitalSignature" signer "Signer" "" <-- make a self-signed object signing cert
EOF
     exit 0
     ;;
    *)
     echo "ERROR: Unknown option: $opt" >&2
     exit 1
     ;;
  esac
done

if [[ $# -lt 2 || $# -gt 3 ]]
then
  echo "Incorrect Usage. Check --help" >&2
  exit 1
fi

entityName="$1"
commonName="$2"
parentCa="$3"

: ${entityName:?ERROR: Must provide entity name}

subjectName="${subjectName:-$subjectPrefix/CN=$commonName}"

if [[ -n "$parentCa" ]]
then
  if [[ ! -d $parentCa || ! -r $parentCa ]]
  then
    echo "Parent CA directory must be readable" >&2
    exit 1
  fi
fi


if [[ -z "$parentCa" ]]
then
  if [[ -n "$keyUsage" && ",$(sed 's/ //g' <<< $keyUsage)," != *"keyCertSign," ]]
  then
    # Per RFC4280, this should NOT be done for non-CAs,
    # but openssl doesn't verify self-signed root certs
    # that do not have this usage set
    # Fortunately, it lets us set this for non-CA certs
    echo "WARNING: This is a root certificate, but it does not specify keyCertSign as a keyUsage. Expect verification problems with openssl"
  fi
fi

# Validate, and get the key type and key type arguments
# First, get the key type, rsa, dsa, ec etc.
: ${keySpec:?ERROR: Empty --key specification}
keyType=${keySpec%%:*}
# And, then any arguments for that type of key
keyArg=${keySpec#*:}
: ${keyArg:?ERROR: No argument specified in --key $keySpec}


mkdir $entityName
cd $entityName

# Make subdirs
mkdir certs private ca-stuff
chmod 700 private
pushd ca-stuff
  # This is going to be a CA, add more stuff
  mkdir crl newcerts
  touch index.txt
  touch index.txt.attr
  echo 1000 > serial
  echo 1000 > crlnumber
  cat <<OPENSSL-CONFIG-END >openssl.cnf
[ ca ]
default_ca = CA_default
prompt = no


[ CA_default ]
# Directory and file locations.
dir               = $(dirname $(pwd))
certs             = \$dir/certs
crl_dir           = \$dir/ca-stuff/crl
new_certs_dir     = \$dir/ca-stuff/newcerts
database          = \$dir/ca-stuff/index.txt
serial            = \$dir/ca-stuff/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/private/key.pem
certificate       = \$dir/certs/cert.pem

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
unique_subject    = no
policy            = policy_sec
copy_extensions   = copy

[ policy_sec ]
commonName              = supplied
countryName             = optional
stateOrProvinceName     = optional
organizationName        = optional
organizationalUnitName  = optional
emailAddress            = optional

[ x509_ext ]
basicConstraints = critical, CA:\$ENV::isCA
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

OPENSSL-CONFIG-END
popd



# Generate the private key.

# Special case for DH. We will have to create a "fake" RSA key and cert etc. This is because DH can't create a csr. Then, we
# will resign the certificate with the dh parameter

if [[ "$keyType" == "dh" ]]
then
  if [[ -z "$parentCa" ]]
  then
    echo "ERROR: Can't use DH for selfsigned certs" >&2
    exit 1
  fi
  openssl dhparam -out private/dhparam.pem "$keyArg"
  openssl genpkey -paramfile private/dhparam.pem -out private/dhkey.pem
  openssl pkey -in private/dhkey.pem -pubout -out certs/dhpubkey.pem
  dh=yes
  keyType=rsa
fi

if [[ "$keyType" == "rsa" ]]
then
  openssl genrsa -out private/key.pem "$keyArg"
elif [[ "$keyType" == "dsa" ]]
then
  openssl dsaparam -genkey "$keyArg" -out private/key.pem
elif [[ "$keyType" == "ec" ]]
then
  openssl ecparam -name "$keyArg" -genkey -param_enc named_curve -out private/key.pem
else
  echo "ERROR: Invalid key type in --key $keySpec"
  exit 1
fi

# Even if we are making a self-signed cert, we first have to make a CSR and sign it
# using ca -selfsign. Coz that way we get more control over the final certificate
# than 'req -x509'
# Also DSA does not support sha512, that's why we use sha256
openssl req -new \
     -key private/key.pem \
     -subj "$subjectName" \
     -out private/csr.pem \
     -sha256 -utf8 -multivalue-rdn \
     -reqexts req_ext \
     -config <(cat <<-OPENSSL-CONFIG-END 
[ req ]
distinguished_name  = req_distinguished_name
string_mask         = utf8only

[ req_distinguished_name ]
countryName                     = Country Name
countryName_default             = XX

[ req_ext ]
$keyUsage
$extendedKeyUsage
$extensions

OPENSSL-CONFIG-END
)


if [[ -z "$parentCa" ]]
then
  selfsign="-selfsign"
  signerDir=.
else
  selfsign=
  signerDir=../$parentCa
fi

# DSA does not support sha512, that's why force sha256
isCA=$isCA openssl ca \
     -extensions x509_ext \
     $startdate $enddate \
     -notext -md sha256 \
     -preserveDN -multivalue-rdn -utf8 \
     -batch $selfsign \
     -in private/csr.pem \
     -out certs/cert.pem \
     -config $signerDir/ca-stuff/openssl.cnf

if [[ -z "$parentCa" ]]
then
  cp certs/cert.pem certs/chain.pem

  # Verify, but only for information!
  openssl verify -CAfile certs/cert.pem certs/cert.pem || true
else
  ln -s ../$parentCa parentCa

  # If DH, then we aren't done yet!
  if [[ -n "$dh" ]]
  then
    # Reset keyType
    keyType=dh
    # Resign the certificate, using x509 utility, which forces us to use a given public key.
    openssl x509 -req -in private/csr.pem -CAkey ../$parentCa/private/key.pem -CA ../$parentCa/certs/cert.pem -force_pubkey certs/dhpubkey.pem -CAserial ../$parentCa/ca-stuff/serial -out certs/dhcert.pem -days 365 -extensions x509_ext -extfile <(cat <<-OPENSSL-CONFIG-END
[ x509_ext ]
basicConstraints = critical, CA:$isCA
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
$keyUsage
$extendedKeyUsage
$extensions

OPENSSL-CONFIG-END
)

    # Use the DH key and cert as the new bits
    mv private/dhkey.pem private/key.pem
    mv certs/dhcert.pem certs/cert.pem
    # TODO: patch up CA's database
  fi

  cat certs/cert.pem ../$parentCa/certs/chain.pem > certs/chain.pem

  # Verify, but only for information!
  # First, we find the single root CA cert. That is our "truststore"
  root=parentCa
  while [[ -L "$root/parentCa" ]]
  do
    root="$root/parentCa"
  done
  
  # Using the root as the trust, verify the newly generated cert.
  # Use the entire parent's chain as untrusted intermediary certs.
  # This flag is not necessary if this current cert's parent is the root.
  # The chain also contains the (trusted) root cert.
  # However, both of these don't hurt!
  openssl verify -CAfile "$root/certs/cert.pem" -untrusted parentCa/certs/chain.pem certs/cert.pem || true
fi

# Convenience concatenations of private key with cert/chain
cat private/key.pem certs/chain.pem > private/key-chain.pem
cat private/key.pem certs/cert.pem > private/key-cert.pem

# Note, this is the single cert for this entity, not the entire chain rooted at a self-signed cert
keytool -import -alias ca -file certs/cert.pem -keystore certs/truststore.jks -storepass password -noprompt

# Java doesn't do DH private keys!
if [[ "$keyType" != "dh" ]]
then
  openssl pkcs12 -export -in certs/chain.pem -inkey private/key.pem -out private/keystore.p12 -passout pass:password
  keytool -importkeystore -srckeystore private/keystore.p12 -srcstoretype pkcs12 -destkeystore private/keystore.jks -deststorepass password -srcstorepass password
fi

chmod 444 certs/*.pem
chmod 400 private/*.pem
