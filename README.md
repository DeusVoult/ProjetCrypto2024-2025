# Commande

## Certificats lemonde verif RootCA
```
java -cp "bin;lib/*" App validate-cert -format PEM X509/lemonde/GlobalSign  
```

## Certificats lemonde verif chain (RSA)
```
java -cp "bin;lib/*" App validate-cert-chain -format PEM X509/lemonde/GlobalSign x509/lemonde/GlobalSignAtlasR3DVTLSCA2024Q4 x509/lemonde/_.lemonde.fr
```
## Certificats tbscertificate verif chain (ECDSA)
```
java -cp "bin;lib/*" App validate-cert-chain -format PEM X509/tbs-certificate/USERTrustECCCertificationAuthority x509/tbs-certificate/SectigoQualifiedWebsiteAuthenticationCAE35 x509/tbs-certificate/www.tbs-certificats.com
```