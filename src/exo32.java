import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;


public class exo32 {
    public boolean validatecertchain(String[] args) {
        String Format=args[2];
        String certtoconv=null;
        //Prépare la liste des certificats
        ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
        for (int i=3; i<args.length; i++) {
            if (Format.equals("PEM")) {
                certtoconv=args[i]+".crt";
            } else if (Format.equals("DER")) {
                certtoconv=args[i]+".crt";
            } else {
                System.out.println("Unknown certificate format");
                return false;
            }
            try (InputStream inStream = new FileInputStream(certtoconv)) {
                CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inStream);
                certList.add(cert);
                System.out.println("\n================================\nCertificate "+ cert.getSubjectX500Principal() + ":\n===========================================\n" + cert);
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                    return false;
                }
        };
        //3.2.1
        // Coder la validation récursive de la chaîne de certificats en vérifiant toutes les signatures comme ci-dessus
        // et la correspondance des sujets et des émetteurs.
        System.out.println("\n======================================\nVerification, signatures & Issuer=Emetteur\n======================================");
        for (int i = certList.size() - 1; i >= 0; i--) {
            X509Certificate currentCert = certList.get(i);
            X509Certificate issuerCert;
            // SI root, alors l'issuer c'est lui même
            if (i == 0) {
                issuerCert = currentCert;
            } else {
                issuerCert = certList.get(i - 1);
            }
            if (certList.get(i).getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                "\n| VALIDE => Issuer = Emetteur\n| Issuer : "+ currentCert.getIssuerX500Principal()+
                "\n| Emetteur : "+ issuerCert.getSubjectX500Principal());
            } else {
                System.out.println("Certificat " + currentCert.getSubjectX500Principal() + " est invalide : Issuer != Emetteur");
                return false;
            }
            try {
                // Vérification de la signature du certificat avec la commande Java
                //currentCert.verify(issuerCert.getPublicKey());
                //System.out.println("| OK : Signature VALIDE");
            } catch (Exception e) {
                System.out.println("| KO : Signature INVALIDE : \n| Raison : " + e.getMessage());
                return false;
            }
            try{
                byte[] tbsData;
                tbsData = currentCert.getTBSCertificate();
                String certSignAlg = currentCert.getSigAlgName();
                Signature sign = null;
                switch (certSignAlg) {
                    case "SHA256withRSA":
                        sign  = Signature.getInstance("SHA256withRSA");
                        break;
                    case "SHA384withRSA":
                        sign = Signature.getInstance("SHA384withRSA");
                        break;
                    case "SHA512withRSA":
                        sign = Signature.getInstance("SHA512withRSA");
                        break;
                    case "SHA256withECDSA":
                        sign = Signature.getInstance("SHA256withECDSA");
                        break;
                    case "SHA384withECDSA":
                        sign = Signature.getInstance("SHA384withECDSA");
                        break;
                    case "SHA512withECDSA":
                        sign = Signature.getInstance("SHA512withECDSA");
                        break;
                    default:
                        System.out.println("| Algorithme de Signature Inconnu");
                        return false;
                }
                if (sign != null) {
                sign.initVerify(issuerCert.getPublicKey());
                sign.update(tbsData);
                boolean isSignValid = sign.verify(currentCert.getSignature());
                if (isSignValid){
                    System.out.println("| Signature "+ certSignAlg +" Valide\n");
                }else{
                    System.out.println("| Signature Invalide / Algorithme : " +certSignAlg);
                    //return false;
                }
                }else{
                    System.out.println("| Aucune signature dans ce certificat");
                    return false;
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                return false;
            }
    }
        //3.2.2 
        //Effectuer la vérification de signature RSA en utilisant une API de calcul sur les grands nombres au lieu
        //d'une API de cryptographie
        System.out.println("\n======================================\nVerification RSA/ECDSA Signature\n======================================");     
        for (int i = certList.size() - 1; i >= 0; i--) {
            X509Certificate currentCert = certList.get(i);
            X509Certificate issuerCert;
            if (i == 0) {
                issuerCert = currentCert;
            } else {
                issuerCert = certList.get(i - 1);
            }
            if (currentCert.getSigAlgName().contains("RSA")) {
                System.out.println("\n======================================\nSignature RSA\n======================================");   
                    boolean validRSA = verifyRSASignature(currentCert,(RSAPublicKey) issuerCert.getPublicKey());
                    if (!validRSA) {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature RSA invalide");
                        //return false;
                    } else {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature RSA valide");
                    }
            }
            //3.2.3
            //. Effectuer la vérification de signature ECDSA en utilisant une librairie de calcul sur courbe elliptique en
            //plus de celle sur les grands nombres (par exemple org.bouncycastle.math.ec.ECPoint) au lieu d'une API de cryptographie.
            else if (currentCert.getSigAlgName().contains("ECDSA")) {
                System.out.println("\n======================================\nSignature ECDSA\n======================================");   
                if (Security.getProvider("BC") == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
                boolean validECDSA = verifyECDSASignature(currentCert, (java.security.interfaces.ECPublicKey) issuerCert.getPublicKey());
                if (!validECDSA) {
                    System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                    " possède une signature ECDSA invalide");
                    //return false;
                } else {
                    System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                    " possède une signature ECDSA valide");
                }
            }else{
                System.out.println("Algorithme de signature non supporté");
                return false;
            }
        }
        //3.2.4 + 3.2.5
        //Ajuster la vérification de l'extension KeyUsage suivant le niveau de certificat.
        //Effectuer la vérification de l'extension BasicConstraints.
        System.out.println("\n======================================\nVerification Key Usage + Basic Constraints\n======================================");
        for ( X509Certificate cert : certList ) {
            //Root
            boolean[] keyUsage = cert.getKeyUsage();
            int basicConstraints = cert.getBasicConstraints();
            if (basicConstraints == Integer.MAX_VALUE) {
                if ((keyUsage[5] && keyUsage[6]) || (keyUsage[5] && keyUsage[6] && keyUsage[7])){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'une CA ROOT\n| Basic Constraints attendu Integer.MAX_VALUE (2147483647) : 2147483647 : "+basicConstraints+"\nKeyUsages attendu (TRUE, TRUE, OPTIONNAL) : \n| Key_CertSign : " + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6] +"\n| Digital_Signature : " + keyUsage[7]);
                } else{
                System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + "ne possède pas les keyusages d'une certificate authority ROOT\n| Basic Constraints attendu Integer.MAX_VALUE (2147483647) : "+basicConstraints+"\nKeyUsages attendu (TRUE,TRUE,OPTIONNAL)\n| Key_CertSign : " 
                    + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6]+"\n| Digital_Signature : " + keyUsage[7]);
                return false;
                }
            }
            //Sub-CA
            else if (basicConstraints >= 0) {
                if(keyUsage[5] && keyUsage[6]){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'une CA\n| Basic Constraints attendu >=0 : "+basicConstraints+"\nKeyUsages attendu (TRUE, TRUE) \n| Key_CertSign : " 
                    + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6]);
            }else{
                System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " ne possède pas les keyusages pour une CA\n| Basic Constraints attendu >=0 : "+basicConstraints+"\nKeyUsages attendu (TRUE,TRUE)\n| Key_CertSign : " 
                    + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6]);
                return false;
            }
            }
            //Cert Serveur
            else if (basicConstraints == -1) {
                if(keyUsage[0] || (keyUsage[0] && keyUsage[2])){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'un certificat serveur standard\n| Basic Constraints attendu = -1 : "+basicConstraints+"\nKeyUsages attendu (TRUE, OPTIONNAL)\n| DigitalSignature : " 
                    + keyUsage[0] + "\n| KeyEncipherment : " +keyUsage[2]);
            }else{
                System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + "ne possède pas les keyusages pour un certificat serveur standard\n| Basic Constraints attendu = -1 : "+basicConstraints+"\nKeyUsages attendu (TRUE,OPTIONNAL)\n| DigitalSignature : " 
                    + keyUsage[0] + "\n| KeyEncipherment : " +keyUsage[2]);
                return false;
                }
            }else{
                System.out.println("Basic Constraints invalide");
                return false;}
            }
            return true;
        }

    //fonction pour vérifier la signature RSA
    //La seule avec ECDSA ayant des commentaires poussés vu que la démarche est un peu plus importante que le reste
    public boolean verifyRSASignature(X509Certificate cert, RSAPublicKey pubKey) {
        try {
            // Récupération des données du certificat qui ont été signées (TBS : To Be Signed)
            byte[] tbsCertData = cert.getTBSCertificate();
            // Récupération de la signature du certificat
            byte[] signatureBytes = cert.getSignature();

            // Déterminer l'algorithme de hachage utilisé dans la signature
            String hashAlgorithm;
            switch (cert.getSigAlgName()) {
                case "SHA256withRSA":
                    hashAlgorithm = "SHA-256";
                    break;
                case "SHA384withRSA":
                    hashAlgorithm = "SHA-384";
                    break;
                case "SHA512withRSA":
                    hashAlgorithm = "SHA-512";
                    break;
                default:
                    System.out.println("Unsupported signature algorithm: " + cert.getSigAlgName());
                    return false;
            }

            // Calcul du hash des données signées
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(tbsCertData);
            byte[] digestValue = md.digest();

            // Conversion de la signature en BigInteger pour effectuer l'opération RSA
            BigInteger signature = new BigInteger(1, signatureBytes);
            BigInteger modulus = pubKey.getModulus();
            BigInteger exponent = pubKey.getPublicExponent();

            // Taille du module en octets
            int modulusSize = (modulus.bitLength() + 7) / 8;

            // Déchiffrement de la signature RSA avec la clé publique (signature^e mod n)
            BigInteger decryptedSignature = signature.modPow(exponent, modulus);
            byte[] decryptedBytes = new byte[modulusSize];
            byte[] bigIntBytes = decryptedSignature.toByteArray();

            // Gestion du padding car BigInteger déteste les début de 0
            int copyOffset = 0;
            if (bigIntBytes.length > modulusSize) {
                copyOffset = bigIntBytes.length - modulusSize;
            }
            int destOffset = modulusSize - Math.min(modulusSize, bigIntBytes.length - copyOffset);
            int length = Math.min(modulusSize, bigIntBytes.length - copyOffset);
            System.arraycopy(bigIntBytes, copyOffset, decryptedBytes, destOffset, length);

            // Recherche du début de la structure DigestInfo (format PKCS#1 v1.5)
            int digestInfoStart = -1;
            for (int i = 0; i < decryptedBytes.length - 1; i++) {
                if (decryptedBytes[i] == 0x00 && decryptedBytes[i + 1] == 0x30) {
                    digestInfoStart = i + 1;
                    break;
                }
            }
            if (digestInfoStart == -1) {
                System.out.println("Digest info struct absente de la signature décrypté");
                return false;
            }

            // Extraction de la structure DigestInfo
            byte[] digestInfo = new byte[decryptedBytes.length - digestInfoStart];
            System.arraycopy(decryptedBytes, digestInfoStart, digestInfo, 0, digestInfo.length);

            // Déterminer la taille du hash attendu
            int hashLength;
            switch (hashAlgorithm) {
                case "SHA-256":
                    hashLength = 32;
                    break;
                case "SHA-384":
                    hashLength = 48;
                    break;
                case "SHA-512":
                    hashLength = 64;
                    break;
                default:
                    System.out.println("Algo de hash pas supporté : " + hashAlgorithm);
                    return false;
            }

            // Trouver la position du hash dans la structure DigestInfo
            int hashPosition = -1;
            for (int i = 0; i < digestInfo.length - hashLength; i++) {
                if (digestInfo[i] == 0x04 && digestInfo[i + 1] == hashLength) {
                    hashPosition = i + 2;
                    break;
                }
            }
            if (hashPosition == -1) {
                System.out.println("Impossible de trouver le hash du digestInfo");
                return false;
            }

            // Extraction du hash contenu dans DigestInfo
            byte[] extractedHash = new byte[hashLength];
            System.arraycopy(digestInfo, hashPosition, extractedHash, 0, hashLength);

            // Comparaison du hash calculé avec celui extrait de la signature
            return MessageDigest.isEqual(digestValue, extractedHash);

        } catch (Exception e) {
            System.out.println("Erreur lors de la vérification de la signature : " + e.getMessage());
            return false;
        }
    }

    //fonction pour vérifier ECDSA
    public boolean verifyECDSASignature(X509Certificate cert, java.security.interfaces.ECPublicKey issuerPublicKeytoformat) {
        // Récupération des paramètres de la clé publique en format JDK
        java.security.spec.ECParameterSpec jdkSpec = issuerPublicKeytoformat.getParams();

        // Conversion des paramètres EC en format Bouncy Castle
        org.bouncycastle.jce.spec.ECParameterSpec bcSpec = EC5Util.convertSpec(jdkSpec);
        java.security.spec.ECPoint jdkQ = issuerPublicKeytoformat.getW();
        ECPoint bcQ = EC5Util.convertPoint(bcSpec.getCurve(), jdkQ);

        // Conversion de la clé publique dans un format compatible Bouncy Castle
        ECPublicKey ECissuerPublicKey = new JCEECPublicKey(
            "ECDSA",
            new org.bouncycastle.jce.spec.ECPublicKeySpec(bcQ, bcSpec)
        );

        try {
            // Extraction des données à signer du certificat
            byte[] tbsCertData = cert.getTBSCertificate();
            // Extraction de la signature
            byte[] signatureBytes = cert.getSignature();

            // Déterminer l'algorithme de hachage utilisé dans la signature
            String hashAlgorithm;
            switch (cert.getSigAlgName()) {
                case "SHA256withECDSA":
                    hashAlgorithm = "SHA-256";
                    break;
                case "SHA384withECDSA":
                    hashAlgorithm = "SHA-384";
                    break;
                case "SHA512withECDSA":
                    hashAlgorithm = "SHA-512";
                    break;
                default:
                    System.out.println("Unsupported signature algorithm: " + cert.getSigAlgName());
                    return false;
            }

            // Calcul du hash des données signées
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(tbsCertData);
            byte[] digestValue = md.digest();
            BigInteger e = new BigInteger(1, digestValue); // Valeur de e dans l'équation ECDSA

            // Décodage de la signature ASN.1 en (r, s)
            ASN1InputStream aIn = new ASN1InputStream(signatureBytes);
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
            aIn.close();

            // Récupération des paramètres EC
            ECParameterSpec ecParams = ((ECPublicKey) ECissuerPublicKey).getParameters();
            ECPoint G = ecParams.getG(); // Générateur de la courbe
            BigInteger n = ecParams.getN(); // Ordre du générateur
            ECPoint Q = ((ECPublicKey) ECissuerPublicKey).getQ(); // Clé publique du signataire

            // Vérification que s est bien dans l'intervalle valide [1, n-1]
            if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) {
                return false;
            }

            // Calcul des paramètres u1 et u2
            BigInteger w = s.modInverse(n); // w = s^(-1) mod n
            BigInteger u1 = e.multiply(w).mod(n); // u1 = e * w mod n
            BigInteger u2 = r.multiply(w).mod(n); // u2 = r * w mod n

            // Calcul des points correspondants
            ECPoint point1 = G.multiply(u1); // u1 * G
            ECPoint point2 = Q.multiply(u2); // u2 * Q
            ECPoint R = point1.add(point2); // R = u1 * G + u2 * Q

            // Vérification que R n'est pas le point à l'infini
            if (R.isInfinity()) {
                return false;
            }

            // Récupération de la coordonnée x normalisée et réduction modulo n
            BigInteger v = R.normalize().getXCoord().toBigInteger().mod(n);

            // La signature est valide si v == r
            return v.equals(r);

        } catch (Exception e) {
            System.out.println("Erreur lors de la vérification de la signature ECDSA : " + e.getMessage());
            return false;
        }
    }
}

