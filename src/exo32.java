import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
//import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;


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
        //check le reste de la chaine en commencant par la fin de la liste pour être dans le bon sens (sauf ROOT car spécial)
        System.out.println("\n======================================\nVerify Issuer Emetteur\n======================================");
        for (int i = certList.size() - 1; i >= 0; i--) {
            X509Certificate currentCert = certList.get(i);
            X509Certificate issuerCert;
            // SI root, alors l'issuer c'est lui même
            if (i == 0) {
                issuerCert = currentCert;
            } else {
                issuerCert = certList.get(i - 1);
            }
            try {
                currentCert.verify(issuerCert.getPublicKey());
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                return false;
            }
            if (certList.get(i).getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                "\n| VALIDE => Issuer = Emetteur\n| Issuer : "+ currentCert.getIssuerX500Principal()+
                "\n| Emetteur : "+ issuerCert.getSubjectX500Principal());
            } else {
                System.out.println("Certificat " + currentCert.getSubjectX500Principal() + " est invalide : Issuer != Emetteur");
                return false;
            }
        }
        System.out.println("\n======================================\nVerify Signature\n======================================");     
        //3.2.2 Vérification Signature RSA avec BigInteger
        for (int i = certList.size() - 1; i >= 0; i--) {
            X509Certificate currentCert = certList.get(i);
            X509Certificate issuerCert;
            // SI root, alors l'issuer c'est lui même
            if (i == 0) {
                issuerCert = currentCert;
            } else {
                issuerCert = certList.get(i - 1);
            }
            if (currentCert.getSigAlgName().contains("RSA")) {
                    boolean validRSA = verifyRSASignature(currentCert,(RSAPublicKey) issuerCert.getPublicKey());
                    if (!validRSA) {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature RSA invalide");
                        return false;
                    } else {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature RSA valide");
                    }
                }else if (currentCert.getSigAlgName().contains("ECDSA")) {
                    boolean validECDSA = verifyECDSASignature(currentCert, (org.bouncycastle.jce.interfaces.ECPublicKey) issuerCert.getPublicKey());
                    if (!validECDSA) {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature ECDSA invalide");
                        return false;
                    } else {
                        System.out.println("\nCertificat " + currentCert.getSubjectX500Principal() + 
                                        " possède une signature ECDSA valide");
                    }
            }
        }
        //3.2.4 + 3.2.5
        System.out.println("\n======================================\nVerify Key Usage + Basic Constraints\n======================================");
        for ( X509Certificate cert : certList ) {
            //Root
            boolean[] keyUsage = cert.getKeyUsage();
            int basicConstraints = cert.getBasicConstraints();
            if (basicConstraints == Integer.MAX_VALUE) {
                if(keyUsage[5] && keyUsage[6]){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'une certificate authority ROOT\n| Basic Constraints attendu Integer.MAX_VALUE (2147483647) : "+basicConstraints+"\n| Key_CertSign : " 
                    + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6]);
            }else{
                System.out.println("Certificat "+ cert.getSubjectX500Principal() + " ne possède pas les keyusages d'une certificate authority ROOT ou la valeur du basicConstraints est erronée");
                return false;
                }
            }
            //Sub-CA
            else if (basicConstraints >= 0) {
                if(keyUsage[5] && keyUsage[6]){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'une CA\n| Basic Constraints attendu >=0 : "+basicConstraints+"\n| Key_CertSign : " 
                    + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6]);
            }else{
                System.out.println("Certificat "+ cert.getSubjectX500Principal() + " ne possède pas les keyusages d'une CA ou la valeur du basicConstraints est erronée");
                return false;
            }
            }
            //End certificate
            else if (basicConstraints == -1) {
                if(keyUsage[0] && keyUsage[2]){
                    System.out.println("\nCertificat "+ cert.getSubjectX500Principal() + " possède bien les keyusages d'un certificat serveur standard\n| Basic Constraints attendu = -1 : "+basicConstraints+"\n| DigitalSignature : " 
                    + keyUsage[0] + "\n| KeyEncipherment : " +keyUsage[2]);
            }else{
                System.out.println("Certificat "+ cert.getSubjectX500Principal() + " ne possède pas les keyusages d'un certificat serveur standard ou la valeur du basicConstraints est erronée");
                return false;
                }
            }
            }
            return true;
        }
    
         // EXO 3.3

    //fonction pour vérifier la signature RSA
    public boolean verifyRSASignature(X509Certificate cert,RSAPublicKey pubKey) {
        try {
            // TBSCertificate data utile pour vérifier la signature
            byte[] tbsCertData = cert.getTBSCertificate();
            // signature du certificat
            byte[] signatureBytes = cert.getSignature();
            // On determine l'algorithme de hashage de l'algo de signature
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
            
            // Create MessageDigest with the appropriate algorithm
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(tbsCertData);
            byte[] digestValue = md.digest();
            
            // Convert signature to BigInteger
            BigInteger signature = new BigInteger(1, signatureBytes);
            
            // Get RSA components from public key
            BigInteger modulus = pubKey.getModulus();
            BigInteger exponent = pubKey.getPublicExponent();
            
            // Calculate modulus size in bytes
            int modulusSize = (modulus.bitLength() + 7) / 8;
            
            // RSA verification: (signature^e) mod n
            BigInteger decryptedSignature = signature.modPow(exponent, modulus);
            
            // Convert to byte array with proper padding
            byte[] decryptedBytes = new byte[modulusSize];
            byte[] bigIntBytes = decryptedSignature.toByteArray();
            
            // Copy bytes properly to handle BigInteger's representation
            int copyOffset = 0;
            if (bigIntBytes.length > modulusSize) {
                // Skip leading zero if present (BigInteger format quirk)
                copyOffset = bigIntBytes.length - modulusSize;
            }
            
            int destOffset = modulusSize - Math.min(modulusSize, bigIntBytes.length - copyOffset);
            int length = Math.min(modulusSize, bigIntBytes.length - copyOffset);
            System.arraycopy(bigIntBytes, copyOffset, decryptedBytes, destOffset, length);
            
            // Search for DigestInfo ASN.1 SEQUENCE marker (0x30)
            int digestInfoStart = -1;
            for (int i = 0; i < decryptedBytes.length - 1; i++) {
                // Look for 0x00 followed by 0x30 (ASN.1 SEQUENCE tag)
                if (decryptedBytes[i] == 0x00 && decryptedBytes[i+1] == 0x30) {
                    digestInfoStart = i + 1;
                    break;
                }
            }
            
            if (digestInfoStart == -1) {
                System.out.println("Couldn't find DigestInfo structure in decrypted signature");
                return false;
            }
            
            // Extract DigestInfo
            byte[] digestInfo = new byte[decryptedBytes.length - digestInfoStart];
            System.arraycopy(decryptedBytes, digestInfoStart, digestInfo, 0, digestInfo.length);
            
            // Parse DigestInfo to extract the hash
            // For SHA-256, we need to extract the last 32 bytes
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
                    System.out.println("Unsupported hash algorithm");
                    return false;
            }
            
            // Find the hash in DigestInfo - it follows the OCTET STRING tag (0x04)
            int hashPosition = -1;
            for (int i = 0; i < digestInfo.length - hashLength; i++) {
                if (digestInfo[i] == 0x04 && digestInfo[i+1] == hashLength) {
                    hashPosition = i + 2;
                    break;
                }
            }
            
            if (hashPosition == -1) {
                System.out.println("Couldn't find hash value in DigestInfo");
                return false;
            }
            
            byte[] extractedHash = new byte[hashLength];
            System.arraycopy(digestInfo, hashPosition, extractedHash, 0, hashLength);
            
            // Comparaison du hash extrait et de celui calculé
            boolean hashesMatch = MessageDigest.isEqual(digestValue, extractedHash);
            //System.out.println("RSA signature verification: " + hashesMatch);
            return hashesMatch;
            
        } catch (Exception e) {
            System.out.println("Error during RSA signature verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    //fonction pour vérifier ECDSA
    
    public boolean verifyECDSASignature(X509Certificate cert, ECPublicKey issuerPublicKey) {
        try {
            byte[] tbsCertData = cert.getTBSCertificate();
            byte[] signatureBytes = cert.getSignature();
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
    
            // Calculate hash of tbsCertData
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            md.update(tbsCertData);
            byte[] digestValue = md.digest();
            BigInteger e = new BigInteger(1, digestValue);
    
            // Parse ASN.1 DER SEQUENCE for ECDSA signature
            ASN1InputStream aIn = new ASN1InputStream(signatureBytes);
            ASN1Sequence seq = (ASN1Sequence)aIn.readObject();
            BigInteger r = ((ASN1Integer)seq.getObjectAt(0)).getValue();
            BigInteger s = ((ASN1Integer)seq.getObjectAt(1)).getValue();
            aIn.close();
    
            // Get curve parameters from public key
            ECParameterSpec ecParams = ((ECPublicKey)issuerPublicKey).getParameters();
            ECPoint G = ecParams.getG();
            BigInteger n = ecParams.getN();
            ECPoint Q = ((ECPublicKey)issuerPublicKey).getQ();
    
            // Verify s is within range
            if (s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0) {
                return false;
            }
    
            // Calculate w = s^(-1) mod n
            BigInteger w = s.modInverse(n);
    
            // Calculate u1 = ew mod n
            BigInteger u1 = e.multiply(w).mod(n);
    
            // Calculate u2 = rw mod n
            BigInteger u2 = r.multiply(w).mod(n);
    
            // Calculate point (x,y) = u1G + u2Q
            ECPoint point1 = G.multiply(u1);
            ECPoint point2 = Q.multiply(u2);
            ECPoint R = point1.add(point2);
    
            // If R is infinity, signature is invalid
            if (R.isInfinity()) {
                return false;
            }
    
            // Convert R's x-coordinate to integer and reduce mod n
            BigInteger v = R.normalize().getXCoord().toBigInteger().mod(n);
    
            // Verify that v = r
            return v.equals(r);
    
        } catch (Exception e) {
            System.out.println("Error during ECDSA signature verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

}

