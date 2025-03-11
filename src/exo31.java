import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.util.Date;

public class exo31 {
    String filename=null;
    public boolean validatecert(String[] args) {
        //3.1.1
        switch(args[2]){
            case "PEM":
                filename=args[3]+".crt";
                break;
            case "DER":
                filename=args[3]+".der";
                break;
            default :
                System.out.println("Unknown certificate format");
                return false;
        }
        try (InputStream inStream = new FileInputStream(filename)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inStream);
            if (cert!=null) {
                System.out.println("CERTIFICATE :\n" + cert);
                //3.1.2
                PublicKey publicKey=cert.getPublicKey();
                try {
                    cert.verify(publicKey);
                    System.out.println("OK | Certificat Valide");
                } catch (Exception e) {
                    System.out.println("KO | Certificat invalide: " + e.getMessage());
                    return false;
                }
                //3.1.3
                System.out.println("\nSujet : " + cert.getSubjectX500Principal());
                System.out.println("Emetteur : " + cert.getIssuerX500Principal());   
                //3.1.4
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage !=null){
                    if ((keyUsage[5] && keyUsage[6]) || (keyUsage[5] && keyUsage[6] && keyUsage[7])){
                        System.out.println("\nKeyUsage Valide : \nKey_CertSign : " + keyUsage[5] + "\nCrl_Sign : " +keyUsage[6] +"\nDigital_Signature : " + keyUsage[7]);
                    } else{
                        System.out.println("KeyUsage Invalide");
                        return false;
                    }
                }
                //3.1.5
                Date notBefore = cert.getNotBefore();
                Date notAfter = cert.getNotAfter();
                Date Actuel = new Date();
                if (Actuel.after(notBefore) && Actuel.before(notAfter)){
                    System.out.println("Certificat Toujours valide jusqu'au : " + notAfter);
                }else{
                    System.out.println("Certificat Expiré");
                    return false;
                }
                //3.1.6
                byte[] tbsData = cert.getTBSCertificate();
                String certSignAlg = cert.getSigAlgName();
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
                        System.out.println("Algorithme de Signature Inconnu");
                        return false;
                }
                if (sign != null) {
                sign.initVerify(publicKey);
                sign.update(tbsData);
                boolean isSignValid = sign.verify(cert.getSignature());
                if (isSignValid){
                    System.out.println("Signature "+ certSignAlg +" Valide");
                }else{
                    System.out.println("Signature Invalide");
                    return false;
                }
                }else{
                    System.out.println("Aucune signature dans ce certificat");
                }
            }else{
                System.out.println("Certificate est nulle");
                return false;
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
