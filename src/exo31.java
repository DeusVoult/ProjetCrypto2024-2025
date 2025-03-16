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
        // Coder la prise en compte des arguments de la ligne de commande, la lecture du fichier au format DER ou PEM
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
        //Création d'un objet de classe java.security.cert.X509Certificate
        try (InputStream inStream = new FileInputStream(filename)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inStream);
            //Début des test avec l'objet crée
            if (cert!=null) {
                System.out.println("\n======================================\nAffichage du certificat a traité\n======================================\n");
                System.out.println("CERTIFICATE :\n" + cert);
                //3.1.2
                //Ajouter l'extraction de la clef publique du certificat auto-signé et la vérification de la signature avec java.security.cert.X509Certificate.verify(PublicKey key).
                System.out.println("\n=============================================\nVerification de la signature pub key\n=============================================\n");
                PublicKey publicKey=cert.getPublicKey();
                try {
                    System.out.println("| Certificat : " + cert.getSubjectX500Principal());
                    cert.verify(publicKey);
                    System.out.println("| OK : Signature VALIDE");
                } catch (Exception e) {
                    System.out.println("| KO : Signature INVALIDE : \n| Raison : " + e.getMessage());
                    return false;
                }
                //3.1.3
                //Afficher le sujet et l'émetteur du certificat.
                System.out.println("\n======================================\nVerification de la signature\n======================================\n");
                System.out.println("| Sujet : " + cert.getSubjectX500Principal());
                System.out.println("| Emetteur : " + cert.getIssuerX500Principal());    
                //3.1.4
                //Vérifier l'extension KeyUsage.
                System.out.println("\n======================================\nVerification des Keys Usages\n======================================\n");
                boolean[] keyUsage = cert.getKeyUsage();
                if (keyUsage !=null){
                    if ((keyUsage[5] && keyUsage[6]) || (keyUsage[5] && keyUsage[6] && keyUsage[7])){
                        System.out.println("KeyUsage Attendus (TRUE, TRUE, OPTIONNAL) : \n| Key_CertSign : " + keyUsage[5] + "\n| Crl_Sign : " +keyUsage[6] +"\n| Digital_Signature : " + keyUsage[7]);
                    } else{
                        System.out.println("KeyUsage Invalide");
                        return false;
                    }
                }else {
                    System.out.println("KeyUsage Invalide");
                    return false;
                }
                //3.1.5
                //Vérifier la période de validité.
                System.out.println("\n========================================\nVerification de la période de validité\n========================================\n");
                Date notBefore = cert.getNotBefore();
                Date notAfter = cert.getNotAfter();
                Date Actuel = new Date(); 
                if (Actuel.after(notBefore) && Actuel.before(notAfter)){
                    System.out.println("| Certificat toujours valide jusqu'au : " + notAfter);
                    System.out.println("| Date Actuel : " + Actuel);
                }else{
                    System.out.println("| Certificat Expiré");
                    System.out.println("| Certificat  valide jusqu'au : " + notAfter);
                    System.out.println("| Date Actuel : " + Actuel);
                    return false;
                }
                //3.1.6
                // Extraire l'algorithme de signature du certificat ainsi que la signature. 
                //Vérifier celle-ci avec l'API cryptographique (Signature.verify(byte[ ])). Notez que vous devrez traiter les signatures RSA et ECDSA.
                System.out.println("\n===========================================================\nVerification de l'algorithme de signature et la signature\n===========================================================\n");
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
                        System.out.println("| Algorithme de Signature Inconnu");
                        return false;
                }
                if (sign != null) {
                sign.initVerify(publicKey);
                sign.update(tbsData);
                boolean isSignValid = sign.verify(cert.getSignature());
                if (isSignValid){
                    System.out.println("| Signature "+ certSignAlg +" Valide\n");
                }else{
                    System.out.println("| Signature Invalide");
                    return false;
                }
                }else{
                    System.out.println("| Aucune signature dans ce certificat");
                    return false;
                }
            }else{
                System.out.println("| Certificate est nulle");
                return false;
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
