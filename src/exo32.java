import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.math.BigInteger;
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
                System.out.println("\n================================\nCertificate "+ (i-2) + ":\n===========================================\n" + cert);
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                    return false;
                }
        };
        //3.2.1
        //check le reste de la chaine en commencant par la fin de la liste pour être dans le bon sens (sauf ROOT car spécial)
        for (int i = certList.size() - 1; i > 0; i--) {
            try {
                certList.get(i).verify(certList.get(i - 1).getPublicKey());
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                return false;
            }
            if (certList.get(i).getIssuerX500Principal().equals(certList.get(i - 1).getSubjectX500Principal())) {
                System.out.println("\n======================================\nCertificat " + certList.get(i).getSubjectX500Principal() + 
                "\n| VALIDE => Issuer = Emetteur\n| Issuer : "+ certList.get(i).getIssuerX500Principal()+
                "\n| Emetteur : "+ certList.get(i-1).getSubjectX500Principal());
            } else {
                System.out.println("Certificat " + certList.get(i).getSubjectX500Principal() + " est invalide");
                return false;
            }
        }
        //Check root 
        // check certificat root
        try {
            certList.get(0).verify(certList.get(0).getPublicKey());
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return false;
        }
        if (certList.get(0).getIssuerX500Principal().equals(certList.get(0 ).getSubjectX500Principal())) {
            System.out.println("\n======================================\nCertificat ROOT "+ 
            certList.get(0).getSubjectX500Principal()+
            "\n| VALIDE => Issuer = Emetteur\n| Issuer : "+ certList.get(0).getIssuerX500Principal()+
            "\n| Emetteur : "+ certList.get(0).getSubjectX500Principal());
        } else {
            System.out.println("Certificate Root invalide");
            return false;
        }        
        //3.2.2 Vérification Signature avec BigInteger
        //cas du certificat root

        //reste 
        for (int i = certList.size() - 1; i > 0; i--) {}
        return true;
    }
}
