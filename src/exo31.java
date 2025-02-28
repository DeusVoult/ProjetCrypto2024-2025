import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

public class exo31 {
    String filename=null;
    X509Certificate cert=null;
    //publickey=null;
    public boolean validatecert(String[] args) {
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
            cert = (X509Certificate) certificateFactory.generateCertificate(inStream);
            //publickey=cert.getPublicKey();
            System.out.println("CERTIFICATE :\n" + cert);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
