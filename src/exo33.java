import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.*;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;


public class exo33 {
    List<HashMap<Integer, CertInfo>> CertInfoCache = new ArrayList<HashMap<Integer,CertInfo>>();
    public class CertInfo {
        String crlUrl=null;
        File crlFile=null;
        String ocspUrl=null;
    }
    public boolean revokationcertchain(String[] args) {
        String Format=args[2];
        String certtoconv=null;
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
        }
        //3.3.1
        //Ajouter la vérification du status de révocation en téléchargeant la CRL pour chaque certificat (attention à vérifier la 
        //validité de la CRL dont sa signature).
        System.out.println("\n================================\nExtraction CRL URL\n================================\n");
        for (int i=0; i<3 ;i++){
            HashMap<Integer,CertInfo> cache = new HashMap<Integer,CertInfo>();
            CertInfo info = new CertInfo();
            try {
                // Extraire URL de la CRL
                System.out.println("> Certificat : " + certList.get(i).getSubjectX500Principal());
                byte[] crlDistPoints = certList.get(i).getExtensionValue("2.5.29.31"); // OID de l'extension CDP
                if (crlDistPoints == null) {
                    System.out.println("| Aucun point de distrubition CRL trouvé sur ce certficat \n");
                    continue;
                }

                ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(crlDistPoints));
                ASN1Primitive derObject = asn1InputStream.readObject();
                asn1InputStream.close();

                byte[] octets = ((DEROctetString) derObject).getOctets();
                asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(octets));
                ASN1Primitive derSeq = asn1InputStream.readObject();
                asn1InputStream.close();

                CRLDistPoint distPoint = CRLDistPoint.getInstance(derSeq);
                for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                    DistributionPointName dpn = dp.getDistributionPoint();
                    if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                        GeneralNames names = (GeneralNames) dpn.getName();
                        for (GeneralName genName : names.getNames()) {
                            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                                String URL = ((ASN1String) genName.getName()).getString();
                                System.out.println("| CRL URL: " + URL);
                                info.crlUrl = URL;
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Erreur lors de l'extraction de l'url de la CRL : " + e.getMessage());
            }
            //Extraction Ocsp (3.3.2)
            try {
                byte[] aiaExtension = certList.get(i).getExtensionValue("1.3.6.1.5.5.7.1.1"); // AIA OID
                if (aiaExtension == null) {
                    System.out.println("Pas de point d'OCSP trouvé dans ce certificat");
                    continue;
                }
    
                ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(aiaExtension));
                ASN1Primitive derObject = asn1InputStream.readObject();
                asn1InputStream.close();
    
                byte[] octets = ((DEROctetString) derObject).getOctets();
                asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(octets));
                ASN1Primitive derSeq = asn1InputStream.readObject();
                asn1InputStream.close();
    
                AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(derSeq);
                for (AccessDescription ad : aia.getAccessDescriptions()) {
                    if (ad.getAccessMethod().toString().equals(AccessDescription.id_ad_ocsp.toString())) {
                        GeneralName name = ad.getAccessLocation();
                        if (name.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String ocspUrl = name.getName().toString();
                            System.out.println("| OCSP URL : " + ocspUrl+"\n");
                            info.ocspUrl = ocspUrl;
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Erreur lors de l'extraction de l'url de l'OCSP : " + e.getMessage());
            }   
            cache.put(i, info);
            CertInfoCache.add(cache);
            }
            // Téléchargement CRL et mise en cache ou utilisation du cache (cache : partie 3.3.3)
            System.out.println("\n================================\nTéléchargement ou Caching :\n================================\n");
            String path = "CRL";
            String fileName=null;
            for (int i = 0; i < CertInfoCache.size(); i++) {
                HashMap<Integer, CertInfo> CRL_Cache = CertInfoCache.get(i);
                for (Map.Entry<Integer, CertInfo> crlinfo : CRL_Cache.entrySet()) {
                    Integer id = crlinfo.getKey();
                    CertInfo info = crlinfo.getValue();
                    String url = info.crlUrl;
                    File file = info.crlFile;
                    System.out.println("\n================================\nRécupération dans le cache "+ fileName + ":\n================================\n");
                    // Récupération du fichier dans le cache sinon on le retélécharge
                    if (url.endsWith(".crl")){
                    fileName = url.substring(url.lastIndexOf("/") + 1);
                    Path savePath = Paths.get(path, fileName);
                    if (Files.exists(savePath)) {
                        file = savePath.toFile();
                        System.out.println("| CRL déjà présente dans le cache : " + file);
                    }else{
                        System.out.println("| CRL Abenste, début du téléchargement ...");
                        try (InputStream in = new URL(url).openStream()) {
                            Files.copy(in, savePath, StandardCopyOption.REPLACE_EXISTING);
                            file = savePath.toFile();
                            System.out.println("| Téléchargement de la CRL réussit : " + file);
                        } catch (IOException e) {
                            System.out.println("| Téléchargement de la CRL a échoué : " + e.getMessage() + "\n");
                        }
                    }
                    //Vérification de la CRL téléchargée (3.3.1)
                    System.out.println("\n================================\nVérification par CRL et OCSP "+ certList.get(id).getSubjectX500Principal() + ":\n================================");
                    if (file != null) {
                        try (InputStream inStream = new FileInputStream(file)) {
                            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                            X509CRL crl = (X509CRL) certificateFactory.generateCRL(inStream);
                            Date date = new Date();
                            if (crl.getNextUpdate().after(date)) {
                                System.out.println("| CRL Toujours valide ---- date d'update crl : "+ crl.getNextUpdate() + " > " + date);
                                System.out.println("| CRL_ID: " + id + "\n| CRL_URL : " + url + "\n| CRL_File : " + file +"\n| OCSP_URL : "+ info.ocspUrl);
                                System.out.println("| Verification pour la CRL de " + certList.get(id).getSubjectX500Principal());
                                verifyCRL(crl, certList.get(id - 1));
                                System.out.println("=================");
                                if (crl.isRevoked(certList.get(id))) {
                                    System.out.println("| Certificat révoqué selon la CRL pour : " + certList.get(id).getSubjectX500Principal());
                                } else {
                                    System.out.println("| Certificat valide selon la CRL pour : " + certList.get(id).getSubjectX500Principal());
                                }
                            } else {
                                System.out.println("| CRL expirée ---- date d'update crl : "+ crl.getNextUpdate() + " < " + date);
                                try (InputStream in = new URL(url).openStream()) {
                                    Files.copy(in, savePath, StandardCopyOption.REPLACE_EXISTING);
                                    file = savePath.toFile();
                                    System.out.println("| CRL Mise à jour : " + file);
                                    System.out.println("| CRL_ID: " + id + "\n| CRL_URL : " + url + "\n| CRL_File : " + file +"\n| OCSP_URL : "+ info.ocspUrl);
                                    System.out.println("| Verification pour la CRL de " + certList.get(id).getSubjectX500Principal());
                                    verifyCRL(crl, certList.get(id - 1));
                                    System.out.println("=================");
                                    if (crl.isRevoked(certList.get(id))) {
                                        System.out.println("| Certificat révoqué selon la CRL pour : " + certList.get(id).getSubjectX500Principal());
                                    } else {
                                        System.out.println("| Certificat valide selon la CRL pour : " + certList.get(id).getSubjectX500Principal());
                                    }
                                } catch (IOException e) {
                                    System.out.println("| Mise à jour de la CRL a échouée : " + e.getMessage()+"\n");
                                }
                            }
                            
                        } catch (Exception e) {
                            System.out.println("| L'ouverture de la CRL a échoué : " + e.getMessage() + "\n");
                        }
                    }
                    }else{
                        System.out.println("Erreur avec l'url, aucune fichier .crl à téléchargé\n| url : " + url);
                        System.out.println("| Vérification par CRL impossible : Certificat invalide");
                    }
                    //Ajouter la vérification du status de révocation en utilisant le protocole OCSP s'il est disponible pour un
                    //certificat donné (3.3.2)
                    if(!checkOCSP(certList.get(id), certList.get(id-1), info.ocspUrl)){
                        System.out.println("| Certificat valide selon l'OCSP pour : " + certList.get(id).getSubjectX500Principal());
                    }else{
                        System.out.println("| Certificat invalide selon l'OCSP pour : " + certList.get(id).getSubjectX500Principal());
                    }
                }
                System.out.println();
            }
        return true;
    }

    //fonctio de vérif CRL (lien avec vérif de la CRL demandé 3.3.1)
    private void verifyCRL(X509CRL crl,X509Certificate IssuerCA){
        try{
        crl.verify(IssuerCA.getPublicKey());
            System.out.println("| Signature de CRL valide");
            System.out.println("| CA d'émission "+IssuerCA.getSubjectX500Principal());
        } catch (Exception e) {
            System.out.println("| Signature de CRL invalide");
            System.out.println("| CA d'émission "+IssuerCA.getSubjectX500Principal());
            e.printStackTrace();
        }
    }

    //fonction pour réaliser le point 3.3.2)
    private boolean checkOCSP(X509Certificate cert, X509Certificate issuerCert, String ocspUrl) {
        try{
        CertificateID certId = new CertificateID(
                new BcDigestCalculatorProvider().get(CertificateID.HASH_SHA1),
                new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuerCert),
                cert.getSerialNumber()
        );

        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);
        OCSPReq ocspReq = builder.build();

        HttpURLConnection con = (HttpURLConnection) new URL(ocspUrl).openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        con.setDoOutput(true);
        con.getOutputStream().write(ocspReq.getEncoded());
        con.getOutputStream().flush();
        con.getOutputStream().close();

        InputStream responseStream = con.getInputStream();
        OCSPResp ocspResp = new OCSPResp(responseStream);
        responseStream.close();

        if (ocspResp.getStatus() == OCSPResp.SUCCESSFUL) {
            BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
            SingleResp[] responses = basicResponse.getResponses();
            for (SingleResp resp : responses) {
                if (resp.getCertStatus() == null) {
                    return false; // Certificat valide
                }
            }
        }
        return true; // Certificat révoquée
    }catch(Exception e){
        System.out.println("Erreur lors de la vérification OCSP");
        return true;
    }
}
}

