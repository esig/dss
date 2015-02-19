package eu.europa.ec.markt.dss.cookbook.example;

import java.net.URL;

import eu.europa.ec.markt.dss.cookbook.sources.MockTSPSource;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;

/**
 * Super-class for all cookbook examples.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class Cookbook {

    /**
     * The document to sign
     */
    static DSSDocument toSignDocument;

    /**
     * The document to extend
     */
    static DSSDocument toExtendDocument;

    /**
     * The object which is in charge of digesting ans encrypting the data to sign.
     */
    static AbstractSignatureTokenConnection signingToken;

    /**
     * This object contains the private key associated to the signing certificate.
     */
    static DSSPrivateKeyEntry privateKey;

    /**
     * The xades xadesService used to sign a document
     */
    //static XAdESService xadesService;

    //static CommonCertificateVerifier commonCertificateVerifier;

    /**
     * This method converts the resource path to the absolute path.
     *
     * @param resourcePath resource path
     * @return
     */
    public static String getPathFromResource(final String resourcePath) {

        final URL uri = Cookbook.class.getResource(resourcePath);
        final String absolutePath = uri.getPath();
        return absolutePath;
    }

    /**
     * This method sets the common parameters.
     */
    protected static void prepareXmlDoc() {
    	String toSignFilePath = getPathFromResource("/xml_example.xml");
        toSignDocument = new FileDocument(toSignFilePath);
    }
    
    /**
     * This method sets the common parameters.
     */
    protected static void preparePdfDoc() {
    	String toSignFilePath = getPathFromResource("/hello-world.pdf");
        toSignDocument = new FileDocument(toSignFilePath);
    }
    
    /**
     * This method sets the common parameters.
     */
    protected static void preparePKCS12TokenAndKey() {
    	String pkcs12TokenFile = getPathFromResource("/user_a_rsa.p12");
        signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);

        privateKey = signingToken.getKeys().get(0);
	}
    
    
    protected static MockTSPSource getMockTSPSource() {
    	return new MockTSPSource();
    }
    
    
    
    
    
    
    
    
    
    
    
    
    
    /**
     * This method sets the common parameters.
     */
//    protected static void prepareXmlTest() {
//
////        String toSignFilePath = getPathFromResource("/xml_example.xml");
////        toSignDocument = new FileDocument(toSignFilePath);
//
//        String pkcs12TokenFile = getPathFromResource("/user_a_rsa.p12");
//        signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);
//
//        privateKey = signingToken.getKeys().get(0);
//    }

    /**
     * This method prepares the common signing parameters.
     *
     * @return
     */
//    protected static SignatureParameters prepareSignatureParameters() {
//
//        SignatureParameters parameters = new SignatureParameters();
//        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
//        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
//        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
//        parameters.setPrivateKeyEntry(privateKey);
//        return parameters;
//    }

//    protected static DSSDocument signWithXAdES(SignatureParameters parameters) {
//
//        commonCertificateVerifier = getCommonCertificateVerifier();
//
//        xadesService = getXAdESService();
//
//        // Get the SignedInfo XML segment that need to be signed.
//        byte[] dataToSign = xadesService.getDataToSign(toSignDocument, parameters);
//
//        // This function obtains the signature value for signed information using the
//        // private key and specified algorithm
//        final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
//        byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
//
//        // We invoke the xadesService to sign the document with the signature value obtained in
//        // the previous step.
//        return xadesService.signDocument(toSignDocument, parameters, signatureValue);
//    }

//    protected static CommonCertificateVerifier getCommonCertificateVerifier() {
//        // Create common certificate verifier
//        if (commonCertificateVerifier == null) {
//            commonCertificateVerifier = new CommonCertificateVerifier();
//        }
//        return commonCertificateVerifier;
//    }
//
//    protected static XAdESService getXAdESService() {
//
//        // Create XAdES Service for signature
//        if (xadesService == null) {
//            xadesService = new XAdESService(getCommonCertificateVerifier());
//        }
//        return xadesService;
//    }


//    protected static SignatureParameters prepareExtendParameters() {
//
//        SignatureParameters parameters = new SignatureParameters();
//        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
//        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
//        return parameters;
//    }
}
