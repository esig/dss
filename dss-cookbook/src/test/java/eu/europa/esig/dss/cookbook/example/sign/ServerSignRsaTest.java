package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ServerSignRsaTest extends CookbookTools {

    private static CAdESService service;

    @BeforeEach
    public void init() {
        // Create common certificate verifier
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        // Create signature service for signature creation
        service = new CAdESService(commonCertificateVerifier);
    }

    @Test
    void serverSignTest() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // GET document to be signed -
            // Return DSSDocument toSignDocument
            DSSDocument toSignDocument = new InMemoryDocument("Hello World!".getBytes());

            // Preparing parameters for a signature creation
            CAdESSignatureParameters parameters = new CAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            parameters.setSigningCertificate(getSigningCert());
            parameters.setCertificateChain(getCertificateChain());
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // tag::demo[]
            // import eu.europa.esig.dss.model.Digest;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.spi.DSSUtils;

            // Compute the hash of ToBeSigned data to send to the remote server
            byte[] toBeSignedDigest = getToBeSignedDigest(parameters, toSignDocument);

            // Encode digest to ASN.1 DigestInfo format for a private key signing in Java
            byte[] encodeRSADigest = DSSUtils.encodeRSADigest(parameters.getDigestAlgorithm(), toBeSignedDigest);

            // Create SignatureValue in Java usign the encoded digest value
            Digest digest = new Digest(parameters.getDigestAlgorithm(), encodeRSADigest);
            SignatureValue signatureValue = signingToken.signDigest(digest, privateKey);
            // end::demo[]

            // We invoke the signature service to create a signed document incorporating the obtained Sig
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            testFinalDocument(signedDocument);
        }

    }

    public byte[] getToBeSignedDigest(CAdESSignatureParameters parameters, DSSDocument toSignDocument) {
        // Get the SignedInfo segment that need to be signed providing the original document
        ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
        return DSSUtils.digest(parameters.getDigestAlgorithm(), dataToSign.getBytes());
    }

}
