package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignPdfWithTempFileTest extends CookbookTools {

    @Test
    public void signPAdESWithTempFile() throws Exception {

        // GET document to be signed
        preparePdfDoc();

        // Get a token connection based on a pkcs12 file
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::demo[]

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create PAdESService for signature
            PAdESService service = new PAdESService(new CommonCertificateVerifier());

            // Set a TempFileResourcesHandlerBuilder, forcing the signature creation process to work with
            // temporary files. It means that the produced DSSDocument after the signDocument() method will
            // be represented by a FileDocument object, pointing to a real file within the file system.
            service.setResourcesHandlerBuilder(new TempFileResourcesHandlerBuilder());

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // Sign the Data To Be Signed
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // Sign document using the obtained SignatureValue.
            // As we used TempFileResourcesHandlerBuilder, the produced document will point to a File
            // within a local file system.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // end::demo[]

            assertTrue(signedDocument instanceof FileDocument);

            testFinalDocument(signedDocument);
        }
    }

}
