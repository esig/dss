package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignCAdESWithTempFileTest extends CookbookTools {

    @Test
    void signPAdESWithTempFile() throws Exception {

        String signedFileDestination = "target/signed.p7s";

        // GET document to be signed
        prepareXmlDoc();

        // Get a token connection based on a pkcs12 file
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::demo[]
            // import eu.europa.esig.dss.cades.CAdESSignatureParameters;
            // import eu.europa.esig.dss.cades.signature.CAdESService;
            // import eu.europa.esig.dss.enumerations.SignatureLevel;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

            // Preparing parameters for the CAdES signature
            CAdESSignatureParameters parameters = new CAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create CAdESService for signature
            CAdESService service = new CAdESService(new CommonCertificateVerifier());

            // Set a TempFileResourcesHandlerBuilder, forcing the signature creation process to
            // work with temporary files. It means that the produced DSSDocument after
            // the signDocument() method will be represented by a FileDocument object, pointing to
            // a real file within the file system.
            TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();

            // Provide to the CAdESService
            service.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);

            // Get the SignedInfo segment that need to be signed.
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            // Sign the Data To Be Signed
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // Sign document using the obtained SignatureValue.
            // As we used TempFileResourcesHandlerBuilder, the produced document will point to
            // a File within a local file system.
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);

            // After signature has been made, it could be a good idea to clear the builder,
            // which will remove the temporary files created during the signing operation.
            // Please note, that you should preserve the files you need before clearing
            // the builder, such as the signedDocument obtained from the #signDocument()
            // method. You may use the method #save() in order to store the file within
            // a preferred location.
            signedDocument.save(signedFileDestination);

            // And clear the builder, which will result in removing of all temporary files.
            tempFileResourcesHandlerBuilder.clear();

            // end::demo[]

            assertInstanceOf(FileDocument.class, signedDocument);

            signedDocument = new FileDocument(signedFileDestination);
            testFinalDocument(signedDocument);

            File file = new File(signedFileDestination);
            assertTrue(file.exists());
            assertTrue(file.delete());
            assertFalse(file.exists());
        }
    }

}
