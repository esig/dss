package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESCounterSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CounterSignXadesBTest extends CookbookTools {

    @Test
    public void signXAdESBaselineB() throws Exception {

        // GET document to be signed -
        // Return DSSDocument toSignDocument
        prepareXmlDoc();

        // Get a token connection based on a pkcs12 file commonly used to store private
        // keys with accompanying public key certificates, protected with a password-based
        // symmetric key -
        // Return AbstractSignatureTokenConnection signingToken
        // and it's first private key entry from the PKCS12 store
        // Return DSSPrivateKeyEntry privateKey

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            XAdESSignatureParameters parameters = new XAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            XAdESService signatureService = new XAdESService(commonCertificateVerifier);
            ToBeSigned dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValueToSign = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = signatureService.signDocument(toSignDocument, parameters, signatureValueToSign);

            // tag::demo[]

            // Initialize counter signature parameters
            XAdESCounterSignatureParameters counterSignatureParameters = new XAdESCounterSignatureParameters();
            // Set signing certificate parameters
            counterSignatureParameters.setSigningCertificate(privateKey.getCertificate());
            counterSignatureParameters.setCertificateChain(privateKey.getCertificateChain());
            // Set target level of the counter signature
            counterSignatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

            // Next step is to extract and set the Id of a signature to be counter signed

            // Initialize a validator over the signedDocument in order to extract the master signature Id
            DocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
            // Get list of signatures
            List<AdvancedSignature> signatures = validator.getSignatures();
            // Get Id of the target signature
            AdvancedSignature signature = signatures.iterator().next();
            String signatureId = signature.getId();
            // For XAdES, the XML Id can be used
            signatureId = signature.getDAIdentifier();
            // Set the Id to parameters
            counterSignatureParameters.setSignatureIdToCounterSign(signatureId);

            // Initialize a new service for the counter signature creation
            // The counter signature will be created in three steps, similarly as a normal signature
            XAdESService service = new XAdESService(commonCertificateVerifier);
            // First step is to get toBeSigned, which represents a SignatureValue of the master signature
            ToBeSigned dataToBeCounterSigned = service.getDataToBeCounterSigned(signedDocument, counterSignatureParameters);
            // Second step is to compute the signatureValue on the dataToBeCounterSigned
            SignatureValue signatureValue = signingToken.sign(dataToBeCounterSigned, counterSignatureParameters.getDigestAlgorithm(), privateKey);
            // Third step is to create the counter signed signature document
            DSSDocument counterSignedSignature = service.counterSignSignature(signedDocument, counterSignatureParameters, signatureValue);

            // end::demo[]

            DiagnosticData diagnosticData = testFinalDocument(counterSignedSignature);

            List<SignatureWrapper> signatureWrappers = diagnosticData.getSignatures();
            assertEquals(2, signatureWrappers.size());
            assertEquals(1, diagnosticData.getAllCounterSignaturesForMasterSignature(signatureWrappers.iterator().next()).size());

        }
    }

}
