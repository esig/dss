package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

public class SignMultipleDocumentsJadesTTest extends CookbookTools {

    private List<DSSDocument> documentsToBeSigned;

    @Test
    public void sign() throws Exception {

        // Get a token connection based on a pkcs12 file commonly used to store
        // private
        // keys with accompanying public key certificates, protected with a
        // password-based
        // symmetric key -
        // Return AbstractSignatureTokenConnection signingToken

        // and it's first private key entry from the PKCS12 store
        // Return DSSPrivateKeyEntry privateKey *****
        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            JAdESSignatureParameters parameters = new JAdESSignatureParameters();
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
            parameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);

            // tag::clearEtsiU[]
            parameters.setBase64UrlEncodedEtsiUComponents(false);
            // end::clearEtsiU[]

            // tag::demo[]
            parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
            parameters.setSigDMechanism(SigDMechanism.OBJECT_ID_BY_URI_HASH);
            // Prepare the documents to be signed
            documentsToBeSigned = new ArrayList<>();
            documentsToBeSigned.add(new FileDocument("src/main/resources/hello-world.pdf"));
            documentsToBeSigned.add(new FileDocument("src/main/resources/xml_example.xml"));
            // end::demo[]

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            JAdESService service = new JAdESService(commonCertificateVerifier);

            ToBeSigned dataToSign = service.getDataToSign(documentsToBeSigned, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument signedDocument = service.signDocument(documentsToBeSigned, parameters, signatureValue);

            testFinalDocument(signedDocument);
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setDetachedContents(documentsToBeSigned);
        return validator;
    }
}
