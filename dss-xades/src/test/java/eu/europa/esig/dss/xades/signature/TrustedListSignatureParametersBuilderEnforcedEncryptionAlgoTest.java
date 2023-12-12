package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TrustedListSignatureParametersBuilderEnforcedEncryptionAlgoTest extends TrustedListSignatureParametersBuilderTest {

    @Override
    protected TrustedListSignatureParametersBuilder getSignatureParametersBuilder() {
        return super.getSignatureParametersBuilder()
                .setEncryptionAlgorithm(EncryptionAlgorithm.EDDSA)
                .setDigestAlgorithm(DigestAlgorithm.SHA512);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.ED25519, signature.getSignatureAlgorithm());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

}
