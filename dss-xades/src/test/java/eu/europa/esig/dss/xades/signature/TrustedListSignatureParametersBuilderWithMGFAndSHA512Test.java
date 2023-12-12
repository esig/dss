package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TrustedListSignatureParametersBuilderWithMGFAndSHA512Test extends TrustedListSignatureParametersBuilderTest {

    @Override
    protected TrustedListSignatureParametersBuilder getSignatureParametersBuilder() {
        return super.getSignatureParametersBuilder()
                .setDigestAlgorithm(DigestAlgorithm.SHA512)
                .setMaskGenerationFunction(MaskGenerationFunction.MGF1);
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        super.checkBLevelValid(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        SignatureAlgorithm signatureAlgorithm = signature.getSignatureAlgorithm();
        assertEquals(SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, signatureAlgorithm);
    }

}
