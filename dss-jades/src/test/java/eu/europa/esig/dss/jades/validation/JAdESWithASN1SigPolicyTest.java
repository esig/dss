package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignaturePolicyProvider;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESWithASN1SigPolicyTest extends AbstractJAdESTestValidation {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final DSSDocument POLICY_CONTENT = new FileDocument("src/test/resources/validation/signature-policy.der");

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-with-asn1policy.json");
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
        signaturePoliciesByUrl.put(HTTP_SPURI_TEST, POLICY_CONTENT);
        signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
        return signaturePolicyProvider;
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());
        assertTrue(signature.isPolicyIdentified());
        assertTrue(signature.isPolicyDigestAlgorithmsEqual());
        assertFalse(signature.isPolicyAsn1Processable());
        assertTrue(signature.isPolicyDigestValid());
        assertTrue(Utils.isStringEmpty(signature.getPolicyProcessingError()));
    }

}
