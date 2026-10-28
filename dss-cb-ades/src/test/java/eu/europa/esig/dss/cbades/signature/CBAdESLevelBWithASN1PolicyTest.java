package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.policy.SignaturePolicyProvider;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBWithASN1PolicyTest extends AbstractCBAdESTestSignature {

    private static final DSSDocument SIGNATURE_POLICY_CONTENT = new FileDocument("src/test/resources/signature-policy.der");

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final String SIGNATURE_POLICY_DOCUMENTATION = "http://nowina.lu/signature-policy.pdf";

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        service = new CBAdESService(getCompleteCertificateVerifier());
        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");
        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        signaturePolicy.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION);
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestValue(Utils.fromBase64("UB1ptLcfxuVzI8LHQTGpyMYkCb43i6eI3CiFVWEbnlg="));
        signaturePolicy.setHashAsInTechnicalSpecification(true);

        SpDocSpecification spDocSpecification = new SpDocSpecification();
        spDocSpecification.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpecification.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpecification.setDocumentationReferences(SIGNATURE_POLICY_DOCUMENTATION);
        signaturePolicy.setSpDocSpecification(spDocSpecification);

        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
    }

    @Override
    protected SignaturePolicyProvider getSignaturePolicyProvider() {
        SignaturePolicyProvider signaturePolicyProvider = new SignaturePolicyProvider();
        Map<String, DSSDocument> signaturePoliciesByUrl = new HashMap<>();
        signaturePoliciesByUrl.put(HTTP_SPURI_TEST, SIGNATURE_POLICY_CONTENT);
        signaturePolicyProvider.setSignaturePoliciesByUrl(signaturePoliciesByUrl);
        return signaturePolicyProvider;
    }

    @Override
    protected void checkSignaturePolicy(List<AdvancedSignature> signatures) {
        super.checkSignaturePolicy(signatures);

        assertEquals(1, signatures.size());
        AdvancedSignature advancedSignature = signatures.get(0);

        SignaturePolicy signaturePolicy = advancedSignature.getSignaturePolicy();
        assertNotNull(signaturePolicy);
        assertEquals(SIGNATURE_POLICY_ID, signaturePolicy.getIdentifier());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signaturePolicy.getDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signaturePolicy.getDocumentationReferences().get(0));
        assertEquals(HTTP_SPURI_TEST, signaturePolicy.getUri());
        assertTrue(signaturePolicy.isHashAsInTechnicalSpecification());
        assertNotNull(signaturePolicy.getDocSpecification());
        assertEquals(SIGNATURE_POLICY_ID, signaturePolicy.getDocSpecification().getId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signaturePolicy.getDocSpecification().getDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signaturePolicy.getDocSpecification().getDocumentationReferences()[0]);
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());
        assertTrue(signature.isPolicyIdentified());
        assertTrue(signature.isPolicyDigestAlgorithmsEqual());
        assertTrue(signature.isPolicyAsn1Processable());
        assertTrue(signature.isPolicyDigestValid());
        assertTrue(Utils.isStringEmpty(signature.getPolicyProcessingError()));
        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signature.getPolicyDocumentationReferences().get(0));

        assertNotNull(signature.getPolicyDocSpecification());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyDocSpecification().getId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDocSpecification().getDescription());
        assertEquals(SIGNATURE_POLICY_DOCUMENTATION, signature.getPolicyDocSpecification().getDocumentationReferences().get(0));
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
