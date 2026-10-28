package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESSignaturePolicyStoreLocalIdTest extends AbstractCBAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final DSSDocument SIGNATURE_POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());
    private static final String[] DOCUMENTATION_REFERENCES = new String[] { "http://docref.com/ref1", "http://docref.com/ref2" };
    private static final String SIG_POL_LOCAL_URI = "file://local/uri/path";

    private static final DSSDocument ORIGINAL_DOCUMENT = new InMemoryDocument("Hello world!".getBytes());

    private CBAdESService service;
    private DSSDocument documentToSign;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        service = new CBAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());

        documentToSign = ORIGINAL_DOCUMENT;
        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN1);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);

        Policy signaturePolicy = new Policy();
        signaturePolicy.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        signaturePolicy.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        signaturePolicy.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signaturePolicy.setDigestValue(DSSUtils.digest(DigestAlgorithm.SHA256, SIGNATURE_POLICY_CONTENT));
        signaturePolicy.setSpuri(HTTP_SPURI_TEST);

        signatureParameters.bLevel().setSignaturePolicy(signaturePolicy);
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        SignaturePolicyStore signaturePolicyStore = new SignaturePolicyStore();
        signaturePolicyStore.setSigPolDocLocalURI(SIG_POL_LOCAL_URI);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpec.setDocumentationReferences(DOCUMENTATION_REFERENCES);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        DSSDocument signedDocumentWithSignaturePolicyStore =
                service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
        assertNotNull(signedDocumentWithSignaturePolicyStore);

        documentToSign = ORIGINAL_DOCUMENT;

        return signedDocumentWithSignaturePolicyStore;
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        AdvancedSignature cbadesSignature = signatures.get(0);
        SignaturePolicyStore extractedSPS = cbadesSignature.getSignaturePolicyStore();
        assertNotNull(extractedSPS);
        assertNull(extractedSPS.getSignaturePolicyContent());
        assertEquals(SIG_POL_LOCAL_URI, extractedSPS.getSigPolDocLocalURI());
        assertNotNull(extractedSPS.getSpDocSpecification());
        assertEquals(SIGNATURE_POLICY_ID, extractedSPS.getSpDocSpecification().getId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, extractedSPS.getSpDocSpecification().getDescription());
        assertArrayEquals(DOCUMENTATION_REFERENCES, extractedSPS.getSpDocSpecification().getDocumentationReferences());
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());

        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
        assertFalse(signature.isPolicyIdentified());
        assertFalse(signature.isPolicyAsn1Processable());
        assertFalse(signature.isPolicyDigestValid());
        assertFalse(signature.isPolicyDigestAlgorithmsEqual());
    }

    @Override
    protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyStore(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyStorePresent());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());

        XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
        assertNull(policyStoreDigestAlgoAndValue);

        assertEquals(SIG_POL_LOCAL_URI, signature.getPolicyStoreLocalURI());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
        assertEquals(Arrays.asList(DOCUMENTATION_REFERENCES), signature.getPolicyStoreDocumentationReferences());
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
