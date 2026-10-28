package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORDecodeException;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
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
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CBAdESLevelTWithSignaturePolicyStoreTest extends AbstractCBAdESTestSignature {

    private static final String HTTP_SPURI_TEST = "http://spuri.test";
    private static final String SIGNATURE_POLICY_ID = "1.2.3.4.5.6";
    private static final String SIGNATURE_POLICY_DESCRIPTION = "Test description";
    private static final DSSDocument SIGNATURE_POLICY_CONTENT = new InMemoryDocument("Hello world".getBytes());
    private static final String[] DOCUMENTATION_REFERENCES = new String[] { "http://docref.com/ref1", "http://docref.com/ref2" };

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
        signatureParameters.setCoseStructureType(COSEStructureType.COSE_SIGN);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_T);

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
        signaturePolicyStore.setSignaturePolicyContent(SIGNATURE_POLICY_CONTENT);
        SpDocSpecification spDocSpec = new SpDocSpecification();
        spDocSpec.setId("urn:oid:" + SIGNATURE_POLICY_ID);
        spDocSpec.setDescription(SIGNATURE_POLICY_DESCRIPTION);
        spDocSpec.setDocumentationReferences(DOCUMENTATION_REFERENCES);
        signaturePolicyStore.setSpDocSpecification(spDocSpec);

        DSSDocument signedDocumentWithSignaturePolicyStore = service.addSignaturePolicyStore(signedDocument, signaturePolicyStore);
        assertNotNull(signedDocumentWithSignaturePolicyStore);

        return signedDocumentWithSignaturePolicyStore;
    }

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocumentWithSignaturePolicyStore = new InMemoryDocument(byteArray);
        assertRequirementsValid(signedDocumentWithSignaturePolicyStore);
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        assertEquals(1, signatures.size());
        CBAdESSignature CBAdESSignature = (CBAdESSignature) signatures.get(0);
        SignaturePolicyStore extractedSPS = CBAdESSignature.getSignaturePolicyStore();
        assertNotNull(extractedSPS);
        assertNotNull(extractedSPS.getSpDocSpecification());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, extractedSPS.getSpDocSpecification().getDescription());
        assertArrayEquals(DOCUMENTATION_REFERENCES, extractedSPS.getSpDocSpecification().getDocumentationReferences());
        assertArrayEquals(DSSUtils.toByteArray(SIGNATURE_POLICY_CONTENT), DSSUtils.toByteArray(extractedSPS.getSignaturePolicyContent()));
    }

    private void assertRequirementsValid(DSSDocument documentWithPolicyStore) {
        try {
            CBORValue cborValue = CBORUtils.parseCbor(documentWithPolicyStore);
            assertTrue(cborValue.isTag());
            assertEquals(98, cborValue.getTag().longValue());

            CBORValue cborArray = cborValue.getTaggedValue();
            assertTrue(cborArray.isArray());
            assertEquals(4, cborArray.size());

            byte[] bodyProtectedHeader = cborArray.getAsBytesOrNull(0);
            assertNotNull(bodyProtectedHeader);
            assertEquals(0, bodyProtectedHeader.length);

            CBORValue bodyUnprotectedHeader = cborArray.getAsMapOrNull(1);
            assertNotNull(bodyUnprotectedHeader);
            assertEquals(0, bodyUnprotectedHeader.size());

            byte[] payload = cborArray.getAsBytesOrNull(2);
            assertNotNull(payload);
            assertArrayEquals(DSSUtils.toByteArray(ORIGINAL_DOCUMENT), payload);

            CBORValue coseSignatures = cborArray.getAsArrayOrNull(3);
            assertNotNull(coseSignatures);
            assertEquals(1, coseSignatures.size());

            CBORValue coseSignature = coseSignatures.get(0);
            assertNotNull(coseSignature);
            assertTrue(coseSignature.isArray());

            byte[] signerProtectedHeader = coseSignature.getAsBytesOrNull(0);
            assertNotNull(signerProtectedHeader);
            assertTrue(signerProtectedHeader.length > 0);

            CBORValue signerProtectedHeaderMap = CBORUtils.parseCbor(signerProtectedHeader);
            assertNotNull(signerProtectedHeaderMap);
            assertTrue(Utils.isCollectionNotEmpty(signerProtectedHeaderMap.getEntries()));

            CBORValue sigPId = signerProtectedHeaderMap.getAsMapOrNull(266L);
            assertNotNull(sigPId);
            assertTrue(sigPId.isMap());

            CBORValue sigPIdOid = sigPId.get(1L);
            assertNotNull(sigPIdOid);
            assertTrue(sigPIdOid.isMap());

            CBORValue sigPIdId = sigPIdOid.get(1L);
            assertTrue(sigPIdId.isTag());
            assertEquals(32L, sigPIdId.getTag().longValue());
            assertNotNull(sigPIdId.getTaggedValue());
            assertTrue(sigPIdId.getTaggedValue().isTextString());
            assertEquals("urn:oid:" + SIGNATURE_POLICY_ID, sigPIdId.getTaggedValue().asString());

            CBORValue sigPIdDesc = sigPIdOid.get(2L);
            assertNotNull(sigPIdDesc);
            assertTrue(sigPIdDesc.isTextString());
            assertEquals(SIGNATURE_POLICY_DESCRIPTION, sigPIdDesc.asString());

            CBORValue sigPIdDocRefs = sigPIdOid.get(3L);
            assertNull(sigPIdDocRefs);

            CBORValue digAlgVal = sigPId.get(2L);
            assertNotNull(digAlgVal);
            assertTrue(digAlgVal.isArray());

            CBORValue hashAlg = digAlgVal.get(0);
            assertNotNull(hashAlg);
            assertTrue(hashAlg.isInteger());
            assertEquals(-16L, hashAlg.asInteger().longValue());

            CBORValue hashValue = digAlgVal.get(1);
            assertNotNull(hashValue);
            assertTrue(hashValue.isByteString());
            assertArrayEquals(DSSUtils.digest(DigestAlgorithm.SHA256, SIGNATURE_POLICY_CONTENT), hashValue.asBytes());

            CBORValue digPSp = sigPId.get(3L);
            assertNull(digPSp); // false by default, not included

            CBORValue sigPQuals = sigPId.get(4L);
            assertNotNull(sigPQuals);
            assertTrue(sigPQuals.isArray());
            assertEquals(1, Utils.collectionSize(sigPQuals.getElements()));

            CBORValue sigPQual = sigPQuals.get(0);
            assertTrue(sigPQual.isMap());
            assertEquals(1, Utils.collectionSize(sigPQual.getEntries()));

            CBORValue spURI = sigPQual.get(1L);
            assertNotNull(spURI);
            assertTrue(spURI.isTag());
            assertEquals(32L, spURI.getTag().longValue());
            assertNotNull(spURI.getTaggedValue());
            assertTrue(spURI.getTaggedValue().isTextString());
            assertEquals(HTTP_SPURI_TEST, spURI.getTaggedValue().asString());

            assertNull(sigPQual.get(2L));
            assertNull(sigPQual.get(3L));

            CBORValue signerUnprotectedHeaderMap = coseSignature.getAsMapOrNull(1);
            assertNotNull(signerUnprotectedHeaderMap);
            assertEquals(1, Utils.collectionSize(signerUnprotectedHeaderMap.getEntries()));

            CBORValue uHeaders = signerUnprotectedHeaderMap.getAsArrayOrNull(268L);
            assertNotNull(uHeaders);
            assertEquals(2, Utils.collectionSize(uHeaders.getElements()));

            byte[] sigTstInstance = uHeaders.getAsBytesOrNull(0);
            assertNotNull(sigTstInstance);
            CBORValue sigTst = CBORUtils.parseCbor(sigTstInstance);
            assertTrue(sigTst.isMap());
            assertEquals(1, Utils.collectionSize(sigTst.getEntries()));
            assertEquals(CBOR.integer(1L), sigTst.getEntries().get(0).key());
            assertTrue(sigTst.getEntries().get(0).value().isMap());

            byte[] sigPStInstance = uHeaders.getAsBytesOrNull(1);
            assertNotNull(sigPStInstance);
            CBORValue sigPSt = CBORUtils.parseCbor(sigPStInstance);
            assertTrue(sigPSt.isMap());
            assertEquals(1, Utils.collectionSize(sigPSt.getEntries()));
            assertEquals(CBOR.integer(7L), sigPSt.getEntries().get(0).key());

            CBORValue sigPStValue = sigPSt.getEntries().get(0).value();
            assertTrue(sigPStValue.isMap());

            CBORValue docOrLocalUri = sigPStValue.getAsMapOrNull(1L);
            assertNotNull(docOrLocalUri);
            assertTrue(docOrLocalUri.isMap());

            byte[] sigPolDoc = docOrLocalUri.getAsBytesOrNull(1L);
            assertNotNull(sigPolDoc);
            assertArrayEquals(DSSUtils.toByteArray(SIGNATURE_POLICY_CONTENT), sigPolDoc);

            CBORValue sigPolLocalURI = docOrLocalUri.get(2L);
            assertNull(sigPolLocalURI);

            CBORValue spDSpec = sigPStValue.getAsMapOrNull(2L);
            assertNotNull(spDSpec);

            CBORValue spDSpecId = spDSpec.get(1L);
            assertTrue(spDSpecId.isTag());
            assertEquals(32L, spDSpecId.getTag().longValue());
            assertNotNull(spDSpecId.getTaggedValue());
            assertTrue(spDSpecId.getTaggedValue().isTextString());
            assertEquals("urn:oid:" + SIGNATURE_POLICY_ID, spDSpecId.getTaggedValue().asString());

            CBORValue spDSpecDesc = spDSpec.get(2L);
            assertNotNull(spDSpecDesc);
            assertTrue(spDSpecDesc.isTextString());
            assertEquals(SIGNATURE_POLICY_DESCRIPTION, spDSpecDesc.asString());

            CBORValue spDSpecDocRefs = spDSpec.get(3L);
            assertNotNull(spDSpecDocRefs);
            assertTrue(spDSpecDocRefs.isArray());
            assertEquals(2, Utils.collectionSize(spDSpecDocRefs.getElements()));

            boolean firstRefFound = false;
            boolean secondRefFound = false;
            for (CBORValue spDSpecDocRef : spDSpecDocRefs.getElements()) {
                assertTrue(spDSpecDocRef.isTag());
                assertEquals(32L, spDSpecDocRef.getTag().longValue());
                assertNotNull(spDSpecDocRef.getTaggedValue());
                assertTrue(spDSpecDocRef.getTaggedValue().isTextString());
                if (spDSpecDocRef.getTaggedValue().asString().contains("ref1")) {
                    firstRefFound = true;
                } else if (spDSpecDocRef.getTaggedValue().asString().contains("ref2")) {
                    secondRefFound = true;
                }
            }
            assertTrue(firstRefFound);
            assertTrue(secondRefFound);

        } catch (CBORDecodeException e) {
            fail(e);
        }
    }

    @Override
    protected void checkSignaturePolicyIdentifier(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyIdentifier(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyPresent());

        assertEquals(HTTP_SPURI_TEST, signature.getPolicyUrl());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyDescription());

        assertFalse(signature.isPolicyAsn1Processable());
        assertTrue(signature.isPolicyIdentified());
        assertTrue(signature.isPolicyDigestValid());
        assertTrue(signature.isPolicyDigestAlgorithmsEqual());
    }

    @Override
    protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
        super.checkSignaturePolicyStore(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SIGNATURE_POLICY_ID, signature.getPolicyStoreId());
        assertEquals(SIGNATURE_POLICY_DESCRIPTION, signature.getPolicyStoreDescription());
        assertEquals(2, signature.getPolicyStoreDocumentationReferences().size());
        assertEquals(DOCUMENTATION_REFERENCES[0], signature.getPolicyStoreDocumentationReferences().get(0));
        assertEquals(DOCUMENTATION_REFERENCES[1], signature.getPolicyStoreDocumentationReferences().get(1));

        XmlDigestAlgoAndValue policyStoreDigestAlgoAndValue = signature.getPolicyStoreDigestAlgoAndValue();
        assertNotNull(policyStoreDigestAlgoAndValue);
        assertNotNull(policyStoreDigestAlgoAndValue.getDigestMethod());
        assertTrue(Utils.isArrayNotEmpty(policyStoreDigestAlgoAndValue.getDigestValue()));

        XmlDigestAlgoAndValue policyDigestAlgoAndValue = signature.getPolicyDigestAlgoAndValue();
        assertEquals(policyDigestAlgoAndValue.getDigestMethod(), policyStoreDigestAlgoAndValue.getDigestMethod());
        assertArrayEquals(policyDigestAlgoAndValue.getDigestValue(), policyStoreDigestAlgoAndValue.getDigestValue());

        assertArrayEquals(SIGNATURE_POLICY_CONTENT.getDigestValue(policyDigestAlgoAndValue.getDigestMethod()), policyDigestAlgoAndValue.getDigestValue());
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
