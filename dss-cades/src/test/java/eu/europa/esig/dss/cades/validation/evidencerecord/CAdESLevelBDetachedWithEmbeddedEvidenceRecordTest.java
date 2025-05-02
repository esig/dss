package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBDetachedWithEmbeddedEvidenceRecordTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBDetachedWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS-detached-ber.p7s"));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument(
                CAdESLevelBDetachedWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/TestDataLogo.png"), "TestDataLogo.png"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CMS_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(2, evidenceRecord.getDigestMatchers().size());

        int sigDMCounter = 0;
        int refDMCounter = 0;
        for (XmlDigestMatcher digestMatcher : evidenceRecord.getDigestMatchers()) {
            assertNotNull(digestMatcher.getDigestMethod());
            assertNotNull(digestMatcher.getDigestValue());
            if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == digestMatcher.getType()) {
                assertNull(digestMatcher.getDocumentName());
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                ++sigDMCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                assertNotNull(digestMatcher.getDocumentName());
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                ++refDMCounter;
            }
        }
        assertEquals(1, sigDMCounter);
        assertEquals(1, refDMCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));

        assertEquals(Utils.collectionSize(signatures), coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNATURE == r.getCategory()).count());
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects.stream()
                .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).collect(Collectors.toList())));

        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertFalse(signature.isSigningCertificateReferencePresent());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            }
        }
        assertEquals(1, sigWithErCounter);
    }

}
