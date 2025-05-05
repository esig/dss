package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelBInvalidSigAndTstWithEmbeddedEvidenceRecordTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBInvalidSigAndTstWithEmbeddedEvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/C-E-ERS-basic-invalid-sig.p7m"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkBLevelValid(DiagnosticData diagnosticData) {
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertTrue(digestMatcher.isDataFound());
        assertTrue(digestMatcher.isDataIntact());
        assertFalse(digestMatcher.isDuplicated());

        assertFalse(signatureWrapper.isSignatureIntact());
        assertFalse(signatureWrapper.isSignatureValid());
        assertFalse(diagnosticData.isBLevelTechnicallyValid(signatureWrapper.getId()));
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordDigestMatchers(diagnosticData);

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(1, evidenceRecord.getDigestMatchers().size());

        XmlDigestMatcher digestMatcher = evidenceRecord.getDigestMatchers().get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE, digestMatcher.getType());
        assertNull(digestMatcher.getDocumentName());
        assertNotNull(digestMatcher.getDigestMethod());
        assertNotNull(digestMatcher.getDigestValue());
        assertTrue(digestMatcher.isDataFound());
        assertTrue(digestMatcher.isDataIntact());
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
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
        assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);

        List<TimestampWrapper> timestampList = evidenceRecord.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            }
            // invalid tst
            assertEquals(Indication.FAILED, simpleReport.getIndication(signatureEvidenceRecords.get(0).getId()));
            assertEquals(SubIndication.HASH_FAILURE, simpleReport.getSubIndication(signatureEvidenceRecords.get(0).getId()));
        }
        assertEquals(1, sigWithErCounter);
    }

}
