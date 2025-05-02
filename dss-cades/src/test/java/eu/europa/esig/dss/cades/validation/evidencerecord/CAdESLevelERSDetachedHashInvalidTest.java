package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CAdESLevelERSDetachedHashInvalidTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelBWithEmbeddedEvidenceRecordTest.class.getResourceAsStream("/validation/evidence-record/C-E-ERS-detached-invalid.p7s"));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("Hello World!".getBytes(), "helloworld"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.CAdES_ERS, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 0;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
        assertEquals(EvidenceRecordIncorporationType.EXTERNAL_EVIDENCE_RECORD, evidenceRecord.getIncorporationType());

        boolean coversSignature = false;
        boolean coversSignedData = false;
        boolean coversCertificates = false;
        boolean coversRevocationData = false;
        boolean coversTimestamps = false;
        List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
        assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
        for (XmlTimestampedObject reference : coveredObjects) {
            if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                coversSignature = true;
            } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                coversSignedData = true;
            } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                coversCertificates = true;
            } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                coversRevocationData = true;
            } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                coversTimestamps = true;
            }
        }
        assertTrue(coversSignature);
        assertTrue(coversSignedData);
        assertTrue(coversCertificates);
        assertTrue(coversTimestamps);
        assertTrue(coversRevocationData);
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        int masterSigDMCounter = 0;
        int refDMCounter = 0;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                assertFalse(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                ++refDMCounter;
            }
        }
        assertEquals(0, masterSigDMCounter);
        assertEquals(2, refDMCounter);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertTrue(Utils.isCollectionEmpty(evidenceRecordWrapper.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<TimestampWrapper> timestampList = evidenceRecordWrapper.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertTrue(timestampWrapper.isSigningCertificateIdentified());
        assertTrue(timestampWrapper.isSigningCertificateReferencePresent());
        assertFalse(timestampWrapper.isSigningCertificateReferenceUnique());
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(simpleReport.getFirstSignatureId());
        assertEquals(1, signatureEvidenceRecords.size());

        XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
        assertEquals(Indication.FAILED, evidenceRecord.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, evidenceRecord.getSubIndication());
    }

}
