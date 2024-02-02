package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordNoDetachedDataValidationValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/BIN-1_ER.ers");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidations.size());

        for (ReferenceValidation referenceValidation : referenceValidations) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, referenceValidation.getType());
            assertFalse(referenceValidation.isFound());
            assertFalse(referenceValidation.isIntact());
        }
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, digestMatcher.getType());
            assertFalse(digestMatcher.isDataFound());
            assertFalse(digestMatcher.isDataIntact());
        }
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());

        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecordWrapper.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().get(0);
        assertEquals(1, timestampWrapper.getTimestampedObjects().size());
        assertEquals(0, timestampWrapper.getTimestampedSignedData().size());
        assertEquals(1, timestampWrapper.getTimestampedEvidenceRecords().size());
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstEvidenceRecordId()));
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(simpleReport.getFirstEvidenceRecordId()));
    }

}
