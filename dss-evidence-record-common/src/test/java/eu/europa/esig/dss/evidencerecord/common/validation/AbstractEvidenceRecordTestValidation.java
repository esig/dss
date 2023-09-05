package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractEvidenceRecordTestValidation extends AbstractDocumentTestValidation {

    @Override
    protected EvidenceRecordValidator getValidator(DSSDocument evidenceRecordDocument) {
        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(evidenceRecordDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setTokenExtractionStrategy(getTokenExtractionStrategy());
        validator.setDetachedContents(getDetachedContents());
        validator.setTokenIdentifierProvider(getTokenIdentifierProvider());
        return validator;
    }

    @Override
    protected List<AdvancedSignature> getSignatures(DocumentValidator validator) {
        return Collections.emptyList();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        assertTrue(Utils.isCollectionEmpty(signatures));
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatures()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getSignatureIdList()));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
            }

            List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
            assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
                assertTrue(timestampToken.isProcessed());
                assertTrue(timestampToken.isMessageImprintDataFound());
                assertTrue(timestampToken.isMessageImprintDataIntact());

                if (tstCounter > 0) {
                    List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                    assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                    boolean archiveTstDigestFound = false;
                    boolean archiveTstSequenceDigestFound = false;
                    for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                        if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                            archiveTstDigestFound = true;
                        } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(referenceValidation.getType())) {
                            archiveTstSequenceDigestFound = true;
                        }
                        assertTrue(referenceValidation.isFound());
                        assertTrue(referenceValidation.isIntact());
                    }

                    if (tstReferenceValidationList.size() == 1) {
                        assertTrue(archiveTstDigestFound);
                    } else {
                        assertTrue(archiveTstSequenceDigestFound);
                    }

                }

                ++tstCounter;
            }
        }
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        List<String> signatureIdList = simpleReport.getSignatureIdList();
        assertEquals(simpleReport.getSignaturesCount(), signatureIdList.size());

        int numberOfValidSignatures = 0;
        for (String sigId : signatureIdList) {
            Indication indication = simpleReport.getIndication(sigId);
            assertNotNull(indication);
            assertTrue(Indication.TOTAL_PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                    || Indication.TOTAL_FAILED.equals(indication));
            if (Indication.TOTAL_PASSED.equals(indication)) {
                assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureScopes(sigId)));

                assertNull(simpleReport.getSubIndication(sigId));
                assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));

                assertNotNull(simpleReport.getSignatureExtensionPeriodMax(sigId));
                ++numberOfValidSignatures;

            } else {
                SubIndication subIndication = simpleReport.getSubIndication(sigId);
                assertNotNull(subIndication);
                assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));

                if (SubIndication.TRY_LATER.equals(subIndication)) {
                    assertNotNull(simpleReport.getSignatureExtensionPeriodMax(sigId));
                }
            }
            assertNotNull(simpleReport.getSignatureQualification(sigId));

            List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(sigId);
            for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : signatureTimestamps) {
                String tstId = xmlTimestamp.getId();
                assertNotNull(tstId);

                Indication timestampIndication = simpleReport.getIndication(tstId);
                assertNotNull(timestampIndication);
                assertTrue(Indication.PASSED.equals(timestampIndication) || Indication.INDETERMINATE.equals(timestampIndication)
                        || Indication.FAILED.equals(timestampIndication));
                if (timestampIndication != Indication.PASSED) {
                    assertNotNull(simpleReport.getSubIndication(tstId));
                    assertTrue(Utils.isCollectionNotEmpty(simpleReport.getAdESValidationErrors(tstId)));
                }
                assertNotNull(simpleReport.getTimestampQualification(tstId));
            }
        }
        assertEquals(simpleReport.getValidSignaturesCount(), numberOfValidSignatures);

        List<String> timestampIdList = simpleReport.getTimestampIdList();
        for (String tstId : timestampIdList) {
            Indication indication = simpleReport.getIndication(tstId);
            assertNotNull(indication);
            assertTrue(Indication.PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                    || Indication.FAILED.equals(indication));
            if (indication != Indication.PASSED) {
                assertNotNull(simpleReport.getSubIndication(tstId));
                assertTrue(Utils.isCollectionNotEmpty(simpleReport.getAdESValidationErrors(tstId)));
            }
            assertNotNull(simpleReport.getTimestampQualification(tstId));
        }

        assertNotNull(simpleReport.getValidationTime());
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        // TODO : implement ETSI VR support
    }

}
