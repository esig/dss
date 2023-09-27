package eu.europa.esig.dss.evidencerecord.common.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
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
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.CryptoInformationType;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectRepresentationType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportDataType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

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
        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationReports));

        SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
        assertEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationReportType.getSignatureValidationStatus().getMainIndication());

        ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);

        List<ValidationObjectType> validationObjects = signatureValidationObjects.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        boolean evidenceRecordFound = false;
        boolean tstFound = false;
        for (ValidationObjectType validationObjectType : validationObjects) {
            if (ObjectType.EVIDENCE_RECORD == validationObjectType.getObjectType()) {
                assertNotNull(validationObjectType.getObjectType());
                POEType poeType = validationObjectType.getPOE();
                assertNotNull(poeType);
                assertNull(poeType.getPOEObject());
                assertEquals(TypeOfProof.VALIDATION, poeType.getTypeOfProof());
                assertNotNull(poeType.getPOETime());

                POEProvisioningType poeProvisioning = validationObjectType.getPOEProvisioning();
                assertNotNull(poeProvisioning);
                assertNotNull(poeProvisioning.getPOETime());
                assertTrue(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

                SignatureValidationReportType validationReport = validationObjectType.getValidationReport();
                assertNotNull(validationReport);

                ValidationStatusType signatureValidationStatus = validationReport.getSignatureValidationStatus();
                assertNotNull(signatureValidationStatus);
                assertNotNull(signatureValidationStatus.getMainIndication());
                if (Indication.PASSED != signatureValidationStatus.getMainIndication()) {
                    assertTrue(Utils.isCollectionNotEmpty(signatureValidationStatus.getSubIndication()));
                    assertNotNull(signatureValidationStatus.getSubIndication().get(0));
                }

                List<ValidationReportDataType> associatedValidationReportData = signatureValidationStatus.getAssociatedValidationReportData();
                assertEquals(1, associatedValidationReportData.size());

                ValidationReportDataType validationReportDataType = associatedValidationReportData.get(0);
                CryptoInformationType cryptoInformation = validationReportDataType.getCryptoInformation();
                assertNotNull(cryptoInformation);
                assertEquals(1, cryptoInformation.getValidationObjectId().getVOReference().size());
                assertNotNull(DigestAlgorithm.forXML(cryptoInformation.getAlgorithm()));
                assertTrue(cryptoInformation.isSecureAlgorithm());
                assertNotNull(cryptoInformation.getNotAfter());

                ValidationObjectRepresentationType validationObjectRepresentation = validationObjectType.getValidationObjectRepresentation();
                assertNotNull(validationObjectRepresentation);

                List<Object> directOrBase64OrDigestAlgAndValue = validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue();
                assertEquals(1, directOrBase64OrDigestAlgAndValue.size());

                if (getTokenExtractionStrategy().isEvidenceRecord()) {
                    assertTrue(directOrBase64OrDigestAlgAndValue.get(0) instanceof byte[]);
                    assertNotNull(directOrBase64OrDigestAlgAndValue.get(0));
                } else {
                    assertTrue(directOrBase64OrDigestAlgAndValue.get(0) instanceof DigestAlgAndValueType);
                    DigestAlgAndValueType digestAlgAndValueType = (DigestAlgAndValueType) directOrBase64OrDigestAlgAndValue.get(0);
                    assertNotNull(DigestAlgorithm.forXML(digestAlgAndValueType.getDigestMethod().getAlgorithm()));
                    assertNotNull(digestAlgAndValueType.getDigestValue());
                }

                evidenceRecordFound = true;

            } else if (ObjectType.TIMESTAMP == validationObjectType.getObjectType()) {
                tstFound = true;
            }
        }
        assertTrue(evidenceRecordFound);
        assertTrue(tstFound);
    }

}
