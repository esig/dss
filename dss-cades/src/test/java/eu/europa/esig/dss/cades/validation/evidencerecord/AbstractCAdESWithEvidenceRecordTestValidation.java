package eu.europa.esig.dss.cades.validation.evidencerecord;

import eu.europa.esig.dss.cades.validation.AbstractCAdESTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;
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

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractCAdESWithEvidenceRecordTestValidation extends AbstractCAdESTestValidation {

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
            assertTrue(Utils.isCollectionNotEmpty(evidenceRecords));

            for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
                List<XmlDigestMatcher> digestMatcherList = evidenceRecord.getDigestMatchers();
                for (XmlDigestMatcher digestMatcher : digestMatcherList) {
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                }

                List<XmlSignatureScope> evidenceRecordScopes = evidenceRecord.getEvidenceRecordScopes();
                assertEquals(diagnosticData.getSignatures().size(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigFileFound = false;
                for (XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (signature.getSignatureFilename().equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);

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
                if (SignatureLevel.XAdES_BASELINE_B != signature.getSignatureFormat()) {
                    assertTrue(coversTimestamps);
                } else if (SignatureLevel.XAdES_BASELINE_T != signature.getSignatureFormat()) {
                    assertTrue(coversRevocationData);
                }

                int tstCounter = 0;

                List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
                for (TimestampWrapper timestamp : timestamps) {
                    assertTrue(timestamp.isMessageImprintDataFound());
                    assertTrue(timestamp.isMessageImprintDataIntact());
                    assertTrue(timestamp.isSignatureIntact());
                    assertTrue(timestamp.isSignatureValid());

                    List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
                    assertEquals(diagnosticData.getSignatures().size(), Utils.collectionSize(timestampScopes));

                    sigFileFound = false;
                    for (XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (signature.getSignatureFilename().equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);

                    boolean coversEvidenceRecord = false;
                    coversSignature = false;
                    coversSignedData = false;
                    coversCertificates = false;
                    coversRevocationData = false;
                    coversTimestamps = false;
                    List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
                    assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
                    for (XmlTimestampedObject reference : timestampedObjects) {
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
                        } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                            coversEvidenceRecord = true;
                        }
                    }

                    assertTrue(coversEvidenceRecord);
                    assertTrue(coversSignature);
                    assertTrue(coversSignedData);
                    assertTrue(coversCertificates);
                    if (SignatureLevel.XAdES_BASELINE_B != signature.getSignatureFormat()) {
                        assertTrue(coversTimestamps);
                    } else if (SignatureLevel.XAdES_BASELINE_T != signature.getSignatureFormat()) {
                        assertTrue(coversRevocationData);
                    }

                    if (tstCounter > 0) {
                        List<XmlDigestMatcher> tstDigestMatcherList = timestamp.getDigestMatchers();
                        assertTrue(Utils.isCollectionNotEmpty(tstDigestMatcherList));

                        boolean archiveTstDigestFound = false;
                        boolean archiveTstSequenceDigestFound = false;
                        for (XmlDigestMatcher digestMatcher : tstDigestMatcherList) {
                            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(digestMatcher.getType())) {
                                archiveTstDigestFound = true;
                            } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(digestMatcher.getType())) {
                                archiveTstSequenceDigestFound = true;
                            }
                            assertTrue(digestMatcher.isDataFound());
                            assertTrue(digestMatcher.isDataIntact());
                        }

                        if (tstDigestMatcherList.size() == 1) {
                            assertTrue(archiveTstDigestFound);
                        } else {
                            assertTrue(archiveTstSequenceDigestFound);
                        }
                    }

                    ++tstCounter;
                }
            }
        }
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertTrue(Utils.isCollectionNotEmpty(signatureEvidenceRecords));

            for (XmlEvidenceRecord xmlEvidenceRecord : signatureEvidenceRecords) {
                assertNotNull(xmlEvidenceRecord.getPOETime());
                assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
                assertEquals(simpleReport.getSignatureIdList().size(), Utils.collectionSize(evidenceRecordScopes));

                boolean sigFileFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                    assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                    if (simpleReport.getDocumentFilename().equals(evidenceRecordScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);

                XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
                assertNotNull(timestamps);
                assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

                for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                    assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                    List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                    assertEquals(simpleReport.getSignatureIdList().size(), Utils.collectionSize(timestampScopes));

                    sigFileFound = false;
                    for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                        assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                        if (simpleReport.getDocumentFilename().equals(tstScope.getName())) {
                            sigFileFound = true;
                        }
                    }
                    assertTrue(sigFileFound);
                }

            }
        }
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        super.verifyETSIValidationReport(etsiValidationReportJaxb);

        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationReports));

        SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
        assertNotEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationReportType.getSignatureValidationStatus().getMainIndication());

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
