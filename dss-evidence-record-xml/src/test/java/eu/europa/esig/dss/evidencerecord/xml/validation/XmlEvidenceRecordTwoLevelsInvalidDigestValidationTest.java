/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
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

class XmlEvidenceRecordTwoLevelsInvalidDigestValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-two-levels.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        // digest from last level
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "AuXvCat2Iu4KxJAd/hPwCFSm0+hF+BWlDsvfKvEGpfg="));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        for (EvidenceRecord evidenceRecord : detachedEvidenceRecords) {
            List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
            for (ReferenceValidation referenceValidation : referenceValidationList) {
                assertTrue(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
            }

            List<TimestampedReference> coveredReferences = evidenceRecord.getTimestampedReferences();
            assertTrue(Utils.isCollectionEmpty(coveredReferences));

            int tstCounter = 0;

            List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
            for (TimestampToken timestampToken : timestamps) {
                assertNotNull(timestampToken.getTimeStampType());
                assertNotNull(timestampToken.getArchiveTimestampType());
                assertNotNull(timestampToken.getEvidenceRecordTimestampType());

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

                    assertEquals(EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstDigestFound);
                    assertEquals(EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestampToken.getEvidenceRecordTimestampType(), archiveTstSequenceDigestFound);

                } else {
                    assertEquals(EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP, timestampToken.getEvidenceRecordTimestampType());
                }

                ++tstCounter;
            }
        }
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(1, Utils.collectionSize(evidenceRecords));

        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecord.getDigestMatchers();
        assertEquals(1, digestMatchers.size());
        XmlDigestMatcher digestMatcher = digestMatchers.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, digestMatcher.getType());
        assertNotNull(digestMatcher.getDigestMethod());
        assertNotNull(digestMatcher.getDigestValue());
        assertTrue(digestMatcher.isDataFound());
        assertFalse(digestMatcher.isDataIntact());
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredObjects()));
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecord = evidenceRecords.get(0);
        assertEquals(1, evidenceRecord.getTimestampList().size());

        TimestampWrapper timestampWrapper = evidenceRecord.getTimestampList().get(0);
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampScopes()));
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
                assertFalse(Utils.isCollectionNotEmpty(poeProvisioning.getValidationObject()));

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
