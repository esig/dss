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
package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESLevelLTWithTwoEvidenceRecordsInSequenceValidationTest extends AbstractASiCWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-two-ers-sequence-multi-files.sce");
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestampedReferences(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        boolean firstErFound = false;
        boolean secondErFound = false;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            XmlManifestFile erManifest = null;
            for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                    erManifest = xmlManifestFile;
                }
            }
            assertNotNull(erManifest);

            boolean coversSignature = false;
            boolean coversSignedData = false;
            boolean coversCertificates = false;
            boolean coversRevocationData = false;
            boolean coversTimestamps = false;
            boolean coversEvidenceRecords = false;
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
                } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                    coversEvidenceRecords = true;
                }
            }
            assertTrue(coversSignature);
            assertTrue(coversSignedData);
            assertTrue(coversCertificates);
            assertTrue(coversTimestamps);
            assertTrue(coversRevocationData);
            if (coversEvidenceRecords) {
                assertEquals(6, coveredObjects.stream()
                        .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
                secondErFound = true;
            } else {
                assertEquals(4, coveredObjects.stream()
                        .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
                firstErFound = true;
            }
        }
        assertTrue(firstErFound);
        assertTrue(secondErFound);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        Set<String> evidenceRecordIds = new HashSet<>();
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertEquals(1, signatureEvidenceRecords.size());

            XmlEvidenceRecord xmlEvidenceRecord = signatureEvidenceRecords.get(0);
            evidenceRecordIds.add(xmlEvidenceRecord.getId());
            assertNotNull(xmlEvidenceRecord.getPOETime());
            assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(4, evidenceRecordScopes.size());

            boolean sigFileFound = false;
            for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
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
                assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));

                sigFileFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                    assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                    if (simpleReport.getTokenFilename(sigId).equals(tstScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);
            }
        }

        List<String> detachedEvidenceRecordIdList = simpleReport.getEvidenceRecordIdList();
        assertEquals(1, detachedEvidenceRecordIdList.size());
        assertFalse(evidenceRecordIds.contains(detachedEvidenceRecordIdList.get(0)));

        XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(detachedEvidenceRecordIdList.get(0));

        evidenceRecordIds.add(xmlEvidenceRecord.getId());
        assertNotNull(xmlEvidenceRecord.getPOETime());
        assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
        assertEquals(2, evidenceRecordScopes.size());

        XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
        assertNotNull(timestamps);
        assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

        for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
            assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
            assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));
        }
    }

    @Override
    protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
        List<SignatureValidationReportType> signatureValidationReports = etsiValidationReportJaxb.getSignatureValidationReport();
        assertTrue(Utils.isCollectionNotEmpty(signatureValidationReports));

        SignatureValidationReportType signatureValidationReportType = signatureValidationReports.get(0);
        assertNotEquals(Indication.NO_SIGNATURE_FOUND, signatureValidationReportType.getSignatureValidationStatus().getMainIndication());

        ValidationObjectListType signatureValidationObjects = etsiValidationReportJaxb.getSignatureValidationObjects();
        assertNotNull(signatureValidationObjects);

        List<ValidationObjectType> validationObjects = signatureValidationObjects.getValidationObject();
        assertTrue(Utils.isCollectionNotEmpty(validationObjects));

        int evidenceRecordCounter = 0;
        int tstCounter = 0;
        for (ValidationObjectType validationObjectType : validationObjects) {
            if (ObjectType.EVIDENCE_RECORD == validationObjectType.getObjectType()) {
                assertNotNull(validationObjectType.getObjectType());
                POEType poeType = validationObjectType.getPOE();
                assertNotNull(poeType);
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

                ++evidenceRecordCounter;

            } else if (ObjectType.TIMESTAMP == validationObjectType.getObjectType()) {
                ++tstCounter;
            }

            ValidationObjectRepresentationType validationObjectRepresentation = validationObjectType.getValidationObjectRepresentation();
            assertNotNull(validationObjectRepresentation);

            List<Object> directOrBase64OrDigestAlgAndValue = validationObjectRepresentation.getDirectOrBase64OrDigestAlgAndValue();
            assertEquals(1, directOrBase64OrDigestAlgAndValue.size());

            assertTrue(directOrBase64OrDigestAlgAndValue.get(0) instanceof DigestAlgAndValueType);
            DigestAlgAndValueType digestAlgAndValueType = (DigestAlgAndValueType) directOrBase64OrDigestAlgAndValue.get(0);
            assertNotNull(DigestAlgorithm.forXML(digestAlgAndValueType.getDigestMethod().getAlgorithm()));
            assertNotNull(digestAlgAndValueType.getDigestValue());
        }
        assertEquals(2, evidenceRecordCounter);
        assertEquals(3, tstCounter);
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 4;
    }

}
