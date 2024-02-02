package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.validationreport.enums.ObjectType;
import eu.europa.esig.validationreport.enums.TypeOfProof;
import eu.europa.esig.validationreport.jaxb.POEProvisioningType;
import eu.europa.esig.validationreport.jaxb.POEType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectListType;
import eu.europa.esig.validationreport.jaxb.ValidationObjectType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordWrongFileValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-simple.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("0".getBytes()));
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(3, referenceValidations.size());
        for (ReferenceValidation referenceValidation : referenceValidations) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, referenceValidation.getType());
            assertNull(referenceValidation.getName());
            assertFalse(referenceValidation.isFound());
            assertFalse(referenceValidation.isIntact());
        }

        assertEquals(1, Utils.collectionSize(evidenceRecord.getTimestamps()));
        TimestampToken timestampToken = evidenceRecord.getTimestamps().get(0);
        List<ReferenceValidation> refValidations = timestampToken.getReferenceValidations();
        assertEquals(0, refValidations.size());
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertTrue(Utils.isCollectionEmpty(evidenceRecordWrapper.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        assertTrue(Utils.isCollectionEmpty(evidenceRecordWrapper.getCoveredObjects()));
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
                assertTrue(Utils.isCollectionEmpty(poeProvisioning.getValidationObject()));
                evidenceRecordFound = true;

            } else if (ObjectType.TIMESTAMP == validationObjectType.getObjectType()) {
                tstFound = true;
            }
        }
        assertTrue(evidenceRecordFound);
        assertTrue(tstFound);
    }

}
