package eu.europa.esig.dss.asic.xades.preservation.container;

import eu.europa.esig.dss.asic.xades.evidencerecord.ASiCWithXAdESContainerEvidenceRecordParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.evidencerecord.AbstractASiCWithXAdESWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.ValidationStatusType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractASiCWithXAdESTestAddContainerEvidenceRecord extends AbstractASiCWithXAdESWithEvidenceRecordTestValidation {

    protected abstract List<DSSDocument> getDocumentsToPreserve();

    protected abstract DSSDocument getEvidenceRecordDocument();

    protected ASiCWithXAdESContainerEvidenceRecordParameters getASiCContainerEvidenceRecordParameters() {
        ASiCWithXAdESContainerEvidenceRecordParameters parameters = new ASiCWithXAdESContainerEvidenceRecordParameters();
        parameters.setContainerType(getASiCContainerType());
        return parameters;
    }

    protected abstract ASiCContainerType getASiCContainerType();

    protected ASiCWithXAdESService getService() {
        return new ASiCWithXAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        ASiCWithXAdESService service = getService();
        return service.addContainerEvidenceRecord(getDocumentsToPreserve(), getEvidenceRecordDocument(), getASiCContainerEvidenceRecordParameters());
    }

    @Override
    public void validate() {
        // skip
    }

    @Test
    public void addERAndValidate() {
        super.validate();
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        // skip (out of scope)
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);
        checkEvidenceRecordFilename(diagnosticData);
    }

    protected void checkEvidenceRecordFilename(DiagnosticData diagnosticData) {
        for (EvidenceRecordWrapper evidenceRecordWrapper : diagnosticData.getEvidenceRecords()) {
            if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                assertEquals("META-INF/evidencerecord.xml", evidenceRecordWrapper.getFilename());
            } else if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecordWrapper.getEvidenceRecordType()) {
                assertEquals("META-INF/evidencerecord.ers", evidenceRecordWrapper.getFilename());
            } else {
                fail(String.format("The evidence record type '%s' is not supported!", evidenceRecordWrapper.getEvidenceRecordType()));
            }
        }
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(getEvidenceRecordType(), evidenceRecord.getEvidenceRecordType());
    }

    protected abstract EvidenceRecordTypeEnum getEvidenceRecordType();

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        assertEquals(getASiCContainerType(), diagnosticData.getContainerType());
        if (ASiCContainerType.ASiC_E == getASiCContainerType()) {
            List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
            assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
            for (XmlManifestFile xmlManifestFile : manifestFiles) {
                if (xmlManifestFile.getSignatureFilename().contains("evidencerecord")) {
                    assertTrue(xmlManifestFile.getFilename().startsWith("META-INF/ASiCEvidenceRecordManifest"));
                    assertTrue(xmlManifestFile.getFilename().endsWith(".xml"));
                    assertEquals(getNumberOfExpectedEvidenceScopes(), xmlManifestFile.getEntries().size());
                }
            }
        }
    }

    @Override
    protected void validateValidationStatus(ValidationStatusType signatureValidationStatus) {
        // skip
    }

}
