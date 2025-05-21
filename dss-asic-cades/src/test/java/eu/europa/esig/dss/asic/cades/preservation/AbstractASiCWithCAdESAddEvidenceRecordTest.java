package eu.europa.esig.dss.asic.cades.preservation;

import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.cades.validation.evidencerecord.AbstractASiCWithCAdESWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class AbstractASiCWithCAdESAddEvidenceRecordTest extends AbstractASiCWithCAdESWithEvidenceRecordTestValidation {

    protected abstract DSSDocument getSignatureDocument();

    protected abstract DSSDocument getEvidenceRecordDocument();

    protected CAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        CAdESEvidenceRecordIncorporationParameters parameters = new CAdESEvidenceRecordIncorporationParameters();
        parameters.setDetachedContents(getDetachedContents());
        return parameters;
    }

    protected ASiCWithCAdESService getService() {
        return new ASiCWithCAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        ASiCWithCAdESService service = getService();
        return service.addSignatureEvidenceRecord(getSignatureDocument(), getEvidenceRecordDocument(), getEvidenceRecordIncorporationParameters());
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
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        // skip (out of scope)
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        // skip
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1 + getNumberOfCoveredDocuments(); // signature + document / detached docs
    }

    protected int getNumberOfCoveredDocuments() {
        return 1;
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

}
