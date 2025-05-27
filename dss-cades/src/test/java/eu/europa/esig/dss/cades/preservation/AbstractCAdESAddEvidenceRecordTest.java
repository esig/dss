package eu.europa.esig.dss.cades.preservation;

import eu.europa.esig.dss.cades.evidencerecord.CAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.validation.evidencerecord.AbstractCAdESWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.model.DSSDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class AbstractCAdESAddEvidenceRecordTest extends AbstractCAdESWithEvidenceRecordTestValidation {

    protected abstract DSSDocument getSignatureDocument();

    protected abstract DSSDocument getEvidenceRecordDocument();

    protected CAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        CAdESEvidenceRecordIncorporationParameters parameters = new CAdESEvidenceRecordIncorporationParameters();
        parameters.setDetachedContents(getDetachedContents());
        return parameters;
    }

    protected CAdESService getService() {
        return new CAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        CAdESService service = getService();
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
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1 + getNumberOfCoveredDocuments(); // signature + document / detached docs
    }

    protected int getNumberOfCoveredDocuments() {
        return 1;
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        super.checkEvidenceRecords(diagnosticData);
    }

    @Override
    protected void checkEvidenceRecordIncorporationType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordIncorporationType(evidenceRecord);

        assertEquals(getEvidenceRecordIncorporationType(), evidenceRecord.getIncorporationType());
    }

    protected abstract EvidenceRecordIncorporationType getEvidenceRecordIncorporationType();
}
