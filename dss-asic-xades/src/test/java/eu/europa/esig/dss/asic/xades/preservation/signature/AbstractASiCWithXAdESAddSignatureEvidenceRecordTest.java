package eu.europa.esig.dss.asic.xades.preservation.signature;

import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.asic.xades.validation.evidencerecord.AbstractASiCWithXAdESWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class AbstractASiCWithXAdESAddSignatureEvidenceRecordTest extends AbstractASiCWithXAdESWithEvidenceRecordTestValidation {

    protected abstract DSSDocument getSignatureDocument();

    protected abstract DSSDocument getEvidenceRecordDocument();

    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        XAdESEvidenceRecordIncorporationParameters parameters = new XAdESEvidenceRecordIncorporationParameters();
        parameters.setDetachedContents(getDetachedContents());
        return parameters;
    }

    protected ASiCWithXAdESService getService() {
        return new ASiCWithXAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument getSignedDocument() {
        ASiCWithXAdESService service = getService();
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

        assertEquals(getEvidenceRecordType(), evidenceRecord.getEvidenceRecordType());
    }

    protected abstract EvidenceRecordTypeEnum getEvidenceRecordType();

}
