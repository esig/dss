package eu.europa.esig.dss.asic.xades.preservation.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ASiCEWithXAdESAddXMLSignatureEvidenceRecordTest extends AbstractASiCWithXAdESAddSignatureEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/onefile-ok.asice");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-onefile-ok.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

}
