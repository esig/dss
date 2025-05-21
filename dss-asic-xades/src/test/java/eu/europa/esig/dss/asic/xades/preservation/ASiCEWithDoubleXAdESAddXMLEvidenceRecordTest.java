package eu.europa.esig.dss.asic.xades.preservation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithDoubleXAdESAddXMLEvidenceRecordTest extends AbstractASiCWithXAdESAddEvidenceRecordTest {

    private String signatureId = null;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/multifiles-ok.asice");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-multifiles-ok.xml");
    }

    @Override
    protected void checkEvidenceRecords(DiagnosticData diagnosticData) {
        int sigWithErCounter = 0;
        int sigWithoutErCounter = 0;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (Utils.isCollectionNotEmpty(signature.getEvidenceRecords())) {
                checkEvidenceRecordCoverage(diagnosticData, signature);
                ++sigWithErCounter;
            } else {
                ++sigWithoutErCounter;
            }
        }
        assertEquals(1, sigWithErCounter);
        assertEquals(1, sigWithoutErCounter);
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            assertEquals(SignatureLevel.XAdES_BASELINE_B, signature.getSignatureFormat());
        }
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfCoveredDocuments() {
        return 2;
    }

    @Override
    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        XAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setSignatureId(signatureId);
        return parameters;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("More than one signature found in a document! " +
                "Please provide a signatureId within the parameters.", exception.getMessage());

        signatureId = "not-existing";
        exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("A signature with id 'not-existing' has not been found!", exception.getMessage());

        // wrong signature
        signatureId = "id-f2d402c33667a271607cec86295fbe09";
        exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to the digest computed " +
                        "on the signature and/or detached content!",
                exception.getMessage());

        // wrong signature
        signatureId = "id-27c5484f172975dd4233d5c3ff356396";
        super.addERAndValidate();
    }

}
