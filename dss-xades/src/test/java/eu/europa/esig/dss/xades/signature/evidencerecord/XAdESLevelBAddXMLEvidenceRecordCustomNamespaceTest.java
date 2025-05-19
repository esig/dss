package eu.europa.esig.dss.xades.signature.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.evidencerecord.XAdESEvidenceRecordIncorporationParameters;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESLevelBAddXMLEvidenceRecordCustomNamespaceTest extends AbstractXAdESAddEvidenceRecordTest {

    private DSSNamespace namespace;

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/X-B-B.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-custom-namespace-X-B-B.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected XAdESEvidenceRecordIncorporationParameters getEvidenceRecordIncorporationParameters() {
        XAdESEvidenceRecordIncorporationParameters parameters = super.getEvidenceRecordIncorporationParameters();
        parameters.setXadesERNamespace(namespace);
        return parameters;
    }

    @Test
    @Override
    public void addERAndValidate() {
        namespace = new DSSNamespace("wrong.uri", "xers");

        Exception exception = assertThrows(IllegalArgumentException.class, super::addERAndValidate);
        assertEquals("The provided URI does not match the 132-3 definition!", exception.getMessage());

        namespace = new DSSNamespace(XAdESNamespace.XADES_EVIDENCERECORD_NAMESPACE.getUri(), "xers");
        super.addERAndValidate();
    }

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument signedDocument = super.getSignedDocument();
        assertTrue(new String(DSSUtils.toByteArray(signedDocument)).contains(
                "xers:SealingEvidenceRecords xmlns:xers=\"http://uri.etsi.org/19132/v1.1.1#\""));
        return signedDocument;
    }

}
