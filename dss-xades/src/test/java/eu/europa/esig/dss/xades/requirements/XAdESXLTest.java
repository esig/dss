package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESXLTest extends XAdESXTest {

    @BeforeEach
    @Override
    public void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_XL);
    }

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    public void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        checkCertificateValuesPresent();
        checkRevocationValuesPresent();
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_XL, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
        super.verifySourcesAndDiagnosticData(signatures, diagnosticData);
    }

}
