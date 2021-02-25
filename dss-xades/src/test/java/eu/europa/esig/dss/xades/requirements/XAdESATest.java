package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class XAdESATest extends XAdESXLTest {

    @BeforeEach
    @Override
    public void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_A);
    }

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    public void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        checkArchiveTimeStampPresent();
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
