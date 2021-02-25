package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;

public class XAdESXTest extends XAdESCTest {

    @BeforeEach
    @Override
    public void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_X);
    }

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    public void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        checkSigAndRefsTimeStampV2Present();
    }

}
