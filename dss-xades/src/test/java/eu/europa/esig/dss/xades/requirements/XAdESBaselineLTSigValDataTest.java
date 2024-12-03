package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.ValidationDataContainerType;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESBaselineLTSigValDataTest extends XAdESBaselineTTest {

    @BeforeEach
    @Override
    void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        XAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.setValidationDataContainerType(ValidationDataContainerType.CERTIFICATE_REVOCATION_VALUES_AND_TIMESTAMP_VALIDATION_DATA);
        return signatureParameters;
    }

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    @Override
    protected void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        assertTrue(checkCertificateValuesPresent());
        assertTrue(checkRevocationValuesPresent());
        assertFalse(checkTimeStampValidationDataPresent());
        assertFalse(checkAnyValidationDataPresent());
    }

}
