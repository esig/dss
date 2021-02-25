package eu.europa.esig.dss.xades.requirements;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.xpath.XPathExpressionException;
import java.util.List;

public class XAdESCTest extends XAdESBaselineTTest {

    @BeforeEach
    @Override
    public void init() throws Exception {
        super.init();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_C);
    }

    /**
     * Checks UnsignedSignatureProperties present for T/LT/LTA levels
     */
    public void checkUnsignedProperties() throws XPathExpressionException {
        super.checkUnsignedProperties();

        checkCompleteCertificateRefsV2Present();
        checkCompleteRevocationRefsPresent();
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> signatures, DiagnosticData diagnosticData) {
        super.verifySourcesAndDiagnosticDataWithOrphans(signatures, diagnosticData);
    }

}
