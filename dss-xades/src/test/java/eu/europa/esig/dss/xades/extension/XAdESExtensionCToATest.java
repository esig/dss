package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class XAdESExtensionCToATest extends AbstractXAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_C;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.XAdES_A;
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures, DiagnosticData diagnosticData) {
        if (SignatureLevel.XAdES_C.equals(diagnosticData.getFirstSignatureFormat())) {
            super.verifySourcesAndDiagnosticDataWithOrphans(advancedSignatures, diagnosticData);

        } else if (SignatureLevel.XAdES_A.equals(diagnosticData.getFirstSignatureFormat())) {
            super.verifySourcesAndDiagnosticData(advancedSignatures, diagnosticData);

        } else {
            fail("Unexpected format " + diagnosticData.getFirstSignatureFormat());
        }
    }

    @Override
    protected void checkFinalLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_A, diagnosticData.getFirstSignatureFormat());
    }

}
