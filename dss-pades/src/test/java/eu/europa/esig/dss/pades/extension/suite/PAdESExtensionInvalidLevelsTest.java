package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESExtensionInvalidLevelsTest extends AbstractPAdESTestExtension {

    private SignatureLevel originalSignatureLevel;
    private SignatureLevel finalSignatureLevel;

    @Test
    public void tLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'PAdES-BASELINE-T'. The signature is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltaLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.PAdES_BASELINE_LTA;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'PAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'PAdES-BASELINE-T'. The signature is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LT;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'PAdES-BASELINE-LT'. The signature is already extended with LTA level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.PAdES_BASELINE_LTA;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(3, reports.getDiagnosticData().getTimestampList().size());
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

}
