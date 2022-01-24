package eu.europa.esig.dss.asic.xades.extension.asics;

import eu.europa.esig.dss.asic.xades.extension.AbstractASiCWithXAdESTestExtension;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ASiCsExtensionWithXAdESInvalidLevelsTest extends AbstractASiCWithXAdESTestExtension {

    private SignatureLevel originalSignatureLevel;
    private SignatureLevel finalSignatureLevel;

    @Test
    public void tLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'XAdES-BASELINE-T'. The signature is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
        DSSDocument extendedSignature = extendSignature(signedDocument);
        reports = verify(extendedSignature);
        checkFinalLevel(reports.getDiagnosticData());
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void ltaLevelExtensionTest() throws Exception {
        originalSignatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
        DSSDocument signedDocument = getSignedDocument(getOriginalDocument());
        Reports reports = verify(signedDocument);
        checkOriginalLevel(reports.getDiagnosticData());
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_B;
        Exception exception = assertThrows(UnsupportedOperationException.class, () -> extendSignature(signedDocument));
        assertEquals("Unsupported signature format 'XAdES-BASELINE-B' for extension.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'XAdES-BASELINE-T'. The signature is already extended with LT level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("Cannot extend signature to 'XAdES-BASELINE-LT'. The signature is already extended with LTA level.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
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
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_S;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

}