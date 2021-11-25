package eu.europa.esig.dss.pdfa;

import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PDFAStructureValidatorTest {

    private static PDFAStructureValidator pdfaStructureValidator = new PDFAStructureValidator();

    @Test
    public void validPdf1Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/not_signed_pdfa.pdf"));
        assertEquals("PDF/A-1B", result.getProfileId());
        assertTrue(result.isCompliant());
        assertTrue(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    public void invalidPdf1Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/sample.pdf"));
        assertEquals("PDF/A-1B", result.getProfileId());
        assertFalse(result.isCompliant());
        assertFalse(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    public void validPdf2Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/testdoc.pdf"));
        assertEquals("PDF/A-2U", result.getProfileId());
        assertTrue(result.isCompliant());
        assertTrue(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

    @Test
    public void invalidPdf2Test() {
        PDFAValidationResult result = pdfaStructureValidator.validate(new FileDocument("src/test/resources/testdoc-signed.pdf"));
        assertEquals("PDF/A-2U", result.getProfileId());
        assertFalse(result.isCompliant());
        assertFalse(Utils.isCollectionEmpty(result.getErrorMessages()));
    }

}
