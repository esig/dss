package eu.europa.esig.dss.asic.cades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCWithCAdESFormatDetectorTest {

    @Test
    void isSupportedZip() {
        final ASiCWithCAdESFormatDetector asicDetector = new ASiCWithCAdESFormatDetector();

        byte[] wrongBytes = new byte[] { 1, 2 };
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test")));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
        assertFalse(asicDetector.isSupportedZip(new InMemoryDocument(wrongBytes, "test.p7c")));

        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.asics")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/test.zip")));
        assertTrue(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/empty.zip")));

        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signature-policy.der")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/test.txt")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/document.odt")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_xades_er.sce")));
        assertFalse(asicDetector.isSupportedZip(new FileDocument("src/test/resources/signable/asic_xades_er.scs")));
    }

    @Test
    void isSupportedASiC() {
        final ASiCWithCAdESFormatDetector asicDetector = new ASiCWithCAdESFormatDetector();

        byte[] wrongBytes = new byte[] { 1, 2 };
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.PDF)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test")));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test", MimeTypeEnum.XML)));
        assertFalse(asicDetector.isSupportedASiC(new InMemoryDocument(wrongBytes, "test.p7c")));

        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/onefile-ok.asice")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/onefile-ok.asics")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/multifiles-ok.asice")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/multifiles-ok.asics")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/er-one-file.asics")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/validation/evidencerecord/er-multi-files.asice")));
        assertTrue(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_cades.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/test.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/empty.zip")));

        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signature-policy.der")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/test.txt")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_xades.zip")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/document.odt")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_xades_er.sce")));
        assertFalse(asicDetector.isSupportedASiC(new FileDocument("src/test/resources/signable/asic_xades_er.scs")));
    }
    
}
