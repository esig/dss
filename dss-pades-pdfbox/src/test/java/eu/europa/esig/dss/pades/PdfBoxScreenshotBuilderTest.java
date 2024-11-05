package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxScreenshotBuilder;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PdfBoxScreenshotBuilderTest {
    
    private final char[] correctProtectionPhrase = new char[] { ' ' };
    private final char[] wrongProtectionPhrase = new char[] { 'A', 'A', 'A', 'A' };

    private DSSDocument sampleDocument;
    private DSSDocument protectedDocument;

    @BeforeEach
    void init() {
        sampleDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        protectedDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"),
                "sample.pdf", MimeTypeEnum.PDF);
    }

    @Test
    void nullTest() {
        Exception exception = assertThrows(NullPointerException.class, () -> PdfBoxScreenshotBuilder.fromDocument(null));
        assertEquals("PDF Document shall be defined!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () -> PdfBoxScreenshotBuilder.fromDocument(null));
        assertEquals("PDF Document shall be defined!", exception.getMessage());

        exception = assertThrows(IndexOutOfBoundsException.class, () -> PdfBoxScreenshotBuilder.fromDocument(sampleDocument));
        assertEquals("Index out of bounds: 0", exception.getMessage());
    }

    @Test
    void generateScreenshotTest() {
        DSSDocument screenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateScreenshot(1);
        assertNotNull(screenshot);

        Exception exception = assertThrows(IndexOutOfBoundsException.class,
                () -> PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateScreenshot(2));
        assertEquals("1-based index out of bounds: 2", exception.getMessage());
    }

    @Test
    void generateScreenshotWithPassTest() {
        DSSDocument screenshot = PdfBoxScreenshotBuilder.fromDocument(protectedDocument, correctProtectionPhrase).generateScreenshot(1);
        assertNotNull(screenshot);

        Exception exception = assertThrows(DSSException.class, () -> PdfBoxScreenshotBuilder.fromDocument(protectedDocument, wrongProtectionPhrase).generateScreenshot(1));
        assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());

        exception = assertThrows(DSSException.class, () -> PdfBoxScreenshotBuilder.fromDocument(protectedDocument).generateScreenshot(1));
        assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());
    }

    @Test
    void generateScreenshotWithTempFileTest() throws IOException {
        TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        DSSDocument fileScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null)
                .setDSSResourcesHandler(tempFileResourcesHandlerBuilder).generateScreenshot(1);
        assertNotNull(fileScreenshot);
        assertInstanceOf(FileDocument.class, fileScreenshot);

        DSSDocument inMemoryScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null)
                .generateScreenshot(1);
        assertNotNull(inMemoryScreenshot);
        assertInstanceOf(InMemoryDocument.class, inMemoryScreenshot);

        assertVisuallyEqual(fileScreenshot, inMemoryScreenshot);
    }

    @Test
    void generateBufferedImageScreenshotWithPdfInFileSettingTest() {
        BufferedImage fileScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null)
                .setMemoryUsageSetting(PdfMemoryUsageSetting.fileOnly()).generateBufferedImageScreenshot(1);
        assertNotNull(fileScreenshot);

        BufferedImage inMemoryScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null)
                .setMemoryUsageSetting(PdfMemoryUsageSetting.memoryFull()).generateBufferedImageScreenshot(1);
        assertNotNull(inMemoryScreenshot);

        assertVisuallyEqual(fileScreenshot, inMemoryScreenshot);
    }

    private void assertVisuallyEqual(DSSDocument documentOne, DSSDocument documentTwo) throws IOException {
        BufferedImage bufferedImageOne = ImageUtils.toBufferedImage(documentOne);
        BufferedImage bufferedImageTwo = ImageUtils.toBufferedImage(documentTwo);
        assertVisuallyEqual(bufferedImageOne, bufferedImageTwo);
    }

    private void assertVisuallyEqual(BufferedImage bufferedImageOne, BufferedImage bufferedImageTwo) {
        assertEquals(0, ImageUtils.drawSubtractionImage(bufferedImageOne, bufferedImageTwo,
                new BufferedImage(bufferedImageOne.getWidth(), bufferedImageOne.getHeight(), BufferedImage.TYPE_INT_RGB)));
    }
    
}
