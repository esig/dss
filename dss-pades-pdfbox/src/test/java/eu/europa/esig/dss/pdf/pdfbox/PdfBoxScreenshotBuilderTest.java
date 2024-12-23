/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
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

class PdfBoxScreenshotBuilderTest {
    
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
    }

    @Test
    void generateScreenshotTest() {
        DSSDocument screenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateScreenshot(1);
        assertNotNull(screenshot);

        Exception exception = assertThrows(IndexOutOfBoundsException.class,
                () -> PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateScreenshot(0));
        assertEquals("Index out of bounds: 0", exception.getMessage());

        exception = assertThrows(IndexOutOfBoundsException.class,
                () -> PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateScreenshot(2));
        assertEquals("1-based index out of bounds: 2", exception.getMessage());
    }

    @Test
    void generateScreenshotWithPassTest() {
        DSSDocument screenshot = PdfBoxScreenshotBuilder.fromDocument(protectedDocument, correctProtectionPhrase).generateScreenshot(1);
        assertNotNull(screenshot);

        Exception exception = assertThrows(DSSException.class,
                () -> PdfBoxScreenshotBuilder.fromDocument(protectedDocument, wrongProtectionPhrase).generateScreenshot(1));
        assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());

        exception = assertThrows(DSSException.class,
                () -> PdfBoxScreenshotBuilder.fromDocument(protectedDocument).generateScreenshot(1));
        assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());
    }

    @Test
    void generateScreenshotWithTempFileTest() throws IOException {
        TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        DSSDocument fileScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null)
                .setDSSResourcesHandlerBuilder(tempFileResourcesHandlerBuilder).generateScreenshot(1);
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
