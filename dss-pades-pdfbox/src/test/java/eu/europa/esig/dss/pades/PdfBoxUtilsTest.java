/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdfBoxUtilsTest {

	private final String correctProtectionPhrase = " ";
	private final String wrongProtectionPhrase = "AAAA";

	private DSSDocument sampleDocument;
	private DSSDocument protectedDocument;
	private DSSDocument twoPagesDocument;

	@BeforeEach
	public void init() {
		sampleDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		protectedDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"),
				"sample.pdf", MimeType.PDF);
		twoPagesDocument = new InMemoryDocument(getClass().getResourceAsStream("/empty-two-pages.pdf"));
	}

	@Test
	public void generateScreenshotTest() {
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(sampleDocument, 1);
		assertNotNull(screenshot);

		Exception exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateScreenshot(sampleDocument, 0));
		assertEquals("Index out of bounds: 0", exception.getMessage());

		exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateScreenshot(sampleDocument, 2));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());

		exception = assertThrows(NullPointerException.class, () -> PdfBoxUtils.generateScreenshot(null, 1));
		assertEquals("pdfDocument shall be defined!", exception.getMessage());
	}

	@Test
	public void generateScreenshotWithPassTest() {
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(protectedDocument, correctProtectionPhrase, 1);
		assertNotNull(screenshot);

		Exception exception = assertThrows(DSSException.class,
				() -> PdfBoxUtils.generateScreenshot(protectedDocument, wrongProtectionPhrase, 1));
		assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());

		exception = assertThrows(DSSException.class, () -> PdfBoxUtils.generateScreenshot(protectedDocument, 1));
		assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());
	}

	@Test
	public void generateSubtractionImageTest() {
		DSSDocument subtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, null, 1, protectedDocument,
				correctProtectionPhrase, 1);
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(twoPagesDocument, null, 1, twoPagesDocument, null, 2);
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, twoPagesDocument, 1);
		assertNotNull(subtractionImage);

		Exception exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateSubtractionImage(sampleDocument, twoPagesDocument, 2));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());
	}

	@Test
	public void generateScreenshotWithTempFileTest() throws IOException  {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();

		DSSDocument fileScreenshot = PdfBoxUtils.generateScreenshot(sampleDocument, null, 1,
				tempFileResourcesHandlerBuilder.createResourcesHandler());
		assertNotNull(fileScreenshot);
		assertTrue(fileScreenshot instanceof FileDocument);

		DSSDocument inMemoryScreenshot = PdfBoxUtils.generateScreenshot(sampleDocument, 1);
		assertNotNull(inMemoryScreenshot);
		assertFalse(inMemoryScreenshot instanceof FileDocument);

		assertVisuallyEqual(fileScreenshot, inMemoryScreenshot);

		DSSDocument fileSubtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, null, 1,
				twoPagesDocument, null, 1, tempFileResourcesHandlerBuilder.createResourcesHandler());
		assertNotNull(fileSubtractionImage);
		assertTrue(fileSubtractionImage instanceof FileDocument);

		DSSDocument inMemorySubtractionImage = PdfBoxUtils.generateSubtractionImage(sampleDocument, twoPagesDocument, 1);
		assertNotNull(inMemorySubtractionImage);
		assertFalse(inMemorySubtractionImage instanceof FileDocument);

		assertVisuallyEqual(fileSubtractionImage, inMemorySubtractionImage);
	}

	private void assertVisuallyEqual(DSSDocument documentOne, DSSDocument documentTwo) throws IOException {
		BufferedImage bufferedImageOnw = ImageUtils.toBufferedImage(documentOne);
		BufferedImage bufferedImageTwo = ImageUtils.toBufferedImage(documentTwo);
		assertEquals(0, ImageUtils.drawSubtractionImage(bufferedImageOnw, bufferedImageTwo,
				new BufferedImage(bufferedImageOnw.getWidth(), bufferedImageOnw.getHeight(), BufferedImage.TYPE_INT_RGB)));
	}

}
