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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import org.apache.pdfbox.io.MemoryUsageSetting;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.pdfbox.util.PdfBoxPageDocumentRequest;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;

class PdfBoxUtilsTest {

	private final char[] correctProtectionPhrase = new char[] { ' ' };
	private final char[] wrongProtectionPhrase = new char[] { 'A', 'A', 'A', 'A' };

	private DSSDocument sampleDocument;
	private DSSDocument protectedDocument;
	private DSSDocument twoPagesDocument;

	@BeforeEach
	void init() {
		sampleDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
		protectedDocument = new InMemoryDocument(getClass().getResourceAsStream("/protected/open_protected.pdf"),
				"sample.pdf", MimeTypeEnum.PDF);
		twoPagesDocument = new InMemoryDocument(getClass().getResourceAsStream("/empty-two-pages.pdf"));
	}

	@Test
	void generateScreenshotTest() {		 
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(sampleDocument, 1));
		assertNotNull(screenshot);
		
		Exception exception = assertThrows(IndexOutOfBoundsException.class, () -> PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(sampleDocument, 0)));
		assertEquals("Index out of bounds: 0", exception.getMessage());

		exception = assertThrows(IndexOutOfBoundsException.class,
				() -> PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(sampleDocument, 2)));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());

		exception = assertThrows(NullPointerException.class, () -> PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(null, 1)));
		assertEquals("pdfDocument shall be defined!", exception.getMessage());
	}

	@Test
	void generateScreenshotWithPassTest() {	
		DSSDocument screenshot = PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(protectedDocument, correctProtectionPhrase, 1));
		assertNotNull(screenshot);
		
		Exception exception = assertThrows(DSSException.class, () -> PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(protectedDocument, wrongProtectionPhrase, 1)));
		assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());
		
		exception = assertThrows(DSSException.class, () -> PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(protectedDocument, 1)));
		assertEquals("Encrypted document : Cannot decrypt PDF, the password is incorrect", exception.getMessage());
	}

	@Test
	void generateSubtractionImageTest() {
		DSSDocument subtractionImage = PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(sampleDocument, (char[]) null, 1), new PdfBoxPageDocumentRequest(protectedDocument, correctProtectionPhrase, 1));
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(twoPagesDocument, (char[]) null, 1), new PdfBoxPageDocumentRequest(twoPagesDocument, (char[]) null, 2));
		assertNotNull(subtractionImage);

		subtractionImage = PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(sampleDocument, 1), new PdfBoxPageDocumentRequest(twoPagesDocument, 1));
		assertNotNull(subtractionImage);

		Exception exception = assertThrows(IndexOutOfBoundsException.class, () -> PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(sampleDocument, 2), new PdfBoxPageDocumentRequest(twoPagesDocument, 2)));
		assertEquals("1-based index out of bounds: 2", exception.getMessage());
	}

	@Test
	void generateScreenshotWithTempFileTest() throws IOException  {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
		tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

		DSSDocument fileScreenshot = PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(sampleDocument, (char[]) null, 1), tempFileResourcesHandlerBuilder.createResourcesHandler());
		assertNotNull(fileScreenshot);
		assertTrue(fileScreenshot instanceof FileDocument);

		DSSDocument inMemoryScreenshot = PdfBoxUtils.generateScreenshot(new PdfBoxPageDocumentRequest(sampleDocument, 1));
		assertNotNull(inMemoryScreenshot);
		assertFalse(inMemoryScreenshot instanceof FileDocument);

		assertVisuallyEqual(fileScreenshot, inMemoryScreenshot);

		DSSDocument fileSubtractionImage = PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(sampleDocument, (char[]) null, 1), new PdfBoxPageDocumentRequest(twoPagesDocument, (char[]) null, 1),
				tempFileResourcesHandlerBuilder.createResourcesHandler());
		assertNotNull(fileSubtractionImage);
		assertTrue(fileSubtractionImage instanceof FileDocument);

		DSSDocument inMemorySubtractionImage = PdfBoxUtils.generateSubtractionImage(new PdfBoxPageDocumentRequest(sampleDocument, 1), new PdfBoxPageDocumentRequest(twoPagesDocument, 1));
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
	
	@Test
	void enforceMemoryUsageSettingMapping() {
		PdfMemoryUsageSetting pdfMemoryUsageSetting = PdfMemoryUsageSetting.memoryOnly(999);
		MemoryUsageSetting memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
		assertEquals(true, memoryUsageSetting.useMainMemory());
		assertEquals(false, memoryUsageSetting.useTempFile());
		assertEquals(999, memoryUsageSetting.getMaxMainMemoryBytes());
		
		pdfMemoryUsageSetting = PdfMemoryUsageSetting.fileOnly(888);
		memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
		assertEquals(false, memoryUsageSetting.useMainMemory());
		assertEquals(true, memoryUsageSetting.useTempFile());
		assertEquals(888, memoryUsageSetting.getMaxStorageBytes());
		
		pdfMemoryUsageSetting = PdfMemoryUsageSetting.mixed(555, 666);
		memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
		assertEquals(true, memoryUsageSetting.useMainMemory());
		assertEquals(true, memoryUsageSetting.useTempFile());
		assertEquals(555, memoryUsageSetting.getMaxMainMemoryBytes());
		assertEquals(666, memoryUsageSetting.getMaxStorageBytes());
	}

}
