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

import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfMemoryUsageSetting;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxScreenshotBuilder;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxUtils;
import eu.europa.esig.dss.pdf.visible.ImageUtils;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import org.apache.pdfbox.io.MemoryUsageSetting;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PdfBoxUtilsTest {

	private final char[] correctProtectionPhrase = new char[] { ' ' };

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
	void generateSubtractionImageTest() {
		BufferedImage docOneScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null).generateBufferedImageScreenshot(1);
		BufferedImage docTwoScreenshot = PdfBoxScreenshotBuilder.fromDocument(protectedDocument, correctProtectionPhrase).generateBufferedImageScreenshot(1);
		DSSDocument subtractionImage = PdfBoxUtils.generateSubtractionImage(docOneScreenshot, docTwoScreenshot);
		assertNotNull(subtractionImage);

		docOneScreenshot = PdfBoxScreenshotBuilder.fromDocument(twoPagesDocument, null).generateBufferedImageScreenshot(1);
		docTwoScreenshot = PdfBoxScreenshotBuilder.fromDocument(twoPagesDocument, null).generateBufferedImageScreenshot(2);
		subtractionImage = PdfBoxUtils.generateSubtractionImage(docOneScreenshot, docTwoScreenshot);
		assertNotNull(subtractionImage);

		docOneScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument).generateBufferedImageScreenshot(1);
		docTwoScreenshot = PdfBoxScreenshotBuilder.fromDocument(twoPagesDocument).generateBufferedImageScreenshot(1);
		subtractionImage = PdfBoxUtils.generateSubtractionImage(docOneScreenshot, docTwoScreenshot);
		assertNotNull(subtractionImage);
	}

	@Test
	void generateScreenshotWithTempFileTest() throws IOException {
		TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
		tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

		BufferedImage docOneScreenshot = PdfBoxScreenshotBuilder.fromDocument(sampleDocument, null).generateBufferedImageScreenshot(1);
		BufferedImage docTwoScreenshot = PdfBoxScreenshotBuilder.fromDocument(twoPagesDocument, null).generateBufferedImageScreenshot(1);
		DSSDocument fileSubtractionImage = PdfBoxUtils.generateSubtractionImage(docOneScreenshot, docTwoScreenshot, tempFileResourcesHandlerBuilder.createResourcesHandler());
		assertNotNull(fileSubtractionImage);
		assertInstanceOf(FileDocument.class, fileSubtractionImage);

		DSSDocument inMemorySubtractionImage = PdfBoxUtils.generateSubtractionImage(docOneScreenshot, docTwoScreenshot);
		assertNotNull(inMemorySubtractionImage);
		assertInstanceOf(InMemoryDocument.class, inMemorySubtractionImage);

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
		PdfMemoryUsageSetting pdfMemoryUsageSetting = PdfMemoryUsageSetting.memoryBuffered(999);
		MemoryUsageSetting memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
        assertTrue(memoryUsageSetting.useMainMemory());
        assertFalse(memoryUsageSetting.useTempFile());
		assertEquals(999, memoryUsageSetting.getMaxMainMemoryBytes());
		
		pdfMemoryUsageSetting = PdfMemoryUsageSetting.fileOnly(888);
		memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
        assertFalse(memoryUsageSetting.useMainMemory());
        assertTrue(memoryUsageSetting.useTempFile());
		assertEquals(888, memoryUsageSetting.getMaxStorageBytes());
		
		pdfMemoryUsageSetting = PdfMemoryUsageSetting.mixed(555, 666);
		memoryUsageSetting = PdfBoxUtils.getMemoryUsageSetting(pdfMemoryUsageSetting);
        assertTrue(memoryUsageSetting.useMainMemory());
        assertTrue(memoryUsageSetting.useTempFile());
		assertEquals(555, memoryUsageSetting.getMaxMainMemoryBytes());
		assertEquals(666, memoryUsageSetting.getMaxStorageBytes());
	}

}
