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
package eu.europa.esig.dss.asic.xades;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.ContainerEntryDocument;
import eu.europa.esig.dss.asic.common.DSSZipEntry;
import eu.europa.esig.dss.asic.common.DSSZipEntryDocument;
import eu.europa.esig.dss.asic.common.SecureContainerHandler;
import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidator;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureContainerHandlerTest {

	private static DSSDocument smallerDocument;
	private static DSSDocument biggerDocument;

	@BeforeAll
	static void init() {
		smallerDocument = new FileDocument("src/test/resources/validation/dss-2245-2400.asice");
		biggerDocument = new FileDocument("src/test/resources/validation/dss-2245-2500.asice");
	}

	@AfterEach
	void reset() {
		ZipUtils.getInstance().setZipContainerHandlerBuilder(new SecureContainerHandlerBuilder());
	}

	@Test
	void testDefault() {
		ZipUtils.getInstance().setZipContainerHandlerBuilder(new SecureContainerHandlerBuilder());

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		validator = getValidator(biggerDocument);
		reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	void testSmallerRatio() {
		SecureContainerHandlerBuilder containerHandlerBuilder = new SecureContainerHandlerBuilder()
				.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandlerBuilder(containerHandlerBuilder);

		DocumentValidator validator = getValidator(smallerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());
	}

	@Test
	void testBiggerThreshold() {
		SecureContainerHandlerBuilder containerHandlerBuilder = new SecureContainerHandlerBuilder()
				.setMaxCompressionRatio(50);
		ZipUtils.getInstance().setZipContainerHandlerBuilder(containerHandlerBuilder);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(biggerDocument));
		assertEquals("Zip Bomb detected in the ZIP container. Validation is interrupted.", exception.getMessage());

		containerHandlerBuilder = new SecureContainerHandlerBuilder()
				.setMaxCompressionRatio(50)
				.setThreshold(100000000);
		ZipUtils.getInstance().setZipContainerHandlerBuilder(containerHandlerBuilder);

		DocumentValidator validator = getValidator(biggerDocument);
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
	}

	@Test
	void testDifferentDocumentsAmount() {
		SecureContainerHandlerBuilder containerHandlerBuilder = new SecureContainerHandlerBuilder()
				.setMaxAllowedFilesAmount(1);
		ZipUtils.getInstance().setZipContainerHandlerBuilder(containerHandlerBuilder);

		Exception exception = assertThrows(IllegalInputException.class, () -> getValidator(smallerDocument));
		assertEquals("Too many files detected. Cannot extract ASiC content from the file.", exception.getMessage());
	}

	private DocumentValidator getValidator(DSSDocument documentToValidate) {
		ASiCContainerWithXAdESValidator validator = new ASiCContainerWithXAdESValidator(documentToValidate);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		return validator;
	}

	@Test
	void extractContainerContentTest() {
		DSSDocument document = new FileDocument("src/test/resources/validation/multifiles-ok.asice");

		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		List<DSSDocument> entries = secureContainerHandler.extractContainerContent(document);
		assertEquals(6, Utils.collectionSize(entries));
		for (DSSDocument entry : entries) {
			assertTrue(entry instanceof DSSZipEntryDocument);
			DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) entry;
			DSSZipEntry zipEntry = dssZipEntry.getZipEntry();
			assertNotNull(zipEntry);
			String name = zipEntry.getName();
			assertNotNull(name);
			if ("mimetype".equals(name)) {
				assertEquals(ZipEntry.STORED, zipEntry.getCompressionMethod());
			} else {
				assertEquals(ZipEntry.DEFLATED, zipEntry.getCompressionMethod());
			}
			assertNotNull(zipEntry.getModificationTime());
		}
	}

	@Test
	void extractContainerContentInMemoryDocumentTest() {
		DSSDocument document = new InMemoryDocument(
				DSSUtils.toByteArray(new File("src/test/resources/validation/multifiles-ok.asice")));

		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		List<DSSDocument> entries = secureContainerHandler.extractContainerContent(document);
		assertEquals(6, Utils.collectionSize(entries));
		for (DSSDocument entry : entries) {
			assertTrue(entry instanceof DSSZipEntryDocument);
			DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) entry;
			DSSZipEntry zipEntry = dssZipEntry.getZipEntry();
			assertNotNull(zipEntry);
			String name = zipEntry.getName();
			assertNotNull(name);
			if ("mimetype".equals(name)) {
				assertEquals(ZipEntry.STORED, zipEntry.getCompressionMethod());
			} else {
				assertEquals(ZipEntry.DEFLATED, zipEntry.getCompressionMethod());
			}
			assertNotNull(zipEntry.getModificationTime());
		}
	}

	@Test
	void createZipArchiveTest() throws IOException {
		Date creationTime = new Date();
		Calendar calendar = Calendar.getInstance();
		calendar.setTime(creationTime);
		calendar.set(Calendar.MILLISECOND, 0);
		creationTime = calendar.getTime(); // reset millis

		MimeType mimeType = MimeTypeEnum.ASICE;

		DSSZipEntry mimetypeZipEntry = new DSSZipEntry("mimetype");
		mimetypeZipEntry.setCompressionMethod(ZipEntry.DEFLATED);

		ContainerEntryDocument mimetypeDocument = new ContainerEntryDocument(
				new InMemoryDocument(mimeType.getMimeTypeString().getBytes(), mimetypeZipEntry.getName()), mimetypeZipEntry);

		DSSZipEntry docOneZipEntry = new DSSZipEntry("docOne.txt");
		docOneZipEntry.setCompressionMethod(ZipEntry.STORED);
		docOneZipEntry.setCreationTime(DSSUtils.getUtcDate(2020, 0, 20));

		ContainerEntryDocument documentOne = new ContainerEntryDocument(
				new InMemoryDocument("Hello World!".getBytes(), docOneZipEntry.getName()), docOneZipEntry);

		DSSZipEntry docTwoZipEntry = new DSSZipEntry("docTwo.txt");
		docTwoZipEntry.setCompressionMethod(ZipEntry.DEFLATED);
		docTwoZipEntry.setCreationTime(creationTime);

		ContainerEntryDocument documentTwo = new ContainerEntryDocument(
				new InMemoryDocument("Bye World!".getBytes(), docTwoZipEntry.getName()), docTwoZipEntry);

		SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
		DSSDocument zipArchive = secureContainerHandler.createZipArchive(
				Arrays.asList(mimetypeDocument, documentOne, documentTwo), creationTime, ASiCUtils.getZipComment(mimeType));
		assertNotNull(zipArchive);

		String zipArchiveFilePath = "target/zipArchive.asice";
		zipArchive.save(zipArchiveFilePath);

		File zipArchiveFile = new File(zipArchiveFilePath);
		assertTrue(zipArchiveFile.exists());

		zipArchive = new FileDocument(zipArchiveFile);

		List<String> docNames = secureContainerHandler.extractEntryNames(zipArchive);
		assertEquals(3, docNames.size());
		assertEquals("mimetype", docNames.get(0));
		assertEquals("docOne.txt", docNames.get(1));
		assertEquals("docTwo.txt", docNames.get(2));

		List<DSSDocument> archiveEntries = secureContainerHandler.extractContainerContent(zipArchive);
		assertEquals(3, archiveEntries.size());

		boolean mimetypeFound = false;
		boolean docOneFound = false;
		boolean docTwoFound = false;
		for (DSSDocument entry : archiveEntries) {
			assertTrue(entry instanceof DSSZipEntryDocument);
			DSSZipEntryDocument dssZipEntry = (DSSZipEntryDocument) entry;
			DSSZipEntry zipEntry = dssZipEntry.getZipEntry();
			assertNotNull(zipEntry);

			String zipEntryName = zipEntry.getName();
			assertNotNull(zipEntryName);
			if ("mimetype".equals(zipEntryName)) {
				assertEquals(ZipEntry.STORED, zipEntry.getCompressionMethod());
				assertNull(zipEntry.getCreationTime());
				mimetypeFound = true;

			} else if ("docOne.txt".equals(zipEntryName)) {
				assertEquals(ZipEntry.STORED, zipEntry.getCompressionMethod());
				assertEquals(FileTime.fromMillis(DSSUtils.getUtcDate(2020, 0, 20).getTime()), zipEntry.getCreationTime());
				docOneFound = true;

			} else if ("docTwo.txt".equals(zipEntryName)) {
				assertEquals(ZipEntry.DEFLATED, zipEntry.getCompressionMethod());
				assertEquals(FileTime.fromMillis(creationTime.getTime()), zipEntry.getCreationTime());
				docTwoFound = true;
			}
		}
		assertTrue(mimetypeFound);
		assertTrue(docOneFound);
		assertTrue(docTwoFound);

		assertTrue(zipArchiveFile.delete());
		assertFalse(zipArchiveFile.exists());
	}

	@Test
	void extractCommentsTest() throws IOException {
		String comment = "Comment shall be preserved!";

		DSSZipEntry zipEntry = new DSSZipEntry("doc.txt");
		zipEntry.setComment(comment);

		ContainerEntryDocument documentOne = new ContainerEntryDocument(
				new InMemoryDocument("Hello World!".getBytes(), zipEntry.getName()), zipEntry);

		SecureContainerHandlerBuilder containerHandlerBuilder = new SecureContainerHandlerBuilder();
		ZipUtils zipUtils = ZipUtils.getInstance();
		zipUtils.setZipContainerHandlerBuilder(containerHandlerBuilder);

		DSSDocument zipArchive = zipUtils.createZipArchive(Collections.singletonList(documentOne), new Date(), null);
		assertNotNull(zipArchive);

		containerHandlerBuilder.setExtractComments(true);

		List<DSSDocument> containerContent = zipUtils.extractContainerContent(zipArchive);
		assertEquals(1, containerContent.size());

		DSSDocument containerEntry = containerContent.get(0);
		assertTrue(containerEntry instanceof DSSZipEntryDocument);

		DSSZipEntry extractedZipEntry = ((DSSZipEntryDocument) containerEntry).getZipEntry();
		assertNotNull(extractedZipEntry);
		assertNull(extractedZipEntry.getComment());

		String zipArchiveFilePath = "target/archive.zip";
		zipArchive.save(zipArchiveFilePath);

		File zipArchiveFile = new File(zipArchiveFilePath);
		assertTrue(zipArchiveFile.exists());

		zipArchive = new FileDocument(zipArchiveFile);

		containerContent = zipUtils.extractContainerContent(zipArchive);
		assertEquals(1, containerContent.size());

		containerEntry = containerContent.get(0);
		assertTrue(containerEntry instanceof DSSZipEntryDocument);
		zipEntry = ((DSSZipEntryDocument) containerEntry).getZipEntry();
		assertNotNull(zipEntry);
		assertEquals(comment, zipEntry.getComment());

		containerHandlerBuilder.setExtractComments(false);

		containerContent = zipUtils.extractContainerContent(zipArchive);
		assertEquals(1, containerContent.size());

		containerEntry = containerContent.get(0);
		assertTrue(containerEntry instanceof DSSZipEntryDocument);
		zipEntry = ((DSSZipEntryDocument) containerEntry).getZipEntry();
		assertNotNull(zipEntry);
		assertNull(zipEntry.getComment());

		assertTrue(zipArchiveFile.delete());
		assertFalse(zipArchiveFile.exists());
	}

}
