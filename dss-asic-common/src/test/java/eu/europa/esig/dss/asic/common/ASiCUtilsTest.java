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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCUtilsTest {

	@Test
	void isZip() {
		assertFalse(ASiCUtils.isZip((DSSDocument) null));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 0 })));
		assertFalse(ASiCUtils.isZip(InMemoryDocument.createEmptyDocument()));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'P' })));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'p', 'k' })));
		InMemoryDocument emptyInMemoryDoc = new InMemoryDocument();
		assertThrows(NullPointerException.class, () -> ASiCUtils.isZip(emptyInMemoryDoc));

		assertTrue(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'K' })));

		assertFalse(ASiCUtils.isZip(new DigestDocument()));
		assertFalse(ASiCUtils.isZip(new DigestDocument(DigestAlgorithm.SHA1, "RslITpSJk9+wNlvSAQbRhBAWCdk=")));

		assertTrue(ASiCUtils.isZip(new FileDocument("src/test/resources/test.zip")));
		assertTrue(ASiCUtils.isZip(new FileDocument("src/test/resources/multifiles-ok.asice")));
	}

	@Test
	void isASiC() {
		assertFalse(ASiCUtils.isASiC(null));
		assertFalse(ASiCUtils.isASiC(new InMemoryDocument(new byte[] { 0 })));
		assertFalse(ASiCUtils.isASiC(InMemoryDocument.createEmptyDocument()));
		assertFalse(ASiCUtils.isASiC(new InMemoryDocument(new byte[] { 'P', 'P' })));
		assertFalse(ASiCUtils.isASiC(new InMemoryDocument(new byte[] { 'p', 'k' })));

		InMemoryDocument emptyInMemoryDoc = new InMemoryDocument();
		assertThrows(NullPointerException.class, () -> ASiCUtils.isASiC(emptyInMemoryDoc));

		assertFalse(ASiCUtils.isASiC(new InMemoryDocument(new byte[] { 'P', 'K' })));

		assertFalse(ASiCUtils.isASiC(new DigestDocument()));
		assertFalse(ASiCUtils.isASiC(new DigestDocument(DigestAlgorithm.SHA1, "RslITpSJk9+wNlvSAQbRhBAWCdk=")));

		assertFalse(ASiCUtils.isASiC(new FileDocument("src/test/resources/test.zip")));
		assertTrue(ASiCUtils.isASiC(new FileDocument("src/test/resources/multifiles-ok.asice")));
	}

	@Test
	void getASiCContainerType() {
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getASiCContainerType(MimeTypeEnum.ASICS));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeTypeEnum.ASICE));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeTypeEnum.ODT));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeTypeEnum.ODG));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeTypeEnum.ODP));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeTypeEnum.ODS));

		Exception exception = assertThrows(IllegalArgumentException.class, () -> ASiCUtils.getASiCContainerType(MimeTypeEnum.TEXT));
		assertEquals(String.format("Not allowed mimetype '%s'", MimeTypeEnum.TEXT.getMimeTypeString()), exception.getMessage());

		exception = assertThrows(NullPointerException.class, () -> ASiCUtils.getASiCContainerType(null));
		assertEquals("MimeType cannot be null!", exception.getMessage());
	}

	@Test
	void ensureMimeTypeAndZipCommentTest() {
		ASiCContent asicContent = new ASiCContent();
		ASiCParameters asicParameters = new ASiCParameters();
		asicParameters.setContainerType(ASiCContainerType.ASiC_S);
		asicParameters.setZipComment(true);

		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		assertNull(mimeTypeDocument);
		String zipComment = asicContent.getZipComment();
		assertNull(zipComment);

		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, asicParameters);

		mimeTypeDocument = asicContent.getMimeTypeDocument();
		assertNotNull(mimeTypeDocument);
		assertTrue(mimeTypeDocument instanceof DSSZipEntryDocument);

		DSSZipEntryDocument zipEntryDocument = (DSSZipEntryDocument) mimeTypeDocument;
		DSSZipEntry zipEntry = zipEntryDocument.getZipEntry();
		assertNotNull(zipEntry);
		assertEquals(ZipEntry.STORED, zipEntry.getCompressionMethod());

		zipComment = asicContent.getZipComment();
		assertNotNull(zipComment);
		assertEquals(ASiCUtils.getZipComment(MimeTypeEnum.ASICS), zipComment);
	}

	@Test
	void ensureMimeTypeAndZipCommentProvidedTest() {
		ASiCContent asicContent = new ASiCContent();
		asicContent.setMimeTypeDocument(new InMemoryDocument("mimetype".getBytes(), "mimetype"));
		asicContent.setZipComment("zip-comment");

		asicContent = ASiCUtils.ensureMimeTypeAndZipComment(asicContent, new ASiCParameters());

		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		assertNotNull(mimeTypeDocument);
		assertEquals("mimetype", mimeTypeDocument.getName());
		assertEquals("mimetype", new String(DSSUtils.toByteArray(mimeTypeDocument)));

		assertEquals("zip-comment", asicContent.getZipComment());
	}

	@Test
	void getContainerTypeTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> ASiCUtils.getContainerType((ASiCContent) null));
		assertEquals("ASiCContent shall be provided!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> ASiCUtils.getContainerType((DSSDocument) null));
		assertEquals("Archive container shall be provided!", exception.getMessage());

		ASiCContent asicContent = new ASiCContent();
		assertNull(ASiCUtils.getContainerType(asicContent));
		assertNull(ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setSignedDocuments(Collections.singletonList(
				new InMemoryDocument("Hello".getBytes(), "hello.txt")));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setSignedDocuments(Collections.singletonList(
				new InMemoryDocument("Hello".getBytes(), "world/hello.txt")));
		assertNull(ASiCUtils.getContainerType(asicContent));
		assertNull(ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setSignedDocuments(Arrays.asList(
				new InMemoryDocument("Hello".getBytes(), "hello.txt"), new InMemoryDocument("World".getBytes(), "world.txt")));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setSignedDocuments(Arrays.asList(
				new InMemoryDocument("Hello".getBytes(), "hello.txt"), new InMemoryDocument("World".getBytes(), "hello/world.txt")));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setAsicContainer(new InMemoryDocument("ASiC container".getBytes(), "container", MimeTypeEnum.ODT));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
		zipArchive.setMimeType(MimeTypeEnum.ODT);
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(zipArchive));

		asicContent.setAsicContainer(new InMemoryDocument("ASiC container".getBytes(), "container", MimeTypeEnum.ASICE));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
		zipArchive.setMimeType(MimeTypeEnum.ASICE);
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(zipArchive));

		asicContent.setAsicContainer(new InMemoryDocument("ASiC container".getBytes(), "container", MimeTypeEnum.ASICS));
		asicContent.setSignedDocuments(Collections.emptyList());
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
		zipArchive.setMimeType(MimeTypeEnum.ASICS);
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(zipArchive));

		asicContent.setSignedDocuments(Arrays.asList(
				new InMemoryDocument("Hello".getBytes(), "hello.txt"), new InMemoryDocument("World".getBytes(), "world.txt")));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
		zipArchive.setMimeType(MimeTypeEnum.ASICS);
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(zipArchive));

		asicContent.setAsicContainer(new InMemoryDocument("ASiC container".getBytes(), "container", MimeTypeEnum.ODT));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		zipArchive = ZipUtils.getInstance().createZipArchive(asicContent);
		zipArchive.setMimeType(MimeTypeEnum.ODT);
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(zipArchive));

		asicContent.setZipComment("mimetype=" + MimeTypeEnum.ODT.getMimeTypeString());
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setZipComment("mimetype=" + MimeTypeEnum.ASICS.getMimeTypeString());
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setZipComment("mimetype=" + MimeTypeEnum.ASICE.getMimeTypeString());
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setMimeTypeDocument(new InMemoryDocument(MimeTypeEnum.ODT.getMimeTypeString().getBytes(), "mimetype"));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setMimeTypeDocument(new InMemoryDocument(MimeTypeEnum.ASICS.getMimeTypeString().getBytes(), "mimetype"));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_S, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));

		asicContent.setMimeTypeDocument(new InMemoryDocument(MimeTypeEnum.ASICE.getMimeTypeString().getBytes(), "mimetype"));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(asicContent));
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getContainerType(ZipUtils.getInstance().createZipArchive(asicContent)));
	}

}
