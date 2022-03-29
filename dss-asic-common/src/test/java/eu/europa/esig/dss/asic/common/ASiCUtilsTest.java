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
package eu.europa.esig.dss.asic.common;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;

import java.util.zip.ZipEntry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCUtilsTest {

	@Test
	public void isZip() {
		assertFalse(ASiCUtils.isZip((DSSDocument) null));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 0 })));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'P' })));
		assertFalse(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'p', 'k' })));
		InMemoryDocument emptyInMemoryDoc = new InMemoryDocument();
		assertThrows(NullPointerException.class, () -> ASiCUtils.isZip(emptyInMemoryDoc));

		assertTrue(ASiCUtils.isZip(new InMemoryDocument(new byte[] { 'P', 'K' })));
	}

	@Test
	public void getASiCContainerType() {
		MimeType mt = new MimeType();
		mt.setMimeTypeString("application/vnd.etsi.asic-e+zip");
		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(mt));

		assertEquals(ASiCContainerType.ASiC_E, ASiCUtils.getASiCContainerType(MimeType.ASICE));
	}

	@Test
	public void getWrongASiCContainerType() {
		MimeType mt = new MimeType();
		mt.setMimeTypeString("application/wrong");
		Exception exception = assertThrows(IllegalArgumentException.class, () -> ASiCUtils.getASiCContainerType(mt));
		assertEquals("Not allowed mimetype 'application/wrong'", exception.getMessage());
	}

	@Test
	public void ensureMimeTypeAndZipCommentTest() {
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
		assertEquals(ASiCUtils.getZipComment(MimeType.ASICS), zipComment);
	}

	@Test
	public void ensureMimeTypeAndZipCommentProvidedTest() {
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

}
