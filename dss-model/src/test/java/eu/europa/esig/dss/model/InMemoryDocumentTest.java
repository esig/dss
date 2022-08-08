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
package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class InMemoryDocumentTest {

	@Test
	public void test() {
		InMemoryDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/AdobeCA.p7c"));
		assertNotNull(doc);
		assertNull(doc.getMimeType());
		assertNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testSetter() {
		InMemoryDocument doc = new InMemoryDocument();
		assertNotNull(doc);
		assertNull(doc.getMimeType());
		assertNull(doc.getName());
		assertNull(doc.getBytes());
		NullPointerException exception = assertThrows(NullPointerException.class, () -> doc.getDigest(DigestAlgorithm.SHA256));
		assertEquals("Byte array is not defined!", exception.getMessage());

		byte[] bytes = new byte[] { 1, 2, 3 };
		doc.setBytes(bytes);
		doc.setName("doc.txt");
		doc.setMimeType(MimeType.TEXT);
		assertNotNull(doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testWithName() {
		InMemoryDocument doc = new InMemoryDocument(getClass().getResourceAsStream("/AdobeCA.p7c"), "AdobeCA.p7c");
		assertNotNull(doc);
		assertEquals(MimeType.BINARY, doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testBytes() {
		byte[] bytes = new byte[] { 1, 2, 3 };

		InMemoryDocument doc = new InMemoryDocument(bytes, "doc.txt");
		assertNotNull(doc);
		assertEquals(MimeType.TEXT, doc.getMimeType());
		assertNotNull(doc.getName());
		assertNotNull(doc.getBytes());
		assertNotNull(doc.getDigest(DigestAlgorithm.SHA256));
	}

	@Test
	public void testFileNotFound() throws IOException {
		try (InputStream is = getClass().getResourceAsStream("/AdobeCAAA.p7c")) {
			NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument(is));
			assertEquals("The InputStream is null", exception.getMessage());
		}
	}

	@Test
	public void testNullInputStream() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument((InputStream) null));
		assertEquals("The InputStream is null", exception.getMessage());
	}

	@Test
	public void testNullBytes() {
		NullPointerException exception = assertThrows(NullPointerException.class, () -> new InMemoryDocument((byte[]) null));
		assertEquals("Bytes cannot be null", exception.getMessage());
	}

}
