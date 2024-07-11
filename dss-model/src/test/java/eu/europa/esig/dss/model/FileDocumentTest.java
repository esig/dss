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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileDocumentTest {

	@TempDir
	static Path temporaryFolder;

	@Test
	void testNull() {
		assertThrows(NullPointerException.class, () -> new FileDocument((String) null));
	}

	@Test
	void testNull2() {
		Exception exception = assertThrows(NullPointerException.class, () -> new FileDocument((File) null));
		assertEquals("File cannot be null", exception.getMessage());
	}

	@Test
	void testFile() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/AdobeCA.p7c");
		assertNotNull(doc);
		assertTrue(doc.exists());
		assertEquals("AdobeCA.p7c", doc.getName());
		assertEquals(MimeTypeEnum.BINARY, doc.getMimeType());
		assertEquals("xF8SpcLlrd4Bhl1moh4Ciz+Rq/PImaChEl/tyGTZyPM=", Base64.getEncoder().encodeToString(doc.getDigestValue(DigestAlgorithm.SHA256)));
		assertEquals("xF8SpcLlrd4Bhl1moh4Ciz+Rq/PImaChEl/tyGTZyPM=", Base64.getEncoder().encodeToString(doc.getDigestValue(DigestAlgorithm.SHA256))); // uses map

		Path containerTemporaryPath = temporaryFolder.resolve("testFileDocument");
		doc.save(containerTemporaryPath.toString());

		File file = containerTemporaryPath.toFile();
		assertTrue(file.exists());
		assertTrue(file.delete(), "Cannot delete the temporary file");
		assertFalse(file.exists());
	}

}
