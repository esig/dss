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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.asic.xades.validation.ASiCEWithXAdESManifestParser;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ManifestEntry;
import eu.europa.esig.dss.model.ManifestFile;

class ASiCEWithXAdESManifestParserTest {

	@Test
	void test() {
		DSSDocument signatureDoc = new InMemoryDocument("Hello".getBytes(), "test");
		DSSDocument manifestDoc = new FileDocument(new File("src/test/resources/manifest-sample.xml"));
		ASiCEWithXAdESManifestParser parser = new ASiCEWithXAdESManifestParser(signatureDoc, manifestDoc);

		ManifestFile description = parser.getManifest();
		assertNotNull(description);
		assertEquals("manifest-sample.xml", description.getFilename());
		assertEquals("test", description.getSignatureFilename());
		List<ManifestEntry> entries = description.getEntries();
		assertEquals(2, entries.size());
		boolean containsTestTxt = false;
		boolean containsTestDataFileBin = false;
		for (ManifestEntry entry : entries) {
			if ("test.txt".equals(entry.getFileName())) {
				containsTestTxt = true;
			}
			if ("test-data-file.bin".equals(entry.getFileName())) {
				containsTestDataFileBin = true;
			}
			assertNotNull(entry.getFileName());
			assertNotNull(entry.getMimeType());
		}
		assertTrue(containsTestTxt);
		assertTrue(containsTestDataFileBin);
	}

}
