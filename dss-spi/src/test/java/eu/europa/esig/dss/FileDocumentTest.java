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
package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class FileDocumentTest {

	@Test(expected = NullPointerException.class)
	public void testNull() {
		new FileDocument((String) null);
	}

	@Test(expected = NullPointerException.class)
	public void testNull2() {
		new FileDocument((File) null);
	}

	@Test
	public void testFile() throws IOException {
		FileDocument doc = new FileDocument("src/test/resources/AdobeCA.p7c");
		assertNotNull(doc);
		assertTrue(doc.exists());
		assertEquals("AdobeCA.p7c", doc.getName());
		assertEquals(MimeType.BINARY, doc.getMimeType());
		assertEquals("xF8SpcLlrd4Bhl1moh4Ciz+Rq/PImaChEl/tyGTZyPM=", doc.getDigest(DigestAlgorithm.SHA256));
		assertEquals("xF8SpcLlrd4Bhl1moh4Ciz+Rq/PImaChEl/tyGTZyPM=", doc.getDigest(DigestAlgorithm.SHA256)); // uses map
		String path = "target/testFileDocument";
		doc.save(path);

		File file = new File(path);
		assertTrue(file.exists());
	}
}
