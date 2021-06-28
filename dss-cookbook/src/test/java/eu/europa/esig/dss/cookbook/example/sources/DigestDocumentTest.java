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
package eu.europa.esig.dss.cookbook.example.sources;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class DigestDocumentTest {

	@Test
	public void testDigestDocument() {

		// tag::demo[]

		// Firstly, we load a basic DSSDocument (FileDocument or InMemoryDocument)
		DSSDocument fileDocument = new FileDocument("src/main/resources/xml_example.xml");

		// After that, we create a DigestDocument
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA1, fileDocument.getDigest(DigestAlgorithm.SHA1));
		digestDocument.setName(fileDocument.getName());
		
		// We can add an additional needed digest value(s). Eg : for a SHA-256 based signature
		digestDocument.addDigest(DigestAlgorithm.SHA256, fileDocument.getDigest(DigestAlgorithm.SHA256));

		// end::demo[]

		assertNotNull(digestDocument.getDigest(DigestAlgorithm.SHA256));

		try {
			digestDocument.getDigest(DigestAlgorithm.SHA512);
			fail("SHA-512 doesn't exist");
		} catch (IllegalArgumentException e) {
			// normal behavior
		}

		try (InputStream is = digestDocument.openStream()) {
			fail("Cannot open a DigestDocument");
		} catch (UnsupportedOperationException | IOException e) {
			// normal behavior
		}

	}

}
