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
import eu.europa.esig.dss.jades.HTTPHeader;
import eu.europa.esig.dss.jades.HTTPHeaderDigest;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class DSSDocumentTest {

	@Test
	public void testInMemoryDocument() throws IOException {

		// tag::inMemoryDocument[]

		// We can instantiate an InMemoryDocument from binaries
		DSSDocument binaryInMemoryDocument = new InMemoryDocument("Hello World".getBytes());

		// Or from InputStream
		DSSDocument isInMemoryDocument;
		try (InputStream is = new FileInputStream("src/main/resources/xml_example.xml")) {
			isInMemoryDocument = new InMemoryDocument("Hello World".getBytes());
		}

		// end::inMemoryDocument[]

		assertNotNull(binaryInMemoryDocument.getDigest(DigestAlgorithm.SHA256));
		assertNotNull(isInMemoryDocument.getDigest(DigestAlgorithm.SHA256));

		try (InputStream is = binaryInMemoryDocument.openStream()) {
			// expected behavior
		} catch (UnsupportedOperationException | IOException e) {
			fail("Cannot open an InMemoryDocument");
		}
		try (InputStream is = isInMemoryDocument.openStream()) {
			// expected behavior
		} catch (UnsupportedOperationException | IOException e) {
			fail("Cannot open an InMemoryDocument");
		}

	}

	@Test
	public void testFileDocument() throws IOException {

		// tag::fileDocument[]

		// Instantiate a FileDocument from a File
		DSSDocument fileDocument = new FileDocument(new File("src/main/resources/xml_example.xml"));

		// Or from file path directly
		DSSDocument filePathDocument = new FileDocument("src/main/resources/xml_example.xml");

		// end::fileDocument[]

		assertNotNull(fileDocument.getDigest(DigestAlgorithm.SHA256));
		assertNotNull(filePathDocument.getDigest(DigestAlgorithm.SHA256));

		try (InputStream is = fileDocument.openStream()) {
			// expected behavior
		} catch (UnsupportedOperationException | IOException e) {
			fail("Cannot open an InMemoryDocument");
		}
		try (InputStream is = filePathDocument.openStream()) {
			// expected behavior
		} catch (UnsupportedOperationException | IOException e) {
			fail("Cannot open an InMemoryDocument");
		}

	}

	@Test
	public void testDigestDocument() {

		// tag::digestDocument[]

		// Firstly, we load a basic DSSDocument (FileDocument or InMemoryDocument)
		DSSDocument fileDocument = new FileDocument("src/main/resources/xml_example.xml");

		// After that, we create a DigestDocument
		DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA1, fileDocument.getDigest(DigestAlgorithm.SHA1));
		digestDocument.setName(fileDocument.getName());

		// We can add additional digest values when required. Eg : for a SHA-256 based signature
		digestDocument.addDigest(DigestAlgorithm.SHA256, fileDocument.getDigest(DigestAlgorithm.SHA256));

		// Or incorporate digest value as a String directly
		digestDocument.addDigest(DigestAlgorithm.SHA512, "T1h8Ss0fiK0pfo1chVoLumIhyIgR9I0g8IvPhJPxwnR5dPFhLDEMU5kpt3AE4xnU2dagh6JaMz1INaCkO0LItg==");

		// end::digestDocument[]

		assertNotNull(digestDocument.getDigest(DigestAlgorithm.SHA256));

		try {
			digestDocument.getDigest(DigestAlgorithm.SHA384);
			fail("SHA-384 doesn't exist");
		} catch (IllegalArgumentException e) {
			// normal behavior
		}

		try (InputStream is = digestDocument.openStream()) {
			fail("Cannot open a DigestDocument");
		} catch (UnsupportedOperationException | IOException e) {
			// normal behavior
		}

	}

	@Test
	public void httpHeaderDocument() throws IOException {

		// tag::httpHeader[]

		// An HTTPHeader shall be defined with a header name and a value
		DSSDocument httpHeader = new HTTPHeader("content-type", "application/json");

		// An `digest` HTTP Header can be created from a HTTP body message, using a DSSDocument and a desired DigestAlgorithm
		DSSDocument httpBodyMessage = new InMemoryDocument("Hello World!".getBytes());
		DSSDocument httpHeaderDigest = new HTTPHeaderDigest(httpBodyMessage, DigestAlgorithm.SHA256);

		// end::httpHeader[]

		try {
			httpHeader.getDigest(DigestAlgorithm.SHA256);
			fail("getDigest(...) method is not supported for HTTPHeader document");
		} catch (UnsupportedOperationException e) {
			// normal behavior
		}

		try {
			httpHeaderDigest.getDigest(DigestAlgorithm.SHA256);
			fail("getDigest(...) method is not supported for HTTPHeader document");
		} catch (UnsupportedOperationException e) {
			// normal behavior
		}

		try (InputStream is = httpHeader.openStream()) {
			fail("Cannot open a HTTPHeader");
		} catch (UnsupportedOperationException | IOException e) {
			// normal behavior
		}
		try (InputStream is = httpHeaderDigest.openStream()) {
			fail("Cannot open a HTTPHeaderDigest");
		} catch (UnsupportedOperationException | IOException e) {
			// normal behavior
		}

	}

}
