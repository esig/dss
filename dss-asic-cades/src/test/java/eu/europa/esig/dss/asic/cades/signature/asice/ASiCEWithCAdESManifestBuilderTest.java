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
package eu.europa.esig.dss.asic.cades.signature.asice;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import eu.europa.esig.asic.manifest.ASiCManifestUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;

public class ASiCEWithCAdESManifestBuilderTest {

	private static Validator validator;

	@BeforeEach
	public void init() throws SAXException {
		Schema schema = ASiCManifestUtils.getSchemaASiCManifest121();
		validator = schema.newValidator();
	}

	@Test
	public void testManifestAgainstXSD() throws SAXException, IOException {
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test.bin"));
		documents.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test", MimeType.BINARY));
		ASiCEWithCAdESManifestBuilder builder = new ASiCEWithCAdESManifestBuilder(documents, DigestAlgorithm.SHA256, "signature.p7s");
		Document build = builder.build();

		validator.validate(new DOMSource(build));
	}

	@Test
	public void testArchiveManifestAgainstXSD() throws SAXException, IOException {
		List<DSSDocument> signatures = new ArrayList<DSSDocument>();
		signatures.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test.p7s", MimeType.PKCS7));
		List<DSSDocument> timestamps = new ArrayList<DSSDocument>();
		signatures.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test.tst", MimeType.TST));
		List<DSSDocument> documents = new ArrayList<DSSDocument>();
		documents.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test.bin"));
		documents.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test", MimeType.BINARY));
		List<DSSDocument> manifests = new ArrayList<DSSDocument>();
		documents.add(new InMemoryDocument(new byte[] { 1, 2, 3 }, "test.xml", MimeType.XML));
		ASiCEWithCAdESArchiveManifestBuilder builder = new ASiCEWithCAdESArchiveManifestBuilder(signatures, timestamps, 
				documents, manifests, null, DigestAlgorithm.SHA256, "timestamp.tst");
		Document build = builder.build();

		validator.validate(new DOMSource(build));
	}

}
