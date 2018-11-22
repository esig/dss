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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

public class SignedDocumentValidatorForDocumentTest {

	@Test
	public void testXmlUTF8() {
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sample.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUTF8InMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sample.xml"));
		byte[] byteArray = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlISO() {
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(new FileDocument(new File("src/test/resources/sampleISO.xml")));
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}

	@Test
	public void testXmlUISOInMemory() throws IOException {
		FileInputStream fis = new FileInputStream(new File("src/test/resources/sampleISO.xml"));
		byte[] byteArray = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);
		DSSDocument document = new InMemoryDocument(byteArray);
		SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);
		assertTrue(documentValidator instanceof XMLDocumentValidator);
	}
}
