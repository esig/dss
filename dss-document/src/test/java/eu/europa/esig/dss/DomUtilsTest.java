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

import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DomUtilsTest {

	private static final String XML_HEADER = "<?xml version='1.0' encoding='UTF-8'?>";
	private static final String XML_TEXT = "<hello><world></world></hello>";
	private static final String INCORRECT_XML_TEXT = "<hello><world></warld></hello>";
	private static final String XML_WITH_NAMESPACE = "<m:manifest xmlns:m=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\"><m:file-entry m:media-type=\"text/plain\" m:full-path=\"hello.txt\" /></m:manifest>";

	@Test
	public void registerNamespaceTest() {
		Document document = DomUtils.buildDOM(XML_WITH_NAMESPACE);

		final String xPathExpression = "./m:file-entry";
		Exception exception = assertThrows(DSSException.class, () -> DomUtils.getElement(document.getDocumentElement(), xPathExpression));
		assertTrue(exception.getMessage().contains("Unable to create an XPath expression"));

		DomUtils.registerNamespace(new DSSNamespace("urn:oasis:names:tc:opendocument:xmlns:manifest:1.0", "m"));

		Element fileEntry = DomUtils.getElement(document.getDocumentElement(), "./m:file-entry");
		assertNotNull(fileEntry);

		exception = assertThrows(UnsupportedOperationException.class,
				() -> DomUtils.registerNamespace(new DSSNamespace("http://some-uri.net", null)));
		assertEquals("The empty namespace cannot be registered!", exception.getMessage());

		exception = assertThrows(UnsupportedOperationException.class,
				() -> DomUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "")));
		assertEquals("The empty namespace cannot be registered!", exception.getMessage());

		exception = assertThrows(UnsupportedOperationException.class,
				() -> DomUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "xmlns")));
		assertEquals("The default namespace 'xmlns' cannot be registered!", exception.getMessage());

		assertTrue(DomUtils.registerNamespace(new DSSNamespace("http://some-uri.net", "otherPrefix")));
	}

	@Test
	public void testNoHeader() {
		InputStream is = new ByteArrayInputStream(XML_TEXT.getBytes());
		assertNotNull(DomUtils.buildDOM(is));
		assertNotNull(DomUtils.buildDOM(XML_TEXT));
		assertNotNull(DomUtils.buildDOM(new InMemoryDocument(XML_TEXT.getBytes(), "my xml")));
	}

	@Test
	public void testNoHeaderError() {
		Exception exception = assertThrows(DSSException.class, () -> DomUtils.buildDOM(INCORRECT_XML_TEXT));
		assertTrue(exception.getMessage().contains("Unable to parse content (XML expected)"));
	}

	@Test
	public void testHeader() {
		InputStream is = new ByteArrayInputStream((XML_HEADER + XML_TEXT).getBytes());
		assertNotNull(DomUtils.buildDOM(is));
		assertNotNull(DomUtils.buildDOM(XML_HEADER + XML_TEXT));
		assertNotNull(DomUtils.buildDOM(new InMemoryDocument((XML_HEADER + XML_TEXT).getBytes(), "my xml")));
	}

	@Test
	public void testHeaderError() {
		Exception exception = assertThrows(DSSException.class, () -> DomUtils.buildDOM(XML_HEADER + INCORRECT_XML_TEXT));
		assertTrue(exception.getMessage().contains("Unable to parse content (XML expected)"));
	}

	@Test
	public void testExpansionXml() throws IOException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/xml_expansion.xml")) {
			Exception exception = assertThrows(DSSException.class, () -> DomUtils.buildDOM(fis));
			assertTrue(exception.getMessage().contains("Unable to parse content (XML expected)"));
		}
	}

	@Test
	public void testEntityXml() throws IOException {
		// Should ignore the URL embedded in the DTD
		try (FileInputStream fis = new FileInputStream("src/test/resources/xml_entity.xml")) {
			Exception exception = assertThrows(DSSException.class, () -> DomUtils.buildDOM(fis));
			assertTrue(exception.getMessage().contains("Unable to parse content (XML expected)"));
		}
	}

	@Test
	public void getSecureTransformer() {
		assertNotNull(DomUtils.getSecureTransformer());
	}

	@Test
	public void getDate() {
		assertNull(DomUtils.getDate("2020-02-16:T18:32:24Z"));
		assertNotNull(DomUtils.getDate("2020-02-16T18:32:24Z"));
	}
	
}
