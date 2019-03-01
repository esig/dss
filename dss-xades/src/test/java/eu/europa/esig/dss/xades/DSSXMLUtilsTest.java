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
package eu.europa.esig.dss.xades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.StringReader;

import javax.xml.transform.stream.StreamSource;

import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class DSSXMLUtilsTest {

	@Test
	public void isOid() {
		assertFalse(DSSXMLUtils.isOid(null));
		assertFalse(DSSXMLUtils.isOid(""));
		assertFalse(DSSXMLUtils.isOid("aurn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("urn:oid:1.2.3.4"));
		assertTrue(DSSXMLUtils.isOid("URN:OID:1.2.3.4"));
	}

	@Test
	public void validateAgainstXSD() throws SAXException {
		DSSXMLUtils.validateAgainstXSD(new FileDocument("src/test/resources/valid-xades-structure.xml"));
	}

	@Test(expected = SAXException.class)
	public void validateAgainstXSDInvalid() throws SAXException {
		DSSXMLUtils.validateAgainstXSD(new FileDocument("src/test/resources/invalid-xades-structure.xml"));
	}

	@Test
	public void validateAgainstXSDvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/valid-xades-structure.xml");
		Document dom = DomUtils.buildDOM(document);
		String xmlToString = DomUtils.xmlToString(dom.getDocumentElement());
		assertFalse(Utils.isStringNotEmpty(DSSXMLUtils.validateAgainstXSD(new StreamSource(new StringReader(xmlToString)))));
	}

	@Test
	public void validateAgainstXSDInvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/invalid-xades-structure.xml");
		Document dom = DomUtils.buildDOM(document);
		String xmlToString = DomUtils.xmlToString(dom.getDocumentElement());
		assertTrue(Utils.isStringNotEmpty(DSSXMLUtils.validateAgainstXSD(new StreamSource(new StringReader(xmlToString)))));
	}

	@Test
	public void getIdentifierPrefixed() {
		FileDocument document = new FileDocument("src/test/resources/ns-prefixes-sample.xml");
		Document dom = DomUtils.buildDOM(document);
		NodeList list = dom.getDocumentElement().getElementsByTagName("czip:initInstantPayment");
		assertEquals("signedData", DSSXMLUtils.getIDIdentifier(list.item(0)));
	}

	@Test
	public void setIdentifierPrefixed() {
		FileDocument document = new FileDocument("src/test/resources/ns-prefixes-sample.xml");
		Document dom = DomUtils.buildDOM(document);
		NodeList list = dom.getDocumentElement().getElementsByTagName("czip:initInstantPayment");
		DSSXMLUtils.setIDIdentifier((Element) list.item(0));

		assertNotNull(dom.getElementById("signedData"));
	}

	@Test
	public void isDuplicateIdsDetected() {
		assertTrue(DSSXMLUtils.isDuplicateIdsDetected(new FileDocument("src/test/resources/sample-duplicate-ids.xml")));
		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(new FileDocument("src/test/resources/sample.xml")));
	}

}
