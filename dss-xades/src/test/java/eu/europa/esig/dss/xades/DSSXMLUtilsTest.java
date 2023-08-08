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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.xades.XAdES319132Utils;

public class DSSXMLUtilsTest {

	private static XAdES319132Utils xadesUtils;

	@BeforeAll
	public static void init() {
		xadesUtils = XAdES319132Utils.getInstance();
	}

	@Test
	public void validateAgainstXSDWithExternalSourceMissing() throws SAXException, IOException {
		DSSDocument document = new FileDocument("src/test/resources/ASiCManifest.xml");
		List<String> errorMessages = xadesUtils.validateAgainstXSD(getSource(document), new StreamSource[0]);
		assertFalse(Utils.isCollectionEmpty(errorMessages));
	}

	@Test
	public void validateAgainstXSDWithExternalSourceOK() throws SAXException, IOException {
		StreamSource streamSource = new StreamSource(DSSXMLUtilsTest.class.getResourceAsStream("/ExternalXSDForAsic.xsd"));
		DSSDocument document = new FileDocument("src/test/resources/ASiCManifest.xml");
		List<String> errorMessages = xadesUtils.validateAgainstXSD(getSource(document), streamSource);
		assertTrue(Utils.isCollectionEmpty(errorMessages));
	}

	@Test
	public void validateAgainstXSDvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/valid-xades-structure.xml");
		assertFalse(Utils.isCollectionNotEmpty(
				DSSXMLUtils.validateAgainstXSD(XAdES319132Utils.getInstance(), getSource(document))));
	}

	@Test
	public void validateAgainstXSDInvalidMessage() {
		FileDocument document = new FileDocument("src/test/resources/invalid-xades-structure.xml");
		assertTrue(Utils.isCollectionNotEmpty(
				DSSXMLUtils.validateAgainstXSD(XAdES319132Utils.getInstance(), getSource(document))));
	}

	public Source getSource(DSSDocument doc) {
		return new DOMSource(DomUtils.buildDOM(doc));
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
