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
package eu.europa.esig.dss.xades.definition;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;

import eu.europa.esig.xades.definition.XAdESNamespaces;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.jaxb.common.definition.DSSAttribute;
import eu.europa.esig.dss.jaxb.common.definition.DSSElement;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.xmldsig.definition.XMLDSigAttribute;
import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import eu.europa.esig.xades.definition.xades111.XAdES111Attribute;
import eu.europa.esig.xades.definition.xades111.XAdES111Element;
import eu.europa.esig.xades.definition.xades122.XAdES122Attribute;
import eu.europa.esig.xades.definition.xades122.XAdES122Element;
import eu.europa.esig.xades.definition.xades132.XAdES132Attribute;
import eu.europa.esig.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.xades.definition.xades141.XAdES141Attribute;
import eu.europa.esig.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.xades.XAdES111Utils;
import eu.europa.esig.xades.XAdES122Utils;
import eu.europa.esig.xades.XAdES319132Utils;
import eu.europa.esig.xades.XAdESUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;

public class XAdESEnumsTest {
	
	public static final DSSNamespace XSD_NS = new DSSNamespace("http://www.w3.org/2001/XMLSchema", "xsd");

	@Test
	public void getAllEments() throws Exception {
		DomUtils.registerNamespace(XSD_NS);

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XmlDSigUtils.XMLDSIG_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, XMLDSigElement.values());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES111Utils.XADES_111_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, XAdES111Element.values());

			assertEquals(XAdESNamespaces.XADES_111, XAdES111Element.ANY.getNamespace());
			assertEquals(XAdESNamespaces.XADES_111.getUri(), XAdES111Element.ANY.getURI());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES122Utils.XADES_122_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, XAdES122Element.values());

			assertEquals(XAdESNamespaces.XADES_122, XAdES122Element.ANY.getNamespace());
			assertEquals(XAdESNamespaces.XADES_122.getUri(), XAdES122Element.ANY.getURI());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES319132Utils.XADES_SCHEMA_LOCATION_EN_319_132)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, XAdES132Element.values());

			assertEquals(XAdESNamespaces.XADES_132, XAdES132Element.ANY.getNamespace());
			assertEquals(XAdESNamespaces.XADES_132.getUri(), XAdES132Element.ANY.getURI());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES319132Utils.XADES_141_SCHEMA_LOCATION_EN_319_132)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, XAdES141Element.values());

			assertEquals(XAdESNamespaces.XADES_141, XAdES141Element.ARCHIVE_TIMESTAMP.getNamespace());
			assertEquals(XAdESNamespaces.XADES_141.getUri(), XAdES141Element.ARCHIVE_TIMESTAMP.getURI());
		}
	}

	@Test
	public void getAllAttributes() throws Exception {
		DomUtils.registerNamespace(XSD_NS);

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XmlDSigUtils.XMLDSIG_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkAttributesSynchronization(xsdDom, XMLDSigAttribute.values());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES111Utils.XADES_111_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkAttributesSynchronization(xsdDom, XAdES111Attribute.values());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES122Utils.XADES_122_SCHEMA_LOCATION)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkAttributesSynchronization(xsdDom, XAdES122Attribute.values());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES319132Utils.XADES_SCHEMA_LOCATION_EN_319_132)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkAttributesSynchronization(xsdDom, XAdES132Attribute.values());
		}

		try (InputStream is = XAdESUtils.class.getResourceAsStream(XAdES319132Utils.XADES_141_SCHEMA_LOCATION_EN_319_132)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkAttributesSynchronization(xsdDom, XAdES141Attribute.values());
		}

	}


	private void checkElementSynchronization(Document xsdDom, DSSElement[] elements) {
		NodeList nodeList = DomUtils.getNodeList(xsdDom, "//xsd:element");
		assertTrue(nodeList.getLength() > 0);
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node item = nodeList.item(i);
			if (item instanceof Element) {
				Element element = (Element) item;
				String tagName = element.getAttribute("name");
				if (tagName != null && !tagName.isEmpty()) {
					boolean found = false;
					for (DSSElement dssElement : elements) {
						if (tagName.equals(dssElement.getTagName())) {
							found = true;
							break;
						}
					}
					assertTrue(found, "Element [" + tagName + "] not found in enum");
				}
			}
		}

		for (DSSElement dssElement : elements) {
			NodeList nodeListByTagName = DomUtils.getNodeList(xsdDom, "//xsd:element[@name=\"" + dssElement.getTagName() + "\"]");
			assertTrue(nodeListByTagName.getLength() > 0, "Element [" + dssElement.getTagName() + "] not found in XSD");
		}
	}

	private void checkAttributesSynchronization(Document xsdDom, DSSAttribute[] attributes) {
		NodeList nodeList = DomUtils.getNodeList(xsdDom, "//xsd:attribute");
		assertTrue(nodeList.getLength() > 0);

		for (int i = 0; i < nodeList.getLength(); i++) {
			Node item = nodeList.item(i);
			if (item instanceof Element) {
				Element element = (Element) item;
				String attributeName = element.getAttribute("name");
				if (attributeName != null && !attributeName.isEmpty()) {
					boolean found = false;
					for (DSSAttribute dssAttribute : attributes) {
						if (attributeName.equals(dssAttribute.getAttributeName())) {
							found = true;
							break;
						}
					}
					assertTrue(found, "Attribute [" + attributeName + "] not found in the Enum");
				}
			}
		}

		for (DSSAttribute dssAttribute : attributes) {
			NodeList nodeListByTagName = DomUtils.getNodeList(xsdDom, "//xsd:attribute[@name=\"" + dssAttribute.getAttributeName() + "\"]");
			assertTrue(nodeListByTagName.getLength() > 0, "Attribute [" + dssAttribute.getAttributeName() + "] not found in XSD");
		}
	}


}
