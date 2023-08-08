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
package eu.europa.esig.dss.asic.common.definition;

import eu.europa.esig.asic.manifest.ASiCManifestUtils;
import eu.europa.esig.asic.manifest.definition.ASiCManifestAttribute;
import eu.europa.esig.asic.manifest.definition.ASiCManifestElement;
import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.jaxb.common.definition.DSSAttribute;
import eu.europa.esig.dss.jaxb.common.definition.DSSElement;
import eu.europa.esig.dss.jaxb.common.definition.DSSNamespace;
import eu.europa.esig.xades.XAdESUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEnumsTest {

	public static final DSSNamespace XSD_NS = new DSSNamespace("http://www.w3.org/2001/XMLSchema", "xsd");

	@Test
	public void getAllElements() throws Exception {
		DomUtils.registerNamespace(XSD_NS);

		try (InputStream is = XAdESUtils.class.getResourceAsStream(ASiCManifestUtils.ASIC_MANIFEST)) {
			Document xsdDom = DomUtils.buildDOM(is);
			checkElementSynchronization(xsdDom, ASiCManifestElement.values());
		}

	}

	@Test
	public void getAllAttributes() throws Exception {
		DomUtils.registerNamespace(XSD_NS);

		try (InputStream is = XAdESUtils.class.getResourceAsStream(ASiCManifestUtils.ASIC_MANIFEST)) {
			Document xsdDom = DomUtils.buildDOM(is);
			 checkAttributesSynchronization(xsdDom, ASiCManifestAttribute.values());
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
