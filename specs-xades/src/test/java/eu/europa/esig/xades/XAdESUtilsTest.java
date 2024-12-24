/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.xades;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.xmldsig.jaxb.SignatureType;

class XAdESUtilsTest {
	
	private static XAdESUtils xadesUtils;
	private static XAdES111Utils xades111Utils;
	private static XAdES122Utils xades122Utils;
	private static XAdES319132Utils xades319132Utils;
	
	@BeforeAll
	static void init() {
		xadesUtils = XAdESUtils.getInstance();
		xades111Utils = XAdES111Utils.getInstance();
		xades122Utils = XAdES122Utils.getInstance();
		xades319132Utils = XAdES319132Utils.getInstance();
	}

	@Test
	@SuppressWarnings("unchecked")
	void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/xades-lta.xml");

		JAXBContext jc = xadesUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = xadesUtils.getSchema();
		assertNotNull(schema);

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<SignatureType> unmarshalled = (JAXBElement<SignatureType>) unmarshaller.unmarshal(xmldsigFile);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String xadesString = sw.toString();

		JAXBElement<SignatureType> unmarshalled2 = (JAXBElement<SignatureType>) unmarshaller.unmarshal(new StringReader(xadesString));
		assertNotNull(unmarshalled2);
	}

	@Test
	void getJAXBContext() throws JAXBException {
		assertNotNull(xadesUtils.getJAXBContext());
		// cached
		assertNotNull(xadesUtils.getJAXBContext());
	}

	@Test
	void getJAXBContextETSI_EN_319_132() throws JAXBException {
		assertNotNull(xades319132Utils.getJAXBContext());
		// cached
		assertNotNull(xades319132Utils.getJAXBContext());
	}

	@Test
	void getJAXBContextXAdES111() throws JAXBException {
		assertNotNull(xades111Utils.getJAXBContext());
		// cached
		assertNotNull(xades111Utils.getJAXBContext());
	}

	@Test
	void getJAXBContextXAdES122() throws JAXBException {
		assertNotNull(xades122Utils.getJAXBContext());
		// cached
		assertNotNull(xades122Utils.getJAXBContext());
	}

	@Test
	void getSchema() throws SAXException {
		assertNotNull(xadesUtils.getSchema());
		// cached
		assertNotNull(xadesUtils.getSchema());
	}

	@Test
	void getSchemaETSI_EN_319_132() throws SAXException {
		assertNotNull(xades319132Utils.getSchema());
		// cached
		assertNotNull(xades319132Utils.getSchema());
	}

	@Test
	void getSchemaXAdES111() throws SAXException {
		assertNotNull(xades111Utils.getSchema());
		// cached
		assertNotNull(xades111Utils.getSchema());
	}

	@Test
	void getSchemaXAdES122() throws SAXException {
		assertNotNull(xades122Utils.getSchema());
		// cached
		assertNotNull(xades122Utils.getSchema());
	}

}
