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
package eu.europa.esig.xades;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.xmldsig.jaxb.SignatureType;

public class XAdESUtilsTest {

	@Test
	@SuppressWarnings("unchecked")
	public void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/xades-lta.xml");

		JAXBContext jc = XAdESUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = XAdESUtils.getSchema();
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
	public void getSchema() throws SAXException {
		assertNotNull(XAdESUtils.getSchema());
		// cached
		assertNotNull(XAdESUtils.getSchema());
	}

	@Test
	public void getSchemaETSI_EN_319_132() throws SAXException {
		assertNotNull(XAdESUtils.getSchemaETSI_EN_319_132());
		// cached
		assertNotNull(XAdESUtils.getSchemaETSI_EN_319_132());
	}

	@Test
	public void getSchemaXAdES111() throws SAXException {
		assertNotNull(XAdESUtils.getSchemaXAdES111());
		// cached
		assertNotNull(XAdESUtils.getSchemaXAdES111());
	}

	@Test
	public void getSchemaXAdES122() throws SAXException {
		assertNotNull(XAdESUtils.getSchemaXAdES122());
		// cached
		assertNotNull(XAdESUtils.getSchemaXAdES122());
	}

}
