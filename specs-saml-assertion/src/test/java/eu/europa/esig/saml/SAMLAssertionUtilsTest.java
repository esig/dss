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
package eu.europa.esig.saml;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import eu.europa.esig.saml.jaxb.metadata.EntityDescriptorType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.saml.jaxb.assertion.AssertionType;

public class SAMLAssertionUtilsTest {

	private static SAMLAssertionUtils samlAssertionUtils;

	@BeforeAll
	public static void init() {
		samlAssertionUtils = SAMLAssertionUtils.getInstance();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void test() throws JAXBException, SAXException {
		JAXBContext jc = samlAssertionUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = samlAssertionUtils.getSchema();
		assertNotNull(schema);

		File file = new File("src/test/resources/sample-saml-assertion.xml");

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<AssertionType> unmarshalled = (JAXBElement<AssertionType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);
	}

	@Test
	void metadata () throws JAXBException, SAXException {

		JAXBContext jc = samlAssertionUtils.getJAXBContext();

		File file = new File("src/test/resources/Metadata.xml");
		Unmarshaller unmarshaller = jc.createUnmarshaller();

		JAXBElement<EntityDescriptorType> unmarshalled = (JAXBElement<EntityDescriptorType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);

		file = new File("src/test/resources/ServiceMetadata.xml");
		unmarshalled = (JAXBElement<EntityDescriptorType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);
	}

}
