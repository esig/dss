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
package eu.europa.esig.dss.validation.policy;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.Test;

import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class ValidationPolicyTest {

	@Test
	public void test1() throws Exception {

		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		InputStream schemaStream = ValidationPolicyTest.class.getResourceAsStream("/xsd/policy.xsd");
		Schema schema = sf.newSchema(new StreamSource(schemaStream));

		JAXBContext jaxbContext = JAXBContext.newInstance(eu.europa.esig.jaxb.policy.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraints = (ConstraintsParameters) unmarshaller.unmarshal(new File("src/main/resources/policy/constraint.xml"));
		assertNotNull(constraints);

		EtsiValidationPolicy policy = new EtsiValidationPolicy(constraints);

		assertNotNull(policy);
	}
}
