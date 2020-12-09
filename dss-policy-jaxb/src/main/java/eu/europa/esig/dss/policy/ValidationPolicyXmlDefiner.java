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
package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.jaxb.XmlDefinerUtils;
import eu.europa.esig.dss.policy.jaxb.ObjectFactory;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.IOException;
import java.io.InputStream;

/**
 * Contains cached the {@code JAXBContext} and {@code Schema} for an XML validation policy
 */
public final class ValidationPolicyXmlDefiner {

	/** The object factory to use */
	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	/** The Validation Policy XSD schema location */
	private static final String VALIDATION_POLICY_SCHEMA_LOCATION = "/xsd/policy.xsd";

	private ValidationPolicyXmlDefiner() {
	}

	/**
	 * The cached JAXBContext
	 *
	 * NOTE: Thread-safe
	 */
	private static JAXBContext jc;

	/**
	 * The cached Schema
	 *
	 * NOTE: Thread-safe
	 */
	private static Schema schema;

	/**
	 * Gets the {@code JAXBContext}
	 *
	 * @return {@link JAXBContext}
	 * @throws JAXBException if an exception occurs
	 */
	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	/**
	 * Gets the {@code Schema}
	 *
	 * @return {@link Schema}
	 * @throws IOException if an IOException occurs
	 * @throws SAXException if a SAXException occurs
	 */
	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream inputStream = ValidationPolicyXmlDefiner.class.getResourceAsStream(VALIDATION_POLICY_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}


}
