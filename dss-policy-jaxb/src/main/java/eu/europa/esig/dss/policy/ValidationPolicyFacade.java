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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;

public class ValidationPolicyFacade extends AbstractJaxbFacade<ConstraintsParameters> {

	public static final String DEFAULT_VALIDATION_POLICY_LOCATION = "/policy/constraint.xml";
	public static final String TRUSTED_LIST_VALIDATION_POLICY_LOCATION = "/policy/tsl-constraint.xml";

	public static ValidationPolicyFacade newFacade() {
		return new ValidationPolicyFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return ValidationPolicyXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return ValidationPolicyXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<ConstraintsParameters> wrap(ConstraintsParameters jaxbObject) {
		return ValidationPolicyXmlDefiner.OBJECT_FACTORY.createConstraintsParameters(jaxbObject);
	}

	public ValidationPolicy getDefaultValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		return loadDefault();
	}

	public ValidationPolicy getTrustedListValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(TRUSTED_LIST_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(is);
		}
	}

	public ValidationPolicy getValidationPolicy(String path) throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(path)) {
			return getValidationPolicy(is);
		}
	}

	public ValidationPolicy getValidationPolicy(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
		Objects.requireNonNull(is, "The provided validation policy is null");
		return new EtsiValidationPolicy(unmarshall(is));
	}

	public ValidationPolicy getValidationPolicy(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		Objects.requireNonNull(file, "The provided validation policy is null");
		return new EtsiValidationPolicy(unmarshall(file));
	}

	private ValidationPolicy loadDefault() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream defaultIs = ValidationPolicyFacade.class.getResourceAsStream(DEFAULT_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(defaultIs);
		}
	}

}
