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

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Used to read an XML validation policy
 */
public class ValidationPolicyFacade extends AbstractJaxbFacade<ConstraintsParameters> {

	/** The default validation policy path */
	private static final String DEFAULT_VALIDATION_POLICY_LOCATION = "/policy/constraint.xml";

	/** The path for default certificate validation policy */
	private static final String CERTIFICATE_VALIDATION_POLICY_LOCATION = "/policy/certificate-constraint.xml";

	/** The path for a LOTL/TL validation policy */
	private static final String TRUSTED_LIST_VALIDATION_POLICY_LOCATION = "/policy/tsl-constraint.xml";

	/**
	 * Default constructor
	 */
	protected ValidationPolicyFacade() {
		// empty
	}

	/**
	 * Initializes a new {@code ValidationPolicyFacade}
	 *
	 * @return {@link ValidationPolicyFacade}
	 */
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

	/**
	 * Gets the default validation policy
	 *
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
	public ValidationPolicy getDefaultValidationPolicy() throws JAXBException, XMLStreamException, IOException,
			SAXException {
		return loadDefault();
	}

	/**
	 * Gets the default policy for certificate validation
	 *
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
	public ValidationPolicy getCertificateValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(CERTIFICATE_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(is);
		}
	}

	/**
	 * Gets the validation policy for LOTL/TL
	 *
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
	public ValidationPolicy getTrustedListValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(TRUSTED_LIST_VALIDATION_POLICY_LOCATION)) {
			return getValidationPolicy(is);
		}
	}

	/**
	 * Gets the validation policy from the {@code path}
	 *
	 * @param path {@link String}
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
	public ValidationPolicy getValidationPolicy(String path) throws JAXBException, XMLStreamException, IOException, SAXException {
		try (InputStream is = ValidationPolicyFacade.class.getResourceAsStream(path)) {
			return getValidationPolicy(is);
		}
	}

	/**
	 * Gets the validation policy from the {@code is}
	 *
	 * @param is {@link InputStream}
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
	public ValidationPolicy getValidationPolicy(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
		Objects.requireNonNull(is, "The provided validation policy is null");
		return new EtsiValidationPolicy(unmarshall(is));
	}

	/**
	 * Gets the validation policy from the {@code file}
	 *
	 * @param file {@link File}
	 * @return {@link ValidationPolicy}
	 * @throws JAXBException if {@link JAXBException} occurs
	 * @throws XMLStreamException if {@link XMLStreamException} occurs
	 * @throws IOException if {@link IOException} occurs
	 * @throws SAXException if {@link SAXException} occurs
	 */
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
