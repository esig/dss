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
package eu.europa.esig.dss.validation;

import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.ObjectFactory;

public class ValidationResourceManager {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationResourceManager.class);

	public static String defaultPolicyConstraintsLocation = "/policy/constraint.xml";
	public static String defaultPolicyXsdLocation = "/xsd/policy.xsd";

	private static JAXBContext jaxbContext;

	static {
		try {
			jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		} catch (JAXBException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads the policy constraint file. If the validationPolicy is not specified then the default policy
	 * file is
	 * loaded.
	 *
	 * @param policyDataStream
	 * @return
	 */
	public static ConstraintsParameters loadPolicyData(InputStream policyDataStream) {

		if (policyDataStream != null) {

			return load(policyDataStream);
		}
		if ((defaultPolicyConstraintsLocation != null) && !defaultPolicyConstraintsLocation.isEmpty()) {

			return load(defaultPolicyConstraintsLocation);
		}
		return null;
	}

	/**
	 * This method loads the data from the resource file into an {@link java.io.InputStream}.
	 *
	 * @param dataFileName
	 * @return
	 */
	public static InputStream getResourceInputStream(final String dataFileName) {
		try {
			InputStream inputStream = ValidationResourceManager.class.getResourceAsStream(dataFileName);
			return inputStream;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This is the utility method that loads the data from the file determined by the path parameter into a
	 * {@link org.w3c.dom.Document}.
	 *
	 * @param path
	 * @return
	 */
	public static ConstraintsParameters load(final String path) {
		if (Utils.isStringEmpty(path)) {
			return null;
		}
		final InputStream fileInputStream = getResourceInputStream(path);
		if (fileInputStream == null) {
			LOG.warn("Unknown resource (path: '{}')", path);
		}
		return load(fileInputStream);
	}

	/**
	 * This is the utility method that loads the data from the inputstream determined by the inputstream parameter into
	 * a
	 * {@link ConstraintsParameters}.
	 *
	 * @param inputStream
	 * @return
	 */
	public static ConstraintsParameters load(final InputStream inputStream) throws DSSException {
		try {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = sf.newSchema(new StreamSource(ValidationResourceManager.class.getResourceAsStream(defaultPolicyXsdLocation)));

			Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
			unmarshaller.setSchema(schema);

			return (ConstraintsParameters) unmarshaller.unmarshal(inputStream);
		} catch (Exception e) {
			throw new DSSException("Unable to load policy : " + e.getMessage(), e);
		}
	}

}
