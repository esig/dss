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

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * SAML Assertion Utils
 */
public class SAMLAssertionUtils extends XSDAbstractUtils {

	public static final String SAML_ASSERTION_SCHEMA_LOCATION = "/xsd/saml-schema-assertion-2.0.xsd";
	public static final String SAML_DCE_SCHEMA_LOCATION = "/xsd/saml-schema-dce-2.0.xsd";
	public static final String SAML_ECP_SCHEMA_LOCATION = "/xsd/saml-schema-ecp-2.0.xsd";
	public static final String SAML_METADATA_SCHEMA_LOCATION = "/xsd/saml-schema-metadata-2.0.xsd";
	public static final String SAML_PROTOCOL_SCHEMA_LOCATION = "/xsd/saml-schema-protocol-2.0.xsd";
	public static final String SAML_X500_SCHEMA_LOCATION = "/xsd/saml-schema-x500-2.0.xsd";
	public static final String SAML_XACML_SCHEMA_LOCATION = "/xsd/saml-schema-xacml-2.0.xsd";
	public static final String SAML_AUTHN_CONTEXT_TYPES_SCHEMA_LOCATION = "/xsd/saml-schema-authn-context-types-2.0.xsd";

	/** Singleton */
	private static SAMLAssertionUtils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	private SAMLAssertionUtils() {
		// empty
	}

	/**
	 * Returns instance of {@code SAMLAssertionUtils}
	 *
	 * @return {@link SAMLAssertionUtils}
	 */
	public static SAMLAssertionUtils getInstance() {
		if (singleton == null) {
			singleton = new SAMLAssertionUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmlenc.jaxb.ObjectFactory.class,
					eu.europa.esig.soap.jaxb.envelope.ObjectFactory.class, eu.europa.esig.saml.jaxb.assertion.ObjectFactory.class,
					eu.europa.esig.saml.jaxb.authn.context.ObjectFactory.class, eu.europa.esig.saml.jaxb.dce.ObjectFactory.class,
					eu.europa.esig.saml.jaxb.ecp.ObjectFactory.class, eu.europa.esig.saml.jaxb.protocol.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.addAll(XMLEncUtils.getInstance().getXSDSources());
		xsdSources.addAll(SoapEnvelopeUtils.getInstance().getXSDSources());
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_ASSERTION_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_PROTOCOL_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_AUTHN_CONTEXT_TYPES_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_DCE_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_ECP_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_METADATA_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_X500_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(SAMLAssertionUtils.class.getResourceAsStream(SAML_XACML_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
