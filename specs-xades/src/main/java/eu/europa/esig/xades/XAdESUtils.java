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

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

import eu.europa.esig.xmldsig.AbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public final class XAdESUtils extends AbstractUtils {

	public static final String XADES_111_SCHEMA_LOCATION = "/xsd/XAdESv111.xsd";
	public static final String XADES_122_SCHEMA_LOCATION = "/xsd/XAdESv122.xsd";
	public static final String XADES_SCHEMA_LOCATION = "/xsd/XAdES.xsd";
	public static final String XADES_141_SCHEMA_LOCATION = "/xsd/XAdESv141.xsd";
	public static final String XADES_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v132-201601.xsd";
	public static final String XADES_141_SCHEMA_LOCATION_EN_319_132 = "/xsd/XAdES01903v141-201601.xsd";

	private XAdESUtils() {
	}

	private static Schema schemaXAdES111;
	private static Schema schemaXAdES122;
	private static Schema schemaETSIEN319132;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = getSchema(getXSDSources());
		}
		return schema;
	}

	public static Schema getSchemaXAdES111() throws SAXException {
		if (schemaXAdES111 == null) {
			schemaXAdES111 = getSchema(getXSDSourcesXAdES111());
		}
		return schemaXAdES111;
	}

	public static Schema getSchemaXAdES122() throws SAXException {
		if (schemaXAdES122 == null) {
			schemaXAdES122 = getSchema(getXSDSourcesXAdES122());
		}
		return schemaXAdES122;
	}

	public static Schema getSchemaETSI_EN_319_132() throws SAXException {
		if (schemaETSIEN319132 == null) {
			schemaETSIEN319132 = getSchema(getXSDSourcesETSI_EN_319_132());
		}
		return schemaETSIEN319132;
	}
	
	public static List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION)));
		return xsdSources;
	}

	public static List<Source> getXSDSourcesXAdES111() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_111_SCHEMA_LOCATION)));
		return xsdSources;
	}

	public static List<Source> getXSDSourcesXAdES122() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_122_SCHEMA_LOCATION)));
		return xsdSources;
	}

	public static List<Source> getXSDSourcesETSI_EN_319_132() {
		List<Source> xsdSources = XmlDSigUtils.getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_SCHEMA_LOCATION_EN_319_132)));
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION_EN_319_132)));
		return xsdSources;
	}
	
	public static Validator getSchemaValidator(Source... sources) throws SAXException {
		List<Source> currentXSDSources = getXSDSourcesETSI_EN_319_132();
		for (Source source : sources) {
			currentXSDSources.add(source);
		}
		return getValidator(currentXSDSources);
	}
	
}