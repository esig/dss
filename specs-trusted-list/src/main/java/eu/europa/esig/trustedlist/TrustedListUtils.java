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
package eu.europa.esig.trustedlist;

import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import eu.europa.esig.xades.XAdESUtils;
import eu.europa.esig.xmldsig.AbstractUtils;

public final class TrustedListUtils extends AbstractUtils {

	public static final String TRUSTED_LIST_SCHEMA_LOCATION = "/xsd/ts_119612v020101_xsd.xsd";
	public static final String TRUSTED_LIST_SIE_SCHEMA_LOCATION = "/xsd/ts_119612v020101_sie_xsd.xsd";
	public static final String TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION = "/xsd/ts_119612v020101_additionaltypes_xsd.xsd";

	private TrustedListUtils() {
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();
	
	protected static JAXBContext jc;
	protected static Schema schema;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(eu.europa.esig.xmldsig.jaxb.ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class, ObjectFactory.class, eu.europa.esig.trustedlist.jaxb.tslx.ObjectFactory.class,
					eu.europa.esig.trustedlist.jaxb.ecc.ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws SAXException {
		if (schema == null) {
			SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
			List<Source> xsdSources = getXSDSources();
			schema = sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
		}
		return schema;
	}

	public static List<Source> getXSDSources() {
		List<Source> xsdSources = XAdESUtils.getXSDSources();
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SIE_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION)));
		return xsdSources;
	}
	
	public static Validator getSchemaValidator(Source... sources) throws SAXException {
		List<Source> currentXSDSources = getXSDSources();
		currentXSDSources.addAll(Arrays.asList(sources));
		return getValidator(currentXSDSources);
	}

}
