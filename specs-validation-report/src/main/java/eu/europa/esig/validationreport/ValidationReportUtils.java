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
package eu.europa.esig.validationreport;

import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.trustedlist.TrustedListUtils;
import eu.europa.esig.validationreport.jaxb.ObjectFactory;
import eu.europa.esig.xmldsig.XSDAbstractUtils;

public final class ValidationReportUtils extends XSDAbstractUtils {

	public static final String VALIDATION_REPORT_SCHEMA_LOCATION = "/xsd/1910202xmlSchema.xsd";
	
	private static final TrustedListUtils trustedListUtils = TrustedListUtils.newInstance();
	
	private static ValidationReportUtils validationReportUtils;

	private ValidationReportUtils() {
	}
	
	public static ValidationReportUtils newInstance() {
		if (validationReportUtils == null) {
			validationReportUtils = new ValidationReportUtils();
		}
		return validationReportUtils;
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	protected static JAXBContext jc;
	protected static Schema schema;

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getSchema(getXSDSources());
		}
		return schema;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = trustedListUtils.getXSDSources();
		xsdSources.add(new StreamSource(ValidationReportUtils.class.getResourceAsStream(VALIDATION_REPORT_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
