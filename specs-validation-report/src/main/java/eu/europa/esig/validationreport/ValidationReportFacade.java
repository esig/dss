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

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import java.io.IOException;

/**
 * Performs marshalling/unmarshalling operation for an ETSI Validation report
 */
public class ValidationReportFacade extends AbstractJaxbFacade<ValidationReportType> {

	/** Validation report utils */
	private static final ValidationReportUtils ETSI_VR_UTILS = ValidationReportUtils.getInstance();

	/**
	 * Default constructor
	 */
	protected ValidationReportFacade() {
		// empty
	}

	/**
	 * Creates a new facade
	 *
	 * @return {@link ValidationReportFacade}
	 */
	public static ValidationReportFacade newFacade() {
		return new ValidationReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return ETSI_VR_UTILS.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return ETSI_VR_UTILS.getSchema();
	}

	@Override
	protected JAXBElement<ValidationReportType> wrap(ValidationReportType jaxbObject) {
		return ValidationReportUtils.OBJECT_FACTORY.createValidationReport(jaxbObject);
	}

}
