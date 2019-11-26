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

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class ValidationReportFacade extends AbstractJaxbFacade<ValidationReportType> {
	
	private static final ValidationReportUtils validationReportUtils = ValidationReportUtils.newInstance();

	public static ValidationReportFacade newFacade() {
		return new ValidationReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return validationReportUtils.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return validationReportUtils.getSchema();
	}

	@Override
	protected JAXBElement<ValidationReportType> wrap(ValidationReportType jaxbObject) {
		return ValidationReportUtils.OBJECT_FACTORY.createValidationReport(jaxbObject);
	}

}
