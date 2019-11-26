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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class ValidationReportFacadeTest {

	@Test
	public void unmarshallAndMarshall() throws IOException, JAXBException, XMLStreamException, SAXException {
		ValidationReportFacade facade = ValidationReportFacade.newFacade();
		ValidationReportType validationReportType = facade.unmarshall(new File("src/test/resources/vr.xml"));

		assertNotNull(validationReportType);
		assertFalse(validationReportType.getSignatureValidationObjects().getValidationObject().isEmpty());
		assertFalse(validationReportType.getSignatureValidationReport().isEmpty());
		assertNull(validationReportType.getSignature());

		String marshall = facade.marshall(validationReportType, true);
		assertNotNull(marshall);
	}

}
