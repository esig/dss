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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.xml.bind.JAXBException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

public class ValidationReportUtilsTest {
	
	private static ValidationReportUtils validationReportUtils;
	
	@BeforeAll
	public static void init() {
		validationReportUtils = ValidationReportUtils.getInstance();
	}

	@Test
	public void getJAXBContext() throws JAXBException {
		assertNotNull(validationReportUtils.getJAXBContext());
		// cached
		assertNotNull(validationReportUtils.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(validationReportUtils.getSchema());
		// cached
		assertNotNull(validationReportUtils.getSchema());
	}

}
