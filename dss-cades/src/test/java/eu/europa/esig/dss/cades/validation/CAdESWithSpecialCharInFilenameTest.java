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
package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * Unit test added to fix : https://esig-dss.atlassian.net/browse/DSS-768
 */
public class CAdESWithSpecialCharInFilenameTest {

	private static final String FILE_TO_TEST = "src/test/resources/validation/dss-768/FD1&FD2&FEA.pdf.p7m";

	@Test
	public void testFile1() {
		DSSDocument dssDocument = new FileDocument(FILE_TO_TEST);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		assertNotNull(reports.getEtsiValidationReportJaxb());
	}

	@Test
	public void testFile1SkipETSIVR() {
		DSSDocument dssDocument = new FileDocument(FILE_TO_TEST);
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(dssDocument);
		validator.setEnableEtsiValidationReport(false);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		assertNull(reports.getEtsiValidationReportJaxb());
	}

}
