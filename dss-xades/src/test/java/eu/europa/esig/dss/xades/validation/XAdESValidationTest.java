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
package eu.europa.esig.dss.xades.validation;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class XAdESValidationTest {

	private static final String POLICY_ID = "1.3.6.1.4.1.10015.1000.3.2.1";
	private static final String POLICY_URL = "http://spuri.test";

	@Test
	public void validatedXadesSignatureShouldContainPolicyParameters() throws Exception {
		SignatureWrapper xadesSignature = openXadesSignature("src/test/resources/validation/valid-xades.xml");
		assertEquals(POLICY_ID, xadesSignature.getPolicyId());
		assertEquals(POLICY_URL, xadesSignature.getPolicyUrl());
	}

	private SignatureWrapper openXadesSignature(String documentPath) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new FileDocument(new File(documentPath)));
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		return diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
	}
}
