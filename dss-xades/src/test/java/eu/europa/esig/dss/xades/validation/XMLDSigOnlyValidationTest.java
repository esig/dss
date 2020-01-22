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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XMLDSigOnlyValidationTest {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/xmldsig-only.xml");
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		validator.setCertificateVerifier(commonCertificateVerifier);

		Reports reports = validator.validateDocument();
		assertNotNull(reports);

		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertEquals(1, diagnosticData.getSignatureIdList().size());

		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isSignatureIntact());
		assertTrue(signatureWrapper.isSignatureValid());
		assertFalse(signatureWrapper.isAttributePresent());
		assertFalse(signatureWrapper.isIssuerSerialMatch());
		assertFalse(signatureWrapper.isDigestValuePresent());
		assertFalse(signatureWrapper.isDigestValueMatch());
		assertEquals(SignatureLevel.XML_NOT_ETSI, signatureWrapper.getSignatureFormat());
		List<XmlDigestMatcher> digestMatchers = signatureWrapper.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			assertTrue(xmlDigestMatcher.isDataFound());
			assertTrue(xmlDigestMatcher.isDataIntact());
		}
	}

}
