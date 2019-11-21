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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.test.signature.UnmarshallingTester;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class XAdES111ValidationTest extends PKIFactoryAccess {

	@Test
	public void test() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/AT/Signature-X-AT-1.xml");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		UnmarshallingTester.unmarshallXmlReports(reports);

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		assertEquals("IMPLICIT_POLICY", signatureById.getPolicyId());
		assertTrue(signatureById.isSignatureIntact());
		assertFalse(signatureById.isSignatureValid());
		assertTrue(signatureById.isSigningCertificateIdentified());
		assertFalse(signatureById.isSignatureProductionPlacePresent());
		assertEquals(SignatureLevel.XAdES_BASELINE_B, signatureById.getSignatureFormat());
	}

	@Test
	public void testEE() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/EE/Signature-X-EE-3.ddoc");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
		assertFalse(signatureById.isSigningCertificateIdentified());
		assertFalse(signatureById.isSignatureProductionPlacePresent());
		assertEquals(SignatureLevel.XML_NOT_ETSI, signatureById.getSignatureFormat());
	}

	@Test
	public void testPT() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/PT/Signature-X-PT-4.xml");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		assertFalse(signatureById.isSignatureIntact());
		assertFalse(signatureById.isSignatureValid());
		assertTrue(signatureById.isSigningCertificateIdentified());
		assertFalse(signatureById.isSignatureProductionPlacePresent());
	}
	
	@Test
	public void testAT_QES() {
		DSSDocument doc = new FileDocument("src/test/resources/validation/qes-xades111-filter2.xml");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		Reports reports = validator.validateDocument();

		DiagnosticData diagnosticData = reports.getDiagnosticData();
		SignatureWrapper signatureById = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		List<XmlDigestMatcher> digestMatchers = signatureById.getDigestMatchers();
		assertEquals(2, digestMatchers.size());
		assertTrue(signatureById.isSignatureIntact());
		assertTrue(signatureById.isSignatureValid());
		assertTrue(signatureById.isSigningCertificateIdentified());
		assertFalse(signatureById.isSignatureProductionPlacePresent());
	}
	
	@Override
	protected String getSigningAlias() {
		return null;
	}

}
