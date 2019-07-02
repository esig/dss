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

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class XAdESOCSPSourceTest extends PKIFactoryAccess {

	@Test
	public void test1() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/BE_ECON/Signature-X-BE_ECON-3.xml");

		DiagnosticData diagnosticData = getDiagnosticData(doc);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(5, signature.getFoundRevocations().size());
		
		assertEquals(4, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(1, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		
		assertEquals(1, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
	}

	@Test
	public void test2() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/HU_POL/Signature-X-HU_POL-3.xml");

		DiagnosticData diagnosticData = getDiagnosticData(doc);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(4, signature.getFoundRevocations().size());
		
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(4, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		
		assertEquals(2, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(2, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
	}

	@Test
	public void test3() {
		DSSDocument doc = new FileDocument("src/test/resources/plugtest/esig2014/ESIG-XAdES/CY/Signature-X-CY-1.xml");

		DiagnosticData diagnosticData = getDiagnosticData(doc);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertEquals(0, signature.getFoundRevocations().size());
		
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.CRL).size());
		assertEquals(0, signature.getRevocationIdsByType(RevocationType.OCSP).size());
		
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_REVOCATION_VALUES).size());
		assertEquals(0, signature.getRevocationIdsByTypeAndOrigin(RevocationType.OCSP, XmlRevocationOrigin.INTERNAL_TIMESTAMP_REVOCATION_VALUES).size());
	}
	
	private DiagnosticData getDiagnosticData(DSSDocument doc) {
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doc);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		Reports reports = validator.validateDocument();
		reports.print();
		return reports.getDiagnosticData();
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
