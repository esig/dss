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
package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPResponseBinary;
import eu.europa.esig.dss.test.AbstractPkiFactoryTestValidation;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SADSSType;
import eu.europa.esig.validationreport.jaxb.SAFilterType;
import eu.europa.esig.validationreport.jaxb.SASubFilterType;
import eu.europa.esig.validationreport.jaxb.SAVRIType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DSS1523Test extends AbstractPkiFactoryTestValidation<PAdESSignatureParameters, PAdESTimestampParameters> {

	@Test
	public void validation() {
		// <</Type /DSS/Certs [20 0 R]/CRLs [21 0 R]/OCSPs [22 0 R]>>
		DSSDocument doc = new InMemoryDocument(DSS1523Test.class.getResourceAsStream("/validation/PAdES-LTA.pdf"), "PAdES-LTA.pdf", MimeType.PDF);
		
		verify(doc);
		
		PDFDocumentValidator validator = new PDFDocumentValidator(doc);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());
		
		List<PdfDssDict> dssDictionaries = validator.getDssDictionaries();
		assertEquals(1, dssDictionaries.size());
		PdfDssDict pdfDssDict = dssDictionaries.get(0);

		Map<Long, CertificateToken> certificateMap = pdfDssDict.getCERTs();
		assertEquals(1, certificateMap.size());
		assertNotNull(certificateMap.get(20L));

		Map<Long, OCSPResponseBinary> ocspMap = pdfDssDict.getOCSPs();
		assertEquals(1, ocspMap.size());
		assertNotNull(ocspMap.get(22L));

		Map<Long, CRLBinary> crlMap = pdfDssDict.getCRLs();
		assertEquals(1, crlMap.size());
		assertNotNull(crlMap.get(21L));
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertFalse(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureIdentifier(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature.getSignatureValue());
	}
	
	@Override
	protected void validateETSIDSSType(SADSSType dss) {
		assertNotNull(dss);
	}
	
	@Override
	protected void validateETSIVRIType(SAVRIType vri) {
		assertNotNull(vri);
	}
	
	@Override
	protected void validateETSIFilter(SAFilterType filterType) {
		assertNotNull(filterType);
	}
	
	@Override
	protected void validateETSISubFilter(SASubFilterType subFilterType) {
		assertNotNull(subFilterType);
	}
	
	@Override
	protected void checkReportsSignatureIdentifier(Reports reports) {
		// do nothing
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
