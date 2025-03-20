/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pades.validation.suite.dss1696;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.SignatureCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArchiveTimestampCoverageTest extends AbstractPAdESTestValidation {

	/**
	 * Duplicate streams
	 * 
	 * CRLs: 27 = 21
	 * 
	 * 28 = 22
	 * 
	 * Certificates: 20=26
	 */

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1696/Test.signed_Certipost-2048-SHA512.extended.pdf"));
	}
	
	@Override
	protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
		super.checkAdvancedSignatures(signatures);
		
		assertEquals(1, signatures.size());
	}
	
	@Override
	protected void checkValidationContext(SignedDocumentValidator validator) {
		super.checkValidationContext(validator);
		
		PDFDocumentValidator pdfDocumentValidator = (PDFDocumentValidator) validator;

		List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();

		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		PAdESSignature pades = (PAdESSignature) signatures.get(0);
		PdfDssDict dssDictionary = pades.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

		PAdESCertificateSource certificateSource = (PAdESCertificateSource) pades.getCertificateSource();
		assertEquals(3, certificateSource.getCertificateMap().size()); // only from the DSS dictionary

		PAdESOCSPSource padesOCSPSource = (PAdESOCSPSource) pades.getOCSPSource();
		assertTrue(padesOCSPSource.getOcspMap().isEmpty());

		PAdESCRLSource crlSource = (PAdESCRLSource) pades.getCRLSource();
		assertEquals(5, crlSource.getCrlMap().size());

		PdfRevision pdfRevision = pades.getPdfRevision();
		assertNotNull(pdfRevision);
		
		List<PdfDssDict> dssDictionaries = pdfDocumentValidator.getDssDictionaries();
		assertEquals(2, dssDictionaries.size());
		
		Iterator<PdfDssDict> iterator = dssDictionaries.iterator();

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>
		dssDictionary = iterator.next();
		
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCERTs().size());
		assertEquals(2, dssDictionary.getCRLs().size());

		// Same than for the signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		dssDictionary = iterator.next();
		
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		SignatureCertificateSource certificateSource = advancedSignatures.get(0).getCertificateSource();
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
		
		assertNotEquals(certificateSource.getDSSDictionaryCertValues().size(),
					foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size() +
					foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
		assertEquals(new HashSet<>(certificateSource.getDSSDictionaryCertValues()).size(), 
				foundCertificates.getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size() +
				foundCertificates.getOrphanCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY).size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertTrue(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertTrue(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}

}
