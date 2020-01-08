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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.PAdESCRLSource;
import eu.europa.esig.dss.pades.validation.PAdESCertificateSource;
import eu.europa.esig.dss.pades.validation.PAdESOCSPSource;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.pdf.PdfCMSRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.PdfRevision;

public class ArchiveTimestampCoverageTest extends PKIFactoryAccess {

	/**
	 * Duplicate streams
	 * 
	 * CRLs: 27 = 21
	 * 
	 * 28 = 22
	 * 
	 * Certificates: 20=26
	 */

	@Test
	public void doc0() {
		DSSDocument dssDocument = new InMemoryDocument(getClass().getResourceAsStream("/validation/dss-1696/Test.signed_Certipost-2048-SHA512.extended.pdf"));
		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

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
		List<PdfRevision> outerSignatures = pdfRevision.getOuterSignatures();
		assertEquals(2, outerSignatures.size());

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>

		Iterator<PdfRevision> iterator = outerSignatures.iterator();
		PdfCMSRevision archiveTST = (PdfCMSRevision) iterator.next();
		assertTrue(archiveTST.isTimestampRevision());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCERTs().size());
		assertEquals(2, dssDictionary.getCRLs().size());

		// Same than for the signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		PdfCMSRevision archiveTST2 = (PdfCMSRevision) iterator.next();
		assertTrue(archiveTST2.isTimestampRevision());
		dssDictionary = archiveTST2.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

	}

	@Test
	public void doc1() {
		DSSDocument dssDocument = new InMemoryDocument(
				getClass().getResourceAsStream("/validation/dss-1696/Test.signed_Certipost-2048-SHA512.extended.extended-2019-07-02.pdf"));
		PDFDocumentValidator validator = new PDFDocumentValidator(dssDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());

		List<AdvancedSignature> signatures = validator.getSignatures();
		assertEquals(1, signatures.size());

		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R 35 0 R 39 0 R 40 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R 34 0 R 36 0 R 37 0 R 38 0 R]>>
		PAdESSignature pades = (PAdESSignature) signatures.get(0);
		PdfDssDict dssDictionary = pades.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(6, dssDictionary.getCERTs().size());
		assertEquals(9, dssDictionary.getCRLs().size());

		PdfRevision pdfRevision = pades.getPdfRevision();
		assertNotNull(pdfRevision);
		List<PdfRevision> outerSignatures = pdfRevision.getOuterSignatures();
		assertEquals(3, outerSignatures.size());

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>
		Iterator<PdfRevision> iterator = outerSignatures.iterator();
		PdfCMSRevision archiveTST = (PdfCMSRevision) iterator.next();
		assertTrue(archiveTST.isTimestampRevision());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCERTs().size());
		assertEquals(2, dssDictionary.getCRLs().size());

		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		archiveTST = (PdfCMSRevision) iterator.next();
		assertTrue(archiveTST.isTimestampRevision());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

		// Same than for signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R 35 0 R 39 0 R 40 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R 34 0 R 36 0 R 37 0 R 38 0 R]>>
		archiveTST = (PdfCMSRevision) iterator.next();
		assertTrue(archiveTST.isTimestampRevision());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(6, dssDictionary.getCERTs().size());
		assertEquals(9, dssDictionary.getCRLs().size());
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
