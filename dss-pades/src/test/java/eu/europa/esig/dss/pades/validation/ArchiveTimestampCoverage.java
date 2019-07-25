package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class ArchiveTimestampCoverage extends PKIFactoryAccess {

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
		PdfSignatureInfo pdfSignatureInfo = pades.getPdfSignatureInfo();
		PdfDssDict dssDictionary = pdfSignatureInfo.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

		PAdESCertificateSource certificateSource = (PAdESCertificateSource) pades.getCertificateSource();
		assertEquals(3, certificateSource.getCertificateMap().size()); // only from the DSS dictionary

		PAdESOCSPSource padesOCSPSource = (PAdESOCSPSource) pades.getOCSPSource();
		assertTrue(padesOCSPSource.getOcspMap().isEmpty());

		PAdESCRLSource crlSource = (PAdESCRLSource) pades.getCRLSource();
		assertEquals(5, crlSource.getCrlMap().size());

		List<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		assertEquals(2, outerSignatures.size());

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>

		Iterator<PdfSignatureOrDocTimestampInfo> iterator = outerSignatures.iterator();
		PdfSignatureOrDocTimestampInfo archiveTST = iterator.next();
		assertTrue(archiveTST.isTimestamp());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCERTs().size());
		assertEquals(2, dssDictionary.getCRLs().size());

		// Same than for the signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		PdfSignatureOrDocTimestampInfo archiveTST2 = iterator.next();
		assertTrue(archiveTST2.isTimestamp());
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
		PdfSignatureInfo pdfSignatureInfo = pades.getPdfSignatureInfo();
		PdfDssDict dssDictionary = pdfSignatureInfo.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(6, dssDictionary.getCERTs().size());
		assertEquals(9, dssDictionary.getCRLs().size());

		List<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		assertEquals(3, outerSignatures.size());

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>
		Iterator<PdfSignatureOrDocTimestampInfo> iterator = outerSignatures.iterator();
		PdfSignatureOrDocTimestampInfo archiveTST = iterator.next();
		assertTrue(archiveTST.isTimestamp());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCERTs().size());
		assertEquals(2, dssDictionary.getCRLs().size());

		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		archiveTST = iterator.next();
		assertTrue(archiveTST.isTimestamp());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCERTs().size());
		assertEquals(5, dssDictionary.getCRLs().size());

		// Same than for signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R 35 0 R 39 0 R 40 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R 34 0 R 36 0 R 37 0 R 38 0 R]>>
		archiveTST = iterator.next();
		assertTrue(archiveTST.isTimestamp());
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
