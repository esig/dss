package eu.europa.esig.dss.pades.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Iterator;
import java.util.List;
import java.util.Set;

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
		assertEquals(3, dssDictionary.getCertMap().size());
		assertEquals(5, dssDictionary.getCrlMap().size());

		Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		assertEquals(2, outerSignatures.size());

		// <</Type /DSS
		// /Certs [20 0 R]
		// /CRLs [21 0 R 22 0 R]>>

		Iterator<PdfSignatureOrDocTimestampInfo> iterator = outerSignatures.iterator();
		PdfSignatureOrDocTimestampInfo archiveTST = iterator.next();
		assertTrue(archiveTST.isTimestamp());
		dssDictionary = archiveTST.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(1, dssDictionary.getCertMap().size());
		assertEquals(2, dssDictionary.getCrlMap().size());

		// Same than for the signature
		// <</Type /DSS
		// /Certs [20 0 R 26 0 R 30 0 R]
		// /CRLs [21 0 R 22 0 R 27 0 R 28 0 R 29 0 R]>>
		PdfSignatureOrDocTimestampInfo archiveTST2 = iterator.next();
		assertTrue(archiveTST2.isTimestamp());
		dssDictionary = archiveTST2.getDssDictionary();
		assertNotNull(dssDictionary);
		assertEquals(3, dssDictionary.getCertMap().size());
		assertEquals(5, dssDictionary.getCrlMap().size());

	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
