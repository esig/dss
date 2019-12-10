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
package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.pdf.AbstractPDFSignatureService;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.PdfRevision;

public class PdfSignatureServiceTest {

	private MockPdfSignatureSignature mockPDFSignatureSignature;

	@BeforeEach
	public void init() {
		mockPDFSignatureSignature = new MockPdfSignatureSignature(PDFServiceMode.SIGNATURE, null);
	}

	@Test
	public void validateByteRangeTest() {
		assertTrue(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 2400, 480 }));

		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 1, 1280, 2400, 480 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 0, 240, 480 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 240, 480 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0, 1280, 2400, 0 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[] { 0 }));
		assertFalse(mockPDFSignatureSignature.isByteRangeCorrect(new int[0]));
	}

	protected class MockPdfSignatureSignature extends AbstractPDFSignatureService {

		protected MockPdfSignatureSignature(PDFServiceMode mode, SignatureDrawerFactory signatureDrawerFactory) {
			super(mode, signatureDrawerFactory);
		}

		@Override
		public byte[] digest(DSSDocument toSignDocument, PAdESSignatureParameters parameters) {
			return null;
		}

		@Override
		public DSSDocument sign(DSSDocument pdfData, byte[] signatureValue, PAdESSignatureParameters parameters) {
			return null;
		}

		@Override
		public DSSDocument addDssDictionary(DSSDocument document, List<DSSDictionaryCallback> callbacks) {
			return null;
		}

		@Override
		public List<String> getAvailableSignatureFields(DSSDocument document) {
			return null;
		}

		@Override
		public DSSDocument addNewSignatureField(DSSDocument document, SignatureFieldParameters parameters) {
			return null;
		}

		@Override
		protected List<PdfRevision> getSignatures(CertificatePool validationCertPool, DSSDocument document) {
			return null;
		}

		protected boolean isByteRangeCorrect(int[] byteRange) {
			try {
				validateByteRange(byteRange);
				return true;
			} catch (DSSException e) {
				return false;
			}
		}

	}

}
