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
package eu.europa.esig.dss.pades.validation;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureValidationCallback;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Validation of PDF document.
 */
public class PDFDocumentValidator extends SignedDocumentValidator {

	private final PDFSignatureService pdfSignatureService;

	/**
	 * Default constructor used with reflexion (see SignedDocumentValidator)
	 */
	private PDFDocumentValidator() {
		super(null);
		pdfSignatureService = null;
	}

	/**
	 * The default constructor for PDFDocumentValidator.
	 */
	public PDFDocumentValidator(final DSSDocument document) {
		super(new PAdESSignatureScopeFinder());
		this.document = document;
		pdfSignatureService = PdfObjFactory.newPAdESSignatureService();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		int headerLength = 50;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		String preambleString = new String(preamble);
		return preambleString.startsWith("%PDF-");
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		final List<AdvancedSignature> signatures = new ArrayList<AdvancedSignature>();

		pdfSignatureService.validateSignatures(validationCertPool, document, new PdfSignatureValidationCallback() {

			@Override
			public void validate(final PdfSignatureInfo pdfSignatureInfo) {
				try {
					if (pdfSignatureInfo.getCades() != null) {

						final PAdESSignature padesSignature = new PAdESSignature(document, pdfSignatureInfo, validationCertPool);
						padesSignature.setSignatureFilename(document.getName());
						padesSignature.setProvidedSigningCertificateToken(providedSigningCertificateToken);
						signatures.add(padesSignature);
					}
				} catch (Exception e) {
					throw new DSSException(e);
				}
			}
		});
		return signatures;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) throws DSSException {
		if (Utils.isStringBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}
		List<DSSDocument> result = new ArrayList<DSSDocument>();

		List<AdvancedSignature> signatures = getSignatures();
		for (AdvancedSignature signature : signatures) {
			PAdESSignature padesSignature = (PAdESSignature) signature;
			if (padesSignature.getId().equals(signatureId)) {
				CAdESSignature cadesSignature = padesSignature.getCAdESSignature();
				List<DSSDocument> cadesDetachedFile = cadesSignature.getDetachedContents();
				if (Utils.collectionSize(cadesDetachedFile) == 1) {
					// data before adding the signature value
					DSSDocument dataToBeSigned = cadesDetachedFile.get(0);

					int[] signatureByteRange = padesSignature.getSignatureByteRange();
					DSSDocument firstByteRangePart = DSSUtils.splitDocument(dataToBeSigned, signatureByteRange[0], signatureByteRange[1]);
					DSSDocument lastRevision = retrieveLastPDFRevision(firstByteRangePart);
					result.add(lastRevision);
				}
			}
		}
		return result;
	}

	private DSSDocument retrieveLastPDFRevision(DSSDocument firstByteRangePart) {
		final byte[] eof = new byte[] { '%', '%', 'E', 'O', 'F' };
		try (InputStream is = firstByteRangePart.openStream();
				BufferedInputStream bis = new BufferedInputStream(is);
				ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

			ByteArrayOutputStream tempLine = new ByteArrayOutputStream();
			ByteArrayOutputStream tempRevision = new ByteArrayOutputStream();
			int b;
			while ((b = bis.read()) != -1) {
				final char c = (char) b;
				/*
				 * 0x0a = New Line
				 * 0x0d = Carriage return
				 */
				if ((c != 0x0a) && (c != 0x0d)) {
					tempLine.write(b);
				} else {
					final byte[] byteArray = tempLine.toByteArray();
					tempRevision.write(byteArray);
					tempRevision.write(b);
					// End of a document revision
					if (Arrays.equals(byteArray, eof)) {
						baos.write(tempRevision.toByteArray());
						tempRevision.close();
						tempRevision = new ByteArrayOutputStream();
					}
					tempLine.close();
					tempLine = new ByteArrayOutputStream();
				}
			}
			tempRevision.close();
			tempLine.close();

			baos.flush();
			return new InMemoryDocument(baos.toByteArray(), "original.pdf", MimeType.PDF);

		} catch (IOException e) {
			throw new DSSException("Unable to retrieve the last revision", e);
		}
	}

}