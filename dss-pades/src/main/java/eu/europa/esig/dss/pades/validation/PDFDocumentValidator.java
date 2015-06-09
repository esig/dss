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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfObjFactory;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureValidationCallback;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

/**
 * Validation of PDF document.
 *
 */
public class PDFDocumentValidator extends SignedDocumentValidator {

	final PDFSignatureService pdfSignatureService;

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
		pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		int headerLength = 500;
		byte[] preamble = new byte[headerLength];
		DSSUtils.readToArray(dssDocument, headerLength, preamble);
		String preambleString = new String(preamble);
		if (preambleString.startsWith("%PDF-")) {
			return true;
		}
		return false;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {

		if (signatures != null) {
			return signatures;
		}
		signatures = new ArrayList<AdvancedSignature>();
		pdfSignatureService.validateSignatures(validationCertPool, document, new PdfSignatureValidationCallback() {

			@Override
			public void validate(final PdfSignatureInfo pdfSignatureInfo) {
				try {
					if (pdfSignatureInfo.getCades() != null) {

						final PAdESSignature padesSignature = new PAdESSignature(document, pdfSignatureInfo, validationCertPool);
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
	public DSSDocument removeSignature(String signatureId) throws DSSException {
		throw new DSSUnsupportedOperationException("This method is not applicable for this kind of signatures!");
	}

}