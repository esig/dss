/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.pades;

import java.util.ArrayList;
import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSUnsupportedOperationException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureValidationCallback;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinder;
import eu.europa.ec.markt.dss.validation102853.scope.SignatureScopeFinderFactory;

/**
 * Validation of PDF document.
 *
 * @version $Revision: 889 $ - $Date: 2011-05-31 17:29:35 +0200 (Tue, 31 May 2011) $
 */

public class PDFDocumentValidator extends SignedDocumentValidator {

	// private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(PDFDocumentValidator.class.getName());

	final PDFSignatureService pdfSignatureService;

	/**
	 * The default constructor for PDFDocumentValidator.
	 */
	public PDFDocumentValidator(final DSSDocument document) {

		padesSignatureScopeFinder = SignatureScopeFinderFactory.geInstance(PAdESSignature.class);
		this.document = document;
		pdfSignatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
	}

	@Override
	public List<AdvancedSignature> getSignatures() {

		if (signatures != null) {
			return signatures;
		}
		signatures = new ArrayList<AdvancedSignature>();
		// TODO: (Bob: 2014 Feb 27) to be replaced document.openStream() by document
		pdfSignatureService.validateSignatures(validationCertPool, document.openStream(), new PdfSignatureValidationCallback() {

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

	@Override
	protected SignatureScopeFinder getSignatureScopeFinder() {
		return padesSignatureScopeFinder;
	}

}
