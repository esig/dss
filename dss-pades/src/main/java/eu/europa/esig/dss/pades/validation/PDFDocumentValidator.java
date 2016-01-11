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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUnsupportedOperationException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
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
	private static final String BASE64_REGEX = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";

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
	public DSSDocument getOriginalDocument(String signatureId) throws DSSException {
		if (StringUtils.isBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}
		for(AdvancedSignature signature : signatures) {
			PAdESSignature padesSignature = (PAdESSignature) signature;
			if(padesSignature.getId().equals(signatureId)) {
				CAdESSignature cadesSignature = padesSignature.getCAdESSignature();
				DSSDocument inMemoryDocument = null;
				DSSDocument firstDocument = null;
				for(DSSDocument document : cadesSignature.getDetachedContents()) {
					byte[] content;
					try {
						content = IOUtils.toByteArray(document.openStream());
					} catch (IOException e) {
						throw new DSSException(e);
					}
					content = isBase64Encoded(content) ? Base64.decode(content) : content;
					if(firstDocument == null) {
						firstDocument = new InMemoryDocument(content);
						inMemoryDocument = firstDocument;
					} else {
						DSSDocument doc = new InMemoryDocument(content);
						inMemoryDocument.setNextDocument(document);
						inMemoryDocument = document;
					}					
				}
				return firstDocument;
			}
		}
		throw new DSSException("The signature with the given id was not found!");
	}
	
	private boolean isBase64Encoded(byte[] array) {
		return isBase64Encoded(new String(array));
	}
	
	private boolean isBase64Encoded(String text) {
		Pattern pattern = Pattern.compile(BASE64_REGEX);
		Matcher matcher = pattern.matcher(text);
		return matcher.matches();
	}

}