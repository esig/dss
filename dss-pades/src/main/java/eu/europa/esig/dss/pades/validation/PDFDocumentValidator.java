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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.scope.PAdESSignatureScopeFinder;
import eu.europa.esig.dss.pdf.IPdfObjFactory;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureValidationCallback;
import eu.europa.esig.dss.pdf.PdfTimestampValidationCallback;
import eu.europa.esig.dss.pdf.ServiceLoaderPdfObjFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.timestamp.SignatureAndTimestampProcessExecutor;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampValidator;

/**
 * Validation of PDF document.
 */
public class PDFDocumentValidator extends SignedDocumentValidator implements TimestampValidator {
	
	private static final byte[] pdfPreamble = new byte[] { '%', 'P', 'D', 'F', '-' };

	private IPdfObjFactory pdfObjectFactory = new ServiceLoaderPdfObjFactory();

	PDFDocumentValidator() {
		super(null);
	}

	/**
	 * The default constructor for PDFDocumentValidator.
	 */
	public PDFDocumentValidator(final DSSDocument document) {
		super(new PAdESSignatureScopeFinder());
		this.document = document;
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		return DSSUtils.compareFirstBytes(dssDocument, pdfPreamble);
	}
	
	@Override
	public SignatureAndTimestampProcessExecutor getDefaultProcessExecutor() {
		return new SignatureAndTimestampProcessExecutor();
	}

	/**
	 * Set the IPdfObjFactory. Allow to set the used implementation. Cannot be null.
	 * 
	 * @param pdfObjFactory
	 *                      the implementation to be used.
	 */
	public void setPdfObjFactory(IPdfObjFactory pdfObjFactory) {
		Objects.requireNonNull(pdfObjFactory, "PdfObjFactory is null");
		this.pdfObjectFactory = pdfObjFactory;
	}

	@Override
	public List<AdvancedSignature> getSignatures() {
		final List<AdvancedSignature> signatures = new ArrayList<AdvancedSignature>();

		PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
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
	public Map<TimestampToken, List<SignatureScope>> getTimestamps() {
		// use LinkedHashMap in order to keep the timestamp order
		final Map<TimestampToken, List<SignatureScope>> timestamps = new LinkedHashMap<TimestampToken, List<SignatureScope>>();

		PDFSignatureService pdfSignatureService = pdfObjectFactory.newPAdESSignatureService();
		pdfSignatureService.validateSignatures(validationCertPool, document, new PdfTimestampValidationCallback() {
			
			@Override
			public void validate(PdfDocTimestampInfo docTimestampInfo) {
				
				try {
					if (docTimestampInfo.getCMSSignedData() != null) {
						TimestampToken timestampToken = new TimestampToken(
								docTimestampInfo.getCMSSignedData(), TimestampType.CONTENT_TIMESTAMP, validationCertPool);
						timestampToken.setFileName(document.getName());
						timestampToken.matchData(new InMemoryDocument(docTimestampInfo.getSignedDocumentBytes()));
						
						PAdESSignatureScopeFinder signatureScopeFinder = new PAdESSignatureScopeFinder();
						signatureScopeFinder.setDefaultDigestAlgorithm(getDefaultDigestAlgorithm());
						SignatureScope signatureScope = signatureScopeFinder.findSignatureScope(docTimestampInfo);
						
						timestamps.put(timestampToken, Arrays.asList(signatureScope));
						
					}
				} catch (Exception e) {
					throw new DSSException(e);
					
				}
				
			}
		});
		return timestamps;
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) throws DSSException {
		if (Utils.isStringBlank(signatureId)) {
			throw new NullPointerException("signatureId");
		}
		List<AdvancedSignature> signatures = getSignatures();
		for (AdvancedSignature signature : signatures) {
			if (signature.getId().equals(signatureId)) {
				return getOriginalDocuments(signature);
			}
		}
		return Collections.emptyList();
	}
	
	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) throws DSSException {
		PAdESSignature padesSignature = (PAdESSignature) advancedSignature;
		List<DSSDocument> result = new ArrayList<DSSDocument>();
		InMemoryDocument originalPDF = PAdESUtils.getOriginalPDF(padesSignature);
		if (originalPDF != null) {
			result.add(originalPDF);
		}
		return result;
	}

}
