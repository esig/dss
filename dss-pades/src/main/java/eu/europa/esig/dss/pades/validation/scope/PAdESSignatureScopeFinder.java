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
package eu.europa.esig.dss.pades.validation.scope;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 *
 */
public class PAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<PAdESSignature> {

	@Override
	public List<SignatureScope> findSignatureScope(final PAdESSignature pAdESSignature) {

		List<SignatureScope> result = new ArrayList<SignatureScope>();
		final PdfSignatureInfo pdfSignature = pAdESSignature.getPdfSignatureInfo();
		if (pdfSignature.isCoverAllOriginalBytes()) {
			result.add(new FullSignatureScope("Full PDF", getOriginalPdfDigest(pAdESSignature)));
		} else if (pAdESSignature.hasOuterSignatures()) {
			final int outerSignatureSize = pdfSignature.getOuterSignatures().size();
			result.add(new PdfByteRangeSignatureScope("PDF previous version #" + outerSignatureSize, pdfSignature.getSignatureByteRange(), 
					getOriginalPdfDigest(pAdESSignature)));
		} else {
			result.add(new PdfByteRangeSignatureScope("Partial PDF", pdfSignature.getSignatureByteRange(), 
					getOriginalPdfDigest(pAdESSignature)));
		}
		return result;
	}
	
	private Digest getOriginalPdfDigest(PAdESSignature padesSignature) {
		return getDigest(getOriginalPdfBytes(padesSignature));
	}
	
	private byte[] getOriginalPdfBytes(PAdESSignature padesSignature) {
		InMemoryDocument originalPDF = PAdESUtils.getOriginalPDF(padesSignature);
		return originalPDF.getBytes();
	}
	
}
