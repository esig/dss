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

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.pades.PAdESUtils;
import eu.europa.esig.dss.pades.validation.PAdESSignature;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

/**
 * The classes finds a signer data for a PAdESSignature / PdfSignatureOrDocTimestampInfo instance
 *
 */
public class PAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<PAdESSignature> {

	@Override
	public List<SignatureScope> findSignatureScope(final PAdESSignature pAdESSignature) {
		return Arrays.asList(findSignatureScope(pAdESSignature.getPdfRevision()));
	}
	
	public SignatureScope findSignatureScope(final PdfRevision pdfRevision) {
			
		if (pdfRevision.doesSignatureCoverAllOriginalBytes()) {
			return new FullSignatureScope("Full PDF", getOriginalPdfDigest(pdfRevision));
		} else if (Utils.isCollectionNotEmpty(pdfRevision.getOuterSignatures())) {
			return new PdfByteRangeSignatureScope("PDF previous version #" + pdfRevision.getOuterSignatures().size(), 
					pdfRevision.getSignatureByteRange(), getOriginalPdfDigest(pdfRevision));
		} else {
			return new PdfByteRangeSignatureScope("Partial PDF", pdfRevision.getSignatureByteRange(), 
					getOriginalPdfDigest(pdfRevision));
		}
	}
	
	private Digest getOriginalPdfDigest(final PdfRevision pdfRevision) {
		DSSDocument originalDocument = PAdESUtils.getOriginalPDF(pdfRevision);
		return new Digest(getDefaultDigestAlgorithm(), 
				DSSUtils.digest(getDefaultDigestAlgorithm(), originalDocument));
	}
	
}
