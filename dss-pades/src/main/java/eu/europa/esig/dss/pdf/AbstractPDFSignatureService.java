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
package eu.europa.esig.dss.pdf;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

public abstract class AbstractPDFSignatureService implements PDFSignatureService {

	protected String getType() {
		return SIGNATURE_TYPE;
	}

	protected String getFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getSignatureFilter())) {
			return parameters.getSignatureFilter();
		}
		return SIGNATURE_DEFAULT_FILTER;
	}

	protected String getSubFilter(PAdESSignatureParameters parameters) {
		if (Utils.isStringNotEmpty(parameters.getSignatureSubFilter())) {
			return parameters.getSignatureSubFilter();
		}
		return SIGNATURE_DEFAULT_SUBFILTER;
	}

	protected String getSignatureName(PAdESSignatureParameters parameters) {
		if (parameters.getSignatureName() != null) {
			return parameters.getSignatureName();
		} else {

			CertificateToken token = parameters.getSigningCertificate();
			Date date = parameters.bLevel().getSigningDate();
			String encodedDate = Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, Long.toString(date.getTime()).getBytes()));

			if (token == null) {
				return "Unknown signer" + encodedDate;
			} else {
				return DSSASN1Utils.getHumanReadableName(token) + encodedDate;
			}
		}
	}

	@Override
	public void validateSignatures(CertificatePool validationCertPool, DSSDocument document, SignatureValidationCallback callback) throws DSSException {
		List<PdfSignatureOrDocTimestampInfo> signaturesFound = getSignatures(validationCertPool, document);
		for (PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo : signaturesFound) {
			callback.validate(pdfSignatureOrDocTimestampInfo);
		}
	}

	protected abstract List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool, DSSDocument document);

	/**
	 * This method links previous signatures to the new one. This is useful to get
	 * revision number and to know if a TSP is over the DSS dictionary
	 */
	protected void linkSignatures(List<PdfSignatureOrDocTimestampInfo> signatures) {
		List<PdfSignatureOrDocTimestampInfo> previousList = new ArrayList<PdfSignatureOrDocTimestampInfo>();
		for (PdfSignatureOrDocTimestampInfo sig : signatures) {
			if (Utils.isCollectionNotEmpty(previousList)) {
				for (PdfSignatureOrDocTimestampInfo previous : previousList) {
					previous.addOuterSignature(sig);
				}
			}
			previousList.add(sig);
		}
	}

	protected byte[] getOriginalBytes(int[] byteRange, byte[] signedContent) {
		final int length = byteRange[1];
		final byte[] result = new byte[length];
		System.arraycopy(signedContent, 0, result, 0, length);
		return result;
	}

}
