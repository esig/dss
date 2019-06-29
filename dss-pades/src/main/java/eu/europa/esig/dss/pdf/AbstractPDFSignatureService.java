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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.tsp.TimeStampToken;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.tsp.TSPSource;

public abstract class AbstractPDFSignatureService implements PDFSignatureService, PDFTimestampService {

	protected final boolean timestamp;
	protected final SignatureDrawerFactory signatureDrawerFactory;

	/**
	 * Constructor for the PDFSignatureService
	 * 
	 * @param timestamp
	 *                               if true, the instance is used to generate
	 *                               DocumentTypestamp if false, it is used to
	 *                               generate a signature layer
	 * @param signatureDrawerFactory
	 *                               the factory of {@code SignatureDrawer}
	 */
	protected AbstractPDFSignatureService(boolean timestamp, SignatureDrawerFactory signatureDrawerFactory) {
		this.timestamp = timestamp;
		this.signatureDrawerFactory = signatureDrawerFactory;
	}

	protected String getType() {
		if (timestamp) {
			return PAdESConstants.TIMESTAMP_TYPE;
		} else {
			return PAdESConstants.SIGNATURE_TYPE;
		}
	}

	protected String getFilter(PAdESSignatureParameters parameters) {
		if (timestamp) {
			if (Utils.isStringNotEmpty(parameters.getTimestampFilter())) {
				return parameters.getTimestampFilter();
			}
			return PAdESConstants.TIMESTAMP_DEFAULT_FILTER;

		} else {
			if (Utils.isStringNotEmpty(parameters.getSignatureFilter())) {
				return parameters.getSignatureFilter();
			}
			return PAdESConstants.SIGNATURE_DEFAULT_FILTER;
		}
	}

	protected String getSubFilter(PAdESSignatureParameters parameters) {
		if (timestamp) {
			if (Utils.isStringNotEmpty(parameters.getTimestampSubFilter())) {
				return parameters.getTimestampSubFilter();
			}
			return PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER;
		} else {
			if (Utils.isStringNotEmpty(parameters.getSignatureSubFilter())) {
				return parameters.getSignatureSubFilter();
			}
			return PAdESConstants.SIGNATURE_DEFAULT_SUBFILTER;
		}
	}

	protected SignatureImageParameters getImageParameters(PAdESSignatureParameters parameters) {
		if (timestamp) {
			return parameters.getTimestampImageParameters();
		} else {
			return parameters.getSignatureImageParameters();
		}
	}

	protected String getSignatureName(PAdESSignatureParameters parameters) {
		if (parameters.getSignatureName() != null) {
			return parameters.getSignatureName();
		} else {

			CertificateToken token = parameters.getSigningCertificate();
			Date date = parameters.bLevel().getSigningDate();
			String encodedDate = Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, Long.toString(date.getTime()).getBytes()));

			if (token == null) {
				return "Unknown signer " + encodedDate;
			} else {
				return DSSASN1Utils.getHumanReadableName(token) + " " + encodedDate;
			}
		}
	}

	@Override
	public DSSDocument timestamp(DSSDocument document, PAdESSignatureParameters parameters, TSPSource tspSource) {
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		final byte[] digest = digest(document, parameters, timestampDigestAlgorithm);
		final TimeStampToken timeStampToken = tspSource.getTimeStampResponse(timestampDigestAlgorithm, digest);
		final byte[] encoded = DSSASN1Utils.getDEREncoded(timeStampToken);
		return sign(document, encoded, parameters, timestampDigestAlgorithm);
	}

	@Override
	public void validateSignatures(CertificatePool validationCertPool, DSSDocument document,
			SignatureValidationCallback callback) {
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

		Collections.sort(signatures, new PdfSignatureOrDocTimestampInfoComparator());

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

	protected void validateByteRange(int[] byteRange) {

		if (byteRange == null || byteRange.length != 4) {
			throw new DSSException("Incorrect BytRange size");
		}

		final int a = byteRange[0];
		final int b = byteRange[1];
		final int c = byteRange[2];
		final int d = byteRange[3];

		if (a != 0) {
			throw new DSSException("The BytRange must cover start of file");
		}
		if (b <= 0) {
			throw new DSSException("The first hash part doesn't cover anything");
		}
		if (c <= b) {
			throw new DSSException("The second hash part must start after the first hash part");
		}
		if (d <= 0) {
			throw new DSSException("The second hash part doesn't cover anything");
		}
	}

	/**
	 * This method builds a Map of known Objects (extracted from previous DSS
	 * Dictionaries). This map will be used to avoid duplicate the same objects
	 * between layers.
	 * 
	 * @param callbacks
	 * @return
	 */
	protected Map<String, Long> buildKnownObjects(List<DSSDictionaryCallback> callbacks) {
		Map<String, Long> result = new HashMap<String, Long>();
		for (DSSDictionaryCallback callback : callbacks) {

			Map<Long, CertificateToken> storedCertificates = callback.getStoredCertificates();
			for (Entry<Long, CertificateToken> certEntry : storedCertificates.entrySet()) {
				result.put(getTokenDigest(certEntry.getValue()), certEntry.getKey());
			}

			Map<Long, BasicOCSPResp> storedOcspResps = callback.getStoredOcspResps();
			for (Entry<Long, BasicOCSPResp> ocspEntry : storedOcspResps.entrySet()) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(ocspEntry.getValue());
				result.put(Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, DSSRevocationUtils.getEncoded(ocspResp))), ocspEntry.getKey());
			}

			Map<Long, byte[]> storedCrls = callback.getStoredCrls();
			for (Entry<Long, byte[]> crlEntry : storedCrls.entrySet()) {
				result.put(Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, crlEntry.getValue())), crlEntry.getKey());
			}
		}
		return result;
	}

	protected String getTokenDigest(Token token) {
		return Utils.toBase64(token.getDigest(DigestAlgorithm.SHA256));
	}

}
