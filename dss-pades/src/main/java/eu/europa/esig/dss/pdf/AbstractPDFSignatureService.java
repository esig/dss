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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.Token;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pdf.visible.SignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.PdfRevision;
import eu.europa.esig.dss.validation.PdfSignatureDictionary;

public abstract class AbstractPDFSignatureService implements PDFSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractPDFSignatureService.class);

	protected final PDFServiceMode serviceMode;
	protected final SignatureDrawerFactory signatureDrawerFactory;

	/**
	 * Constructor for the PDFSignatureService
	 * 
	 * @param serviceMode
	 *                               current instance is used to generate
	 *                               DocumentTypestamp or Signature signature layer
	 * @param signatureDrawerFactory
	 *                               the factory of {@code SignatureDrawer}
	 */
	protected AbstractPDFSignatureService(PDFServiceMode serviceMode, SignatureDrawerFactory signatureDrawerFactory) {
		this.serviceMode = serviceMode;
		this.signatureDrawerFactory = signatureDrawerFactory;
	}

	protected boolean isDocumentTimestampLayer() {
		// CONTENT_TIMESTAMP is part of the signature
		return PDFServiceMode.SIGNATURE_TIMESTAMP == serviceMode || PDFServiceMode.ARCHIVE_TIMESTAMP == serviceMode;
	}

	protected String getType() {
		if (isDocumentTimestampLayer()) {
			return PAdESConstants.TIMESTAMP_TYPE;
		} else {
			return PAdESConstants.SIGNATURE_TYPE;
		}
	}

	protected String getFilter(PAdESSignatureParameters parameters) {
		if (isDocumentTimestampLayer()) {
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
		if (isDocumentTimestampLayer()) {
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
		if (isDocumentTimestampLayer()) {
			return parameters.getTimestampImageParameters();
		} else {
			return parameters.getSignatureImageParameters();
		}
	}

	protected DigestAlgorithm getCurrentDigestAlgorithm(PAdESSignatureParameters parameters) {
		switch (serviceMode) {
		case CONTENT_TIMESTAMP:
			return parameters.getContentTimestampParameters().getDigestAlgorithm();
		case SIGNATURE:
			return parameters.getDigestAlgorithm();
		case SIGNATURE_TIMESTAMP:
			return parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		case ARCHIVE_TIMESTAMP:
			return parameters.getArchiveTimestampParameters().getDigestAlgorithm();
		default:
			throw new DSSException("Unsupported service mode : " + serviceMode);
		}
	}

	protected int getCurrentSignatureSize(PAdESSignatureParameters parameters) {
		if (isDocumentTimestampLayer()) {
			return parameters.getTimestampSize();
		} else {
			return parameters.getSignatureSize();
		}
	}

	@Override
	public void validateSignatures(CertificatePool validationCertPool, DSSDocument document,
			SignatureValidationCallback callback) {
		List<PdfRevision> signaturesFound = getSignatures(validationCertPool, document);
		for (PdfRevision pdfRevision : signaturesFound) {
			callback.validate(pdfRevision);
		}
	}

	protected abstract List<PdfRevision> getSignatures(CertificatePool validationCertPool, DSSDocument document);

	/**
	 * This method links previous signatures to the new one. This is useful to get
	 * revision number and to know if a TSP is over the DSS dictionary
	 */
	protected void linkSignatures(List<PdfRevision> signatures) {

		Collections.sort(signatures, new PdfRevisionComparator());

		List<PdfRevision> previousList = new ArrayList<PdfRevision>();
		for (PdfRevision sig : signatures) {
			if (Utils.isCollectionNotEmpty(previousList)) {
				for (PdfRevision previous : previousList) {
					previous.addOuterSignature(sig);
				}
			}
			previousList.add(sig);
		}
	}

	protected byte[] getSignedContent(DSSDocument dssDocument, int[] byteRange) throws IOException {
		// Adobe Digital Signatures in a PDF (p5): In Figure 4, the hash is calculated
		// for bytes 0 through 840, and 960 through 1200. [0, 840, 960, 1200]
		int beginning = byteRange[0];
		int startSigValueContent = byteRange[1];
		int endSigValueContent = byteRange[2];
		int endValue = byteRange[3];
		
		byte[] signedContentByteArray = new byte[startSigValueContent + endValue];
		
		try (InputStream is = dssDocument.openStream()) {
			
			DSSUtils.skipAvailableBytes(is, beginning);
			DSSUtils.readAvailableBytes(is, signedContentByteArray, 0, startSigValueContent);
			DSSUtils.skipAvailableBytes(is, (long)endSigValueContent - startSigValueContent - beginning);
			DSSUtils.readAvailableBytes(is, signedContentByteArray, startSigValueContent, endValue);
			
		} catch (IllegalStateException e) {
			LOG.error("Cannot extract signed content. Reason : {}", e.getMessage());
		}
		
		return signedContentByteArray;
	}
	
	protected boolean isContentValueEqualsByteRangeExtraction(DSSDocument document, int[] byteRange, byte[] cms, List<String> signatureFieldNames) {
		boolean match = false;
		try {
			byte[] cmsWithByteRange = getSignatureValue(document, byteRange);
			match = Arrays.equals(cms, cmsWithByteRange);
			if (!match) {
				LOG.warn("Conflict between /Content and ByteRange for Signature {}.", signatureFieldNames);
			}
		} catch (IOException | IllegalArgumentException e) {
			String message = String.format("Unable to retrieve data from the ByteRange (%s to %s)", byteRange[0] + byteRange[1], byteRange[2]);
			if (LOG.isDebugEnabled()) {
				// Exception displays the (long) hex value
				LOG.debug(message, e);
			} else {
				LOG.error(message);
			}
		}
		return match;
	}
	
	protected byte[] getSignatureValue(DSSDocument dssDocument, int[] byteRange) throws IOException {
		// Extracts bytes from 841 to 959. [0, 840, 960, 1200]
		int startSigValueContent = byteRange[0] + byteRange[1] + 1;
		int endSigValueContent = byteRange[2] - 1;
		
		int signatureValueArraySize = endSigValueContent - startSigValueContent;
		if (signatureValueArraySize < 1) {
			throw new DSSException("The byte range present in the document is not valid! "
					+ "SignatureValue size cannot be negative or equal to zero!");
		}

		byte[] signatureValueArray = new byte[signatureValueArraySize];
		
		try (InputStream is = dssDocument.openStream()) {
			
			DSSUtils.skipAvailableBytes(is, startSigValueContent);
			DSSUtils.readAvailableBytes(is, signatureValueArray);
			
		} catch (IllegalStateException e) {
			LOG.error("Cannot extract signature value. Reason : {}", e.getMessage());
		}
		
		return Utils.fromHex(new String(signatureValueArray));
	}

	protected byte[] getOriginalBytes(int[] byteRange, byte[] signedContent) {
		final int length = byteRange[1];
		final byte[] result = new byte[length];
		System.arraycopy(signedContent, 0, result, 0, length);
		return result;
	}

	protected void validateByteRange(int[] byteRange) {

		if (byteRange == null || byteRange.length != 4) {
			throw new DSSException("Incorrect ByteRange size");
		}

		final int a = byteRange[0];
		final int b = byteRange[1];
		final int c = byteRange[2];
		final int d = byteRange[3];

		if (a != 0) {
			throw new DSSException("The ByteRange must cover start of file");
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
	 * Checks if the given signature dictionary represents a DocTimeStamp
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a DocTimeStamp, FALSE otherwise
	 */
	protected boolean isDocTimestamp(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.TIMESTAMP_TYPE.equals(type)) && PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
	}

	/**
	 * Checks if the given signature dictionary represents a Signature
	 * 
	 * @param pdfSigDict {@link PdfSignatureDictionary} to check
	 * @return TRUE if the signature dictionary represents a Signature, FALSE otherwise
	 */
	protected boolean isSignature(PdfSignatureDictionary pdfSigDict) {
		String type = pdfSigDict.getType();
		String subFilter = pdfSigDict.getSubFilter();
		/* Support historical TS 102 778-4 and new EN 319 142-1 */
		return (type == null || PAdESConstants.SIGNATURE_TYPE.equals(type)) && !PAdESConstants.TIMESTAMP_DEFAULT_SUBFILTER.equals(subFilter);
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
				String tokenKey = getTokenDigest(certEntry.getValue());
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, certEntry.getKey());
				}
			}

			Map<Long, BasicOCSPResp> storedOcspResps = callback.getStoredOcspResps();
			for (Entry<Long, BasicOCSPResp> ocspEntry : storedOcspResps.entrySet()) {
				final OCSPResp ocspResp = DSSRevocationUtils.fromBasicToResp(ocspEntry.getValue());
				String tokenKey = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, DSSRevocationUtils.getEncoded(ocspResp)));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, ocspEntry.getKey());
				}
			}

			Map<Long, byte[]> storedCrls = callback.getStoredCrls();
			for (Entry<Long, byte[]> crlEntry : storedCrls.entrySet()) {
				String tokenKey = Utils.toBase64(DSSUtils.digest(DigestAlgorithm.SHA256, crlEntry.getValue()));
				if (!result.containsKey(tokenKey)) { // keeps the really first occurrence
					result.put(tokenKey, crlEntry.getKey());
				}
			}
		}
		return result;
	}

	protected String getTokenDigest(Token token) {
		return Utils.toBase64(token.getDigest(DigestAlgorithm.SHA256));
	}

}
