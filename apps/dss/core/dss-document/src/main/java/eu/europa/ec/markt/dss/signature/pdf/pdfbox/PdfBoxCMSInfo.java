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

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;

abstract class PdfBoxCMSInfo implements PdfSignatureOrDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxCMSInfo.class);
	protected final CertificatePool validationCertPool;
	private final PdfDssDict outerCatalog;
	private final PdfDssDict documentDictionary;
	private final Date signingDate;
	private final String location;
	private final int[] signatureByteRange;

	protected final byte[] cms;

	/**
	 * The original signed pdf document
	 */
	final byte[] signedBytes;

	protected InputStream inputStream;
	private boolean verified;
	private SignatureCryptographicVerification verifyResult;

	private Map<PdfSignatureOrDocTimestampInfo, Boolean> outerSignatures = new ConcurrentHashMap<PdfSignatureOrDocTimestampInfo, Boolean>();

	/**
	 * @param validationCertPool
	 * @param outerCatalog       the PDF Dict of the outer document, if the PDFDocument in a enclosed revision. Can be null.
	 * @param document           the signed PDFDocument
	 * @param cms                the CMS bytes (CAdES signature)
	 * @param inputStream        the stream of the whole signed document
	 * @throws IOException
	 */
	PdfBoxCMSInfo(CertificatePool validationCertPool, PdfDict outerCatalog, PDDocument document, PDSignature signature, byte[] cms,
	              InputStream inputStream) throws DSSException, IOException {
		this.validationCertPool = validationCertPool;
		this.outerCatalog = PdfDssDict.build(outerCatalog);
		this.cms = cms;
		this.location = signature.getLocation();
		this.signingDate = signature.getSignDate() != null ? signature.getSignDate().getTime() : null;
		this.signatureByteRange = signature.getByteRange();
		final COSDictionary cosDictionary = document.getDocumentCatalog().getCOSDictionary();
		final PdfBoxDict documentDict = new PdfBoxDict(cosDictionary, document);
		documentDictionary = PdfDssDict.build(documentDict);
		try {
			if (cms == null) {
				// due to not very good revision extracting
				throw new DSSPadesNoSignatureFound();
			}
			signedBytes = signature.getSignedContent(inputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureCryptographicVerification checkIntegrity() {

		if (!verified) {

			verifyResult = checkIntegrityOnce();
			LOG.debug("Verify embedded CAdES Signature on signedBytes size {}. Signature intact: {}", signedBytes.length, verifyResult);
			verified = true;
		}
		return verifyResult;
	}

	protected abstract SignatureCryptographicVerification checkIntegrityOnce();

	@Override
	public String getLocation() {
		return location;
	}

	@Override
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * @return the byte of the originally signed document
	 */
	public byte[] getSignedDocumentBytes() {
		return signedBytes;
	}

	@Override
	public byte[] getOriginalBytes() {
		final int length = signatureByteRange[1];
		final byte[] result = new byte[length];
		System.arraycopy(signedBytes, 0, result, 0, length);
		return result;
	}

	@Override
	public PdfDssDict getDocumentDictionary() {
		return documentDictionary;
	}

	@Override
	public PdfDssDict getOuterCatalog() {
		return outerCatalog;
	}

	protected X509Certificate[] toX509CertificateArray(List<CertificateToken> certificateTokens) {
		X509Certificate[] result = new X509Certificate[certificateTokens.size()];
		for (int i = 0; i < certificateTokens.size(); i++) {
			CertificateToken certificateToken = certificateTokens.get(i);
			result[i] = certificateToken.getCertificate();
		}
		return result;
	}

	@Override
	public int uniqueId() {
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, cms);
		return bytesToInt(digest);
	}

	private int bytesToInt(byte[] bytes) {
		ByteBuffer buffer = ByteBuffer.allocate(8);
		buffer.put(bytes, 0, Integer.SIZE / 8);
		buffer.flip();//need flip
		return buffer.getInt();
	}

	@Override
	public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {

		signatureInfo = PdfBoxSignatureService.signatureAlreadyInListOrSelf(outerSignatures, signatureInfo);
		outerSignatures.put(signatureInfo, false);
	}

	@Override
	public Map<PdfSignatureOrDocTimestampInfo,Boolean> getOuterSignatures() {
		return Collections.unmodifiableMap(outerSignatures);
	}

	@Override
	public int[] getSignatureByteRange() {
		return signatureByteRange;
	}
}
