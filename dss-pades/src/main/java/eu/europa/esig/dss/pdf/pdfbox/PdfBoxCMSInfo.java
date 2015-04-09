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
package eu.europa.esig.dss.pdf.pdfbox;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.validation.SignatureCryptographicVerification;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

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

	// Replace ConcurrentHashSet
	private Set<PdfSignatureOrDocTimestampInfo> outerSignatures = Collections
			.newSetFromMap(new ConcurrentHashMap<PdfSignatureOrDocTimestampInfo, Boolean>());

	/**
	 * @param validationCertPool
	 * @param outerCatalog
	 *            the PDF Dict of the outer document, if the PDFDocument in a enclosed revision. Can be null.
	 * @param document
	 *            the signed PDFDocument
	 * @param cms
	 *            the CMS bytes (CAdES signature)
	 * @param inputStream
	 *            the stream of the whole signed document
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
	@Override
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
		buffer.flip();// need flip
		return buffer.getInt();
	}

	@Override
	public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {
		outerSignatures.add(signatureInfo);
	}

	@Override
	public Set<PdfSignatureOrDocTimestampInfo> getOuterSignatures() {
		return Collections.unmodifiableSet(outerSignatures);
	}

	@Override
	public int[] getSignatureByteRange() {
		return signatureByteRange;
	}
}
