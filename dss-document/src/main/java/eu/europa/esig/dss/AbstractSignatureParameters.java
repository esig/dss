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
package eu.europa.esig.dss;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Parameters for a Signature creation/extension
 *
 */
public abstract class AbstractSignatureParameters implements Serializable {

	/**
	 * This field contains the signing certificate.
	 */
	private CertificateToken signingCertificate;

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;

	/**
	 * This field contains the {@code List} of chain of certificates. It includes the signing certificate.
	 */
	private List<ChainCertificate> certificateChain = new ArrayList<ChainCertificate>();

	private SignatureLevel signatureLevel;
	private SignaturePackaging signaturePackaging;

	/**
	 * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
	 */
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgorithm();

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();

	/**
	 * The object representing the parameters related to B- level.
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();

	private String deterministicId;

	private TimestampParameters signatureTimestampParameters;
	private TimestampParameters archiveTimestampParameters;
	private TimestampParameters contentTimestampParameters;

	private List<TimestampToken> contentTimestamps;

	/**
	 * The document to be signed
	 */
	private DSSDocument detachedContent;

	/**
	 * This method returns the document to sign. In the case of the DETACHED signature this is the detached document.
	 *
	 * @return
	 */
	public DSSDocument getDetachedContent() {
		return detachedContent;
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the document to be signed.<p />
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param detachedContent
	 */
	public void setDetachedContent(final DSSDocument detachedContent) {
		this.detachedContent = detachedContent;
	}

	/**
	 * Returns the list of the {@code TimestampToken} to be incorporated within the signature and representing the content-timestamp.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	public List<TimestampToken> getContentTimestamps() {
		return contentTimestamps;
	}

	public void setContentTimestamps(final List<TimestampToken> contentTimestamps) {
		this.contentTimestamps = contentTimestamps;
	}

	public void addContentTimestamp(final TimestampToken contentTimestamp) {
		if (contentTimestamps == null) {
			contentTimestamps = new ArrayList<TimestampToken>();
		}
		this.contentTimestamps.add(contentTimestamp);
	}

	/**
	 * The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this ID in a deterministic way.
	 *
	 * @return
	 */
	public String getDeterministicId() {
		if (deterministicId != null) {
			return deterministicId;
		}
		final String dssId = (signingCertificate == null ? "" : signingCertificate.getDSSId().asXmlId());
		deterministicId = DSSUtils.getDeterministicId(bLevelParams.getSigningDate(), dssId);
		return deterministicId;
	}

	/**
	 * Get the signing certificate
	 *
	 * @return the value
	 */
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Set the signing certificate. If this certificate is not a part of the certificate chain then it's added as the first one of the chain.
	 *
	 * @param signingCertificate the value
	 */
	public void setSigningCertificate(final CertificateToken signingCertificate) {

		this.signingCertificate = signingCertificate;
		final ChainCertificate chainCertificate = new ChainCertificate(signingCertificate, true);
		if (!this.certificateChain.contains(chainCertificate)) {

			this.certificateChain.add(0, chainCertificate);
		}
	}

	/**
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return
	 */
	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * Allows to change the default behaviour regarding the use of an expired certificate.
	 *
	 * @param signWithExpiredCertificate
	 */
	public void setSignWithExpiredCertificate(final boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	/**
	 * Set the certificate chain
	 *
	 * @return the value
	 */
	public List<ChainCertificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Clears the certificate chain
	 *
	 * @return the value
	 */
	public void clearCertificateChain() {
		certificateChain.clear();
	}

	/**
	 * Set the certificate chain
	 *
	 * @param certificateChain the {@code List} of {@code ChainCertificate}s
	 */
	public void setCertificateChain(final List<ChainCertificate> certificateChain) {

		if (certificateChain != null) {
			this.certificateChain = certificateChain;
		} else {
			this.certificateChain.clear();
		}
	}

	/**
	 * This method sets the list of certificates which constitute the chain. If the certificate is already present in the array then it is ignored.
	 *
	 * @param certificateChainArray the array containing all certificates composing the chain
	 */
	public void setCertificateChain(final CertificateToken... certificateChainArray) {

		if ((certificateChainArray == null) || (certificateChainArray.length == 0)) {
			certificateChain.clear();
		}
		for (final CertificateToken certificate : certificateChainArray) {

			if (certificate != null) {

				final ChainCertificate chainCertificate = new ChainCertificate(certificate, false);
				if (!certificateChain.contains(chainCertificate)) {
					certificateChain.add(chainCertificate);
				}
			}
		}
	}

	/**
	 * Get signature format: XAdES_BES, XAdES_EPES, XAdES_BASELINE_T ../.. CAdES_BES...
	 *
	 * @return the value
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * Set signature level. This field cannot be null.
	 *
	 * @param signatureLevel the value
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) throws NullPointerException {
		if (signatureLevel == null) {
			throw new NullPointerException();
		}
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Get Signature packaging
	 *
	 * @return the value
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * Set Signature packaging
	 *
	 * @param signaturePackaging the value
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}


	/**
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * @param digestAlgorithm the digest algorithm to set
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * This setter should be used only when dealing with web services (or when signing in three steps). Usually the encryption algorithm is automatically extrapolated from the
	 * private key.
	 *
	 * @param encryptionAlgorithm
	 */
	@Deprecated
	public void setEncryptionAlgorithm(final EncryptionAlgorithm encryptionAlgorithm) {

		this.encryptionAlgorithm = encryptionAlgorithm;
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {

			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * @return the encryption algorithm. It's determined by the privateKeyEntry and is null until the privateKeyEntry is set.
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * Gets the signature algorithm.
	 *
	 * @return the value
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	public void setBLevelParams(BLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
	}

	public TimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new TimestampParameters();
		}
		return signatureTimestampParameters;
	}

	public void setSignatureTimestampParameters(TimestampParameters signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	public TimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new TimestampParameters();
		}
		return archiveTimestampParameters;
	}

	public void setArchiveTimestampParameters(TimestampParameters archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	public TimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new TimestampParameters();
		}
		return contentTimestampParameters;
	}

	public void setContentTimestampParameters(TimestampParameters contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	/**
	 * This methods reinits the deterministicId to force to recompute it
	 */
	public void reinitDeterministicId() {
		deterministicId = null;
	}

	@Override
	public String toString() {
		return "SignatureParameters{" +
				"signingCertificate=" + signingCertificate +
				", signWithExpiredCertificate=" + signWithExpiredCertificate +
				", certificateChain_=" + certificateChain +
				", signatureLevel=" + signatureLevel +
				", signaturePackaging=" + signaturePackaging +
				", signatureAlgorithm=" + signatureAlgorithm +
				", encryptionAlgorithm=" + encryptionAlgorithm +
				", digestAlgorithm=" + digestAlgorithm +
				", bLevelParams=" + bLevelParams +
				", deterministicId='" + deterministicId + '\'' +
				", signatureTimestampParameters=" + ((signatureTimestampParameters == null) ? null : signatureTimestampParameters.toString())
				+ ", archiveTimestampParameters=" + ((archiveTimestampParameters == null) ? null : archiveTimestampParameters.toString()) +	", contentTimestamps=" + contentTimestamps +
				", detachedContent=" + detachedContent +
				'}';
	}
}
