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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * Parameters for a Signature creation/extension
 */
@SuppressWarnings("serial")
public abstract class AbstractSignatureParameters extends AbstractSerializableSignatureParameters {

	private String deterministicId;

	/**
	 * The documents to be signed
	 */
	private List<DSSDocument> detachedContents;

	/**
	 * This field contains the signing certificate.
	 */
	private CertificateToken signingCertificate;

	/**
	 * This field contains the {@code List} of chain of certificates. It includes the signing certificate.
	 */
	private Set<CertificateToken> certificateChain = new HashSet<CertificateToken>();

	/*
	 * This parameter is here because that's a signed attribute. It must be computed before getDataToSign/signDocument
	 */
	private List<TimestampToken> contentTimestamps;

	/**
	 * Returns the list of the {@code TimestampToken} to be incorporated within the signature and representing the
	 * content-timestamp.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	public List<TimestampToken> getContentTimestamps() {
		return contentTimestamps;
	}

	public void setContentTimestamps(final List<TimestampToken> contentTimestamps) {
		this.contentTimestamps = contentTimestamps;
	}

	/**
	 * The ID of xades:SignedProperties is contained in the signed content of the xades Signature. We must create this
	 * ID in a deterministic way.
	 *
	 * @return
	 */
	public String getDeterministicId() {
		if (deterministicId != null) {
			return deterministicId;
		}
		final TokenIdentifier identifier = (signingCertificate == null ? null : signingCertificate.getDSSId());
		deterministicId = DSSUtils.getDeterministicId(bLevel().getSigningDate(), identifier);
		return deterministicId;
	}

	/**
	 * This method returns the documents to sign. In the case of the DETACHED signature this is the detached document.
	 *
	 * @return
	 */
	public List<DSSDocument> getDetachedContents() {
		return detachedContents;
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable
	 * {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the
	 * document to be signed.
	 * <p />
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param detachedContent
	 */
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
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
	 * Set the signing certificate. If this certificate is not a part of the certificate chain then it's added as the
	 * first one of the chain.
	 *
	 * @param signingCertificate
	 *            the value
	 */
	public void setSigningCertificate(final CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	/**
	 * Set the certificate chain
	 *
	 * @return the value
	 */
	public Set<CertificateToken> getCertificateChain() {
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
	 * @param certificateChain
	 *            the {@code List} of {@code ChainCertificate}s
	 */
	public void setCertificateChain(final Set<CertificateToken> certificateChain) {
		this.certificateChain = certificateChain;
	}

	/**
	 * This method sets the list of certificates which constitute the chain. If the certificate is already present in
	 * the array then it is ignored.
	 *
	 * @param certificateChainArray
	 *            the array containing all certificates composing the chain
	 */
	public void setCertificateChain(final CertificateToken... certificateChainArray) {
		for (final CertificateToken certificate : certificateChainArray) {
			if (certificate != null) {
				certificateChain.add(certificate);
			}
		}
	}

	/**
	 * This methods reinits the deterministicId to force to recompute it
	 */
	public void reinitDeterministicId() {
		deterministicId = null;
	}

}
