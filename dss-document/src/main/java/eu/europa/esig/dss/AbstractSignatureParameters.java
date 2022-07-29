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

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.AbstractSerializableSignatureParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Parameters for a Signature creation/extension
 */
@SuppressWarnings("serial")
public abstract class AbstractSignatureParameters<TP extends SerializableTimestampParameters> extends AbstractSerializableSignatureParameters<TP> {

	/**
	 * The internal signature processing variable
	 */
	protected ProfileParameters context;

	/**
	 * The documents to be signed
	 */
	private List<DSSDocument> detachedContents;

	/**
	 * This field contains the signing certificate.
	 */
	private CertificateToken signingCertificate;

	/**
	 * Optional parameter that contains the actual canonicalized data that was used when creating the
	 * signature value. This allows scenarios were ToBeSigned was externally updated before signature
	 * value was created (i.e. signature certificate was appended). If this parameter is specified it
	 * will be used in the signed document.
	 */
	private byte[] signedData;

	/**
	 * This field contains the {@code List} of chain of certificates. It includes the signing certificate.
	 */
	private List<CertificateToken> certificateChain = new LinkedList<>();

	/**
	 * This parameter is here because that's a signed attribute. It must be computed before getDataToSign/signDocument
	 */
	private List<TimestampToken> contentTimestamps;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected AbstractSignatureParameters() {
	}

	/**
	 * Returns the list of the {@code TimestampToken} to be incorporated within the signature and representing the
	 * content-timestamp.
	 *
	 * @return {@code List} of {@code TimestampToken}
	 */
	public List<TimestampToken> getContentTimestamps() {
		return contentTimestamps;
	}

	/**
	 * Sets a list of content timestamps to be included into the signature
	 *
	 * @param contentTimestamps a list of {@link TimestampToken}s
	 */
	public void setContentTimestamps(final List<TimestampToken> contentTimestamps) {
		this.contentTimestamps = contentTimestamps;
	}

	/**
	 * This method returns the documents to sign.
	 * In the case of the DETACHED signature this is the detached document.
	 *
	 * @return the list of detached documents
	 */
	public List<DSSDocument> getDetachedContents() {
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			return detachedContents;
		}
		if (context != null) {
			return context.getDetachedContents();
		}
		return Collections.emptyList();
	}

	/**
	 * When signing this method is internally invoked by the {@code AbstractSignatureService} and the related variable
	 * {@code detachedContent} is overwritten by the service
	 * parameter. In the case of the DETACHED signature this is the detached document. In the case of ASiC-S this is the
	 * document to be signed.
	 * <p>
	 * When extending this method must be invoked to indicate the {@code detachedContent}.
	 *
	 * @param detachedContents
	 *            the list of detached documents
	 */
	public void setDetachedContents(final List<DSSDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	/**
	 * Get the signing certificate
	 *
	 * @return the signing certificate
	 */
	@Override
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Set the signing certificate. The encryption algorithm is also set from the
	 * public key.
	 *
	 * @param signingCertificate the signing certificate
	 */
	public void setSigningCertificate(final CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
		setEncryptionAlgorithm(EncryptionAlgorithm.forKey(signingCertificate.getPublicKey()));
	}

	/**
	 * Get signed data
	 * 
	 * @return signed data binaries
	 */
	public byte[] getSignedData() {
		return signedData;
	}

	/**
	 * Set signed data
	 * 
	 * @param signedData data that was used when creating the signature value.
	 */
	public void setSignedData(final byte[] signedData) {
		this.signedData = signedData;
	}

	/**
	 * Set the certificate chain
	 *
	 * @return the certificate chain
	 */
	public List<CertificateToken> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Set the certificate chain
	 *
	 * @param certificateChain the {@code List} of {@code CertificateToken}s
	 */
	public void setCertificateChain(final List<CertificateToken> certificateChain) {
		this.certificateChain = certificateChain;
	}

	/**
	 * This method sets the list of certificates which constitute the chain. If the
	 * certificate is already present in the array then it is ignored.
	 *
	 * @param certificateChainArray the array containing all certificates composing
	 *                              the chain
	 */
	public void setCertificateChain(final CertificateToken... certificateChainArray) {
		for (final CertificateToken certificate : certificateChainArray) {
			if (certificate != null && !certificateChain.contains(certificate)) {
				certificateChain.add(certificate);
			}
		}
	}

	/**
	 * Gets the signature creation context (internal variable)
	 *
	 * @return {@link ProfileParameters}
	 */
	public ProfileParameters getContext() {
		if (context == null) {
			context = new ProfileParameters();
		}
		return context;
	}

	/**
	 * This methods re-inits signature parameters to clean temporary settings
	 */
	public void reinit() {
		context = null;
	}

}
