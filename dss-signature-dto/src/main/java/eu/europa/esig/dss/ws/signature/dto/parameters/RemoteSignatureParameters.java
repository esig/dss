/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.ws.signature.dto.parameters;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SigDMechanism;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.TimestampDTO;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The parameters for a signature creation
 *
 */
@SuppressWarnings("serial")
public class RemoteSignatureParameters implements Serializable {

	/**
	 * Signing certificate
	 */
	private RemoteCertificate signingCertificate;

	/**
	 * Signing certificate chain
	 */
	private List<RemoteCertificate> certificateChain = new ArrayList<>();

	/**
	 * The documents to be signed
	 */
	private List<RemoteDocument> detachedContents;

	/**
	 * ASiC Container type
	 */
	private ASiCContainerType asicContainerType;

	/**
	 * This variable indicates the expected signature level
	 */
	private SignatureLevel signatureLevel;

	/**
	 * The object representing the parameters related to B- level.
	 */
	private RemoteBLevelParameters bLevelParams = new RemoteBLevelParameters();

	/**
	 * This variable indicates the expected signature packaging
	 */
	private SignaturePackaging signaturePackaging;

	/**
	 * This variable defines whether enveloped content shall be embedded into a signature
	 * in its clear XML representation (only for XAdES)
	 */
	private boolean embedXML;

	/**
	 * This variable defines whether an XML Manifest is being signed (only for XAdES)
	 */
	private boolean manifestSignature;

	/**
	 * JAdES JWS Serialization Type
	 */
	private JWSSerializationType jwsSerializationType;

	/**
	 * JAdES SigDMechanism for a DETACHED packaging
	 */
	private SigDMechanism sigDMechanism;

	/**
	 * JAdES base64url encoded payload
	 */
	private boolean base64UrlEncodedPayload = true;

	/**
	 * JAdES base64url encoded etsiU components
	 */
	private boolean base64UrlEncodedEtsiUComponents = true;

	/**
	 * The digest algorithm used on signature creation.
	 */
	private DigestAlgorithm digestAlgorithm;

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm;

	/**
	 * XAdES: The digest algorithm used to hash ds:Reference.
	 */
	private DigestAlgorithm referenceDigestAlgorithm;
	
	/**
	 * This object represents the list of content timestamps to be added into the signature.
	 */
	private List<TimestampDTO> contentTimestamps;

	/**
	 * The object represents the parameters related to the content timestamp (Baseline-B)
	 */
	private RemoteTimestampParameters contentTimestampParameters;

	/**
	 * The object represents the parameters related to the signature timestamp (Baseline-T)
	 */
	private RemoteTimestampParameters signatureTimestampParameters;

	/**
	 * The object represents the parameters related to the archive timestamp (Baseline-LTA)
	 */
	private RemoteTimestampParameters archiveTimestampParameters;

	/**
	 * This variable indicates if it is possible to generate ToBeSigned data without
	 * the signing certificate.
	 */
	private boolean generateTBSWithoutCertificate = false;

	/**
	 * PAdES: The image information to be included.
	 */
	private RemoteSignatureImageParameters imageParameters;
	
	/**
	 * This variable defines an Id of a signature to be counter-signed
	 * Used only for {@code getDataToBeCounterSigned()} and {@code counterSignSignature()} methods
	 */
	private String signatureIdToCounterSign;

	/**
	 * Default constructor
	 */
	public RemoteSignatureParameters() {
		// empty
	}

	/**
	 * Gets the signing certificate
	 *
	 * @return {@link RemoteCertificate}
	 */
	public RemoteCertificate getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Sets the signing certificate
	 *
	 * @param signingCertificate {@link RemoteCertificate}
	 */
	public void setSigningCertificate(RemoteCertificate signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	/**
	 * Gets the certificate chain
	 *
	 * @return a list of {@link RemoteCertificate}s
	 */
	public List<RemoteCertificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Sets the certificate chain of the signing certificate
	 *
	 * @param certificateChain a list of {@link RemoteCertificate}s
	 */
	public void setCertificateChain(List<RemoteCertificate> certificateChain) {
		this.certificateChain = certificateChain;
	}

	/**
	 * Gets the detached contents
	 *
	 * @return a list of {@link RemoteDocument}s
	 */
	public List<RemoteDocument> getDetachedContents() {
		return detachedContents;
	}

	/**
	 * Sets a list of signed detached documents
	 *
	 * @param detachedContents a  ist of {@link RemoteDocument}s
	 */
	public void setDetachedContents(List<RemoteDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	/**
	 * Gets ASiC container type
	 *
	 * @return {@link ASiCContainerType}
	 */
	public ASiCContainerType getAsicContainerType() {
		return asicContainerType;
	}

	/**
	 * Sets ASiCContainerType for ASiC format creation
	 *
	 * @param asicContainerType {@link ASiCContainerType}
	 */
	public void setAsicContainerType(ASiCContainerType asicContainerType) {
		this.asicContainerType = asicContainerType;
	}

	/**
	 * Get signature level: XAdES_BASELINE_T, CAdES_BASELINE_LTA...
	 *
	 * @return the expected signature level
	 */
	public SignatureLevel getSignatureLevel() {
		return signatureLevel;
	}

	/**
	 * Set signature level. This field cannot be null.
	 *
	 * @param signatureLevel
	 *            the expected signature level
	 */
	public void setSignatureLevel(final SignatureLevel signatureLevel) {
		Objects.requireNonNull(signatureLevel, "signatureLevel must be defined!");
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Returns if original XML document shall be embedded into ENVELOPING signature in its clear XML representation
	 *
	 * @return TRUE if the original document shall be embedded in its XML representation, FALSE of base64 encoded
	 */
	public boolean isEmbedXML() {
		return embedXML;
	}

	/**
	 * Sets whether the original XML document shall be embedded in its XML representation
	 * NOTE: used only for XAdES
	 *
	 * @param embedXML whether the original object shall be embedded as XML
	 */
	public void setEmbedXML(boolean embedXML) {
		this.embedXML = embedXML;
	}

	/**
	 * Returns if a manifest signature should be created
	 *
	 * @return TRUE if a signature signs an XML Manifest, FALSE otherwise
	 */
	public boolean isManifestSignature() {
		return manifestSignature;
	}

	/**
	 * Sets whether a manifest signature shall be created
	 * NOTE: used only for XAdES
	 *
	 * @param manifestSignature whether a manifest signature shall be created
	 */
	public void setManifestSignature(boolean manifestSignature) {
		this.manifestSignature = manifestSignature;
	}

	/**
	 * Gets {@code JWSSerializationType}
	 * NOTE: used only for JAdES
	 * 
	 * @return {@link JWSSerializationType}
	 */
	public JWSSerializationType getJwsSerializationType() {
		return jwsSerializationType;
	}

	/**
	 * Sets {@code JWSSerializationType}
	 * 
	 * @param jwsSerializationType {@link JWSSerializationType} to use
	 */
	public void setJwsSerializationType(JWSSerializationType jwsSerializationType) {
		this.jwsSerializationType = jwsSerializationType;
	}

	/**
	 * Gets {@code SigDMechanism}
	 * NOTE: used only for JAdES with DETACHED packaging
	 * 
	 * @return {@link SigDMechanism}
	 */
	public SigDMechanism getSigDMechanism() {
		return sigDMechanism;
	}

	/**
	 * Sets {@code SigDMechanism}
	 * NOTE: used only for JAdES with DETACHED packaging
	 * 
	 * @param sigDMechanism {@link SigDMechanism} to use
	 */
	public void setSigDMechanism(SigDMechanism sigDMechanism) {
		this.sigDMechanism = sigDMechanism;
	}

	/**
	 * Gets whether a payload shall be base64url encoded
	 * NOTE: used only for JAdES
	 *
	 * @return whether a JAdES payload shall be base64url encoded
	 */
	public boolean isBase64UrlEncodedPayload() {
		return base64UrlEncodedPayload;
	}

	/**
	 * Sets whether a payload shall be base64url encoded
	 * NOTE: used only for JAdES
	 *
	 * @param base64UrlEncodedPayload  whether a JAdES payload shall be base64url encoded
	 */
	public void setBase64UrlEncodedPayload(boolean base64UrlEncodedPayload) {
		this.base64UrlEncodedPayload = base64UrlEncodedPayload;
	}

	/**
	 * Gets whether etsiU header components shall be base64url encoded
	 * NOTE: used only for JAdES
	 *
	 * @return whether JAdES etsiU header components shall be base64url encoded
	 */
	public boolean isBase64UrlEncodedEtsiUComponents() {
		return base64UrlEncodedEtsiUComponents;
	}

	/**
	 * Sets whether etsiU header components shall be base64url encoded
	 * NOTE: used only for JAdES
	 *
	 * @param base64UrlEncodedEtsiUComponents whether JAdES etsiU header components shall be base64url encoded
	 */
	public void setBase64UrlEncodedEtsiUComponents(boolean base64UrlEncodedEtsiUComponents) {
		this.base64UrlEncodedEtsiUComponents = base64UrlEncodedEtsiUComponents;
	}

	/**
	 * Get the digest algorithm for ds:Reference or message-digest attribute
	 * 
	 * @return the digest algorithm for ds:Reference or message-digest attribute
	 */
	public DigestAlgorithm getReferenceDigestAlgorithm() {
		return referenceDigestAlgorithm;
	}

	/**
	 * Sets the digest algorithm for ds:Reference or message-digest attribute
	 *
	 * @param referenceDigestAlgorithm {@link DigestAlgorithm}
	 */
	public void setReferenceDigestAlgorithm(DigestAlgorithm referenceDigestAlgorithm) {
		this.referenceDigestAlgorithm = referenceDigestAlgorithm;
	}

	/**
	 * Get Baseline B parameters (signed properties)
	 * 
	 * @return the Baseline B parameters
	 */
	public RemoteBLevelParameters getBLevelParams() {
		return bLevelParams;
	}

	/**
	 * Set the Baseline B parameters (signed properties)
	 * 
	 * @param bLevelParams
	 *            the baseline B properties
	 */
	public void setBLevelParams(RemoteBLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
	}

	/**
	 * Get Signature packaging
	 *
	 * @return the expected signature packaging
	 */
	public SignaturePackaging getSignaturePackaging() {
		return signaturePackaging;
	}

	/**
	 * Set Signature packaging
	 *
	 * @param signaturePackaging
	 *            the expected signature packaging
	 */
	public void setSignaturePackaging(final SignaturePackaging signaturePackaging) {
		this.signaturePackaging = signaturePackaging;
	}

	/**
	 * Get the digest algorithm
	 * 
	 * @return the digest algorithm
	 */
	public DigestAlgorithm getDigestAlgorithm() {
		return digestAlgorithm;
	}

	/**
	 * Set the digest algorithm
	 * 
	 * @param digestAlgorithm
	 *            the digest algorithm to set
	 */
	public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Get the encryption algorithm
	 *
	 * @return the encryption algorithm.
	 */
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * This setter should be used only when dealing with web services (or when signing in three steps). Usually the
	 * encryption algorithm is automatically extrapolated from the private key.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm to use
	 */
	public void setEncryptionAlgorithm(final EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}
	
	/**
	 * Gets a list of content timestamps
	 * @return list of {@link TimestampDTO}s
	 */
	public List<TimestampDTO> getContentTimestamps() {
		return contentTimestamps;
	}
	
	/**
	 * Sets a list of content timestamps to be added into the signature
	 * @param contentTimestamps 
	 * 			list of content {@link TimestampDTO}s to set
	 */
	public void setContentTimestamps(List<TimestampDTO> contentTimestamps) {
		this.contentTimestamps = contentTimestamps;
	}

	/**
	 * Get the parameters for content timestamp (Baseline-B)
	 * 
	 * @return the parameters to produce a content timestamp
	 */
	public RemoteTimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new RemoteTimestampParameters();
		}
		return contentTimestampParameters;
	}

	/**
	 * Set the parameters to produce the content timestamp (Baseline-B)
	 * 
	 * @param contentTimestampParameters
	 *            the parameters to produce the content timestamp
	 */
	public void setContentTimestampParameters(RemoteTimestampParameters contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	/**
	 * Get the parameters for signature timestamp (Baseline-T)
	 * 
	 * @return the parameters to produce a signature timestamp
	 */
	public RemoteTimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new RemoteTimestampParameters();
		}
		return signatureTimestampParameters;
	}

	/**
	 * Set the parameters to produce the signature timestamp (Baseline-T)
	 * 
	 * @param signatureTimestampParameters
	 *            the parameters to produce the signature timestamp
	 */
	public void setSignatureTimestampParameters(RemoteTimestampParameters signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	/**
	 * Get the parameters for achive timestamp (Baseline-LTA)
	 * 
	 * @return the parameters to produce an archive timestamp
	 */
	public RemoteTimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new RemoteTimestampParameters();
		}
		return archiveTimestampParameters;
	}

	/**
	 * Set the parameters to produce the archive timestamp (Baseline-LTA)
	 * 
	 * @param archiveTimestampParameters
	 *            the parameters to produce the archive timestamp
	 */
	public void setArchiveTimestampParameters(RemoteTimestampParameters archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	/**
	 * Indicates if it is possible to generate ToBeSigned data without the signing certificate.
	 * The default values is false.
	 *
	 * @return true if signing certificate is not required when generating ToBeSigned data.
	 */
	public boolean isGenerateTBSWithoutCertificate() {
		return generateTBSWithoutCertificate;
	}

	/**
	 * Allows to change the default behaviour regarding the requirements of signing certificate
	 * to generate ToBeSigned data.
	 *
	 * @param generateTBSWithoutCertificate
	 *            true if it should be possible to generate ToBeSigned data without certificate.
	 */
	public void setGenerateTBSWithoutCertificate(final boolean generateTBSWithoutCertificate) {
		this.generateTBSWithoutCertificate = generateTBSWithoutCertificate;
	}

	/**
	 * Get the image information to be included (PAdES).
	 *
	 * @return {@link RemoteSignatureImageParameters} the image information to be included.
	 */
	public RemoteSignatureImageParameters getImageParameters() {
		return imageParameters;
	}

	/**
	 * Set the image information to be included (PAdES).
	 *
	 * @param imageParameters {@link RemoteSignatureImageParameters} the image information to be included.
	 */
	public void setImageParameters(final RemoteSignatureImageParameters imageParameters) {
		this.imageParameters = imageParameters;
	}

	/**
	 * Returns a signature Id being counter signed
	 * 
	 * @return {@link String} signature Id to counter sign
	 */
	public String getSignatureIdToCounterSign() {
		return signatureIdToCounterSign;
	}

	/**
	 * Sets the signature Id to counter sign
	 * 
	 * @param signatureIdToCounterSign {@link String} signature id to counter sign
	 */
	public void setSignatureIdToCounterSign(String signatureIdToCounterSign) {
		this.signatureIdToCounterSign = signatureIdToCounterSign;
	}

	@Override
	public String toString() {
		return "RemoteSignatureParameters{" +
				"signingCertificate=" + signingCertificate +
				", certificateChain=" + certificateChain +
				", detachedContents=" + detachedContents +
				", asicContainerType=" + asicContainerType +
				", signatureLevel=" + signatureLevel +
				", bLevelParams=" + bLevelParams +
				", signaturePackaging=" + signaturePackaging +
				", embedXML=" + embedXML +
				", manifestSignature=" + manifestSignature +
				", jwsSerializationType=" + jwsSerializationType +
				", sigDMechanism=" + sigDMechanism +
				", base64UrlEncodedPayload=" + base64UrlEncodedPayload +
				", base64UrlEncodedEtsiUComponents=" + base64UrlEncodedEtsiUComponents +
				", digestAlgorithm=" + digestAlgorithm +
				", encryptionAlgorithm=" + encryptionAlgorithm +
				", referenceDigestAlgorithm=" + referenceDigestAlgorithm +
				", contentTimestamps=" + contentTimestamps +
				", contentTimestampParameters=" + contentTimestampParameters +
				", signatureTimestampParameters=" + signatureTimestampParameters +
				", archiveTimestampParameters=" + archiveTimestampParameters +
				", generateTBSWithoutCertificate=" + generateTBSWithoutCertificate +
				", imageParameters=" + imageParameters +
				", signatureIdToCounterSign='" + signatureIdToCounterSign + '\'' +
				'}';
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		RemoteSignatureParameters that = (RemoteSignatureParameters) o;
		return embedXML == that.embedXML && manifestSignature == that.manifestSignature
				&& base64UrlEncodedPayload == that.base64UrlEncodedPayload
				&& base64UrlEncodedEtsiUComponents == that.base64UrlEncodedEtsiUComponents
				&& generateTBSWithoutCertificate == that.generateTBSWithoutCertificate
				&& Objects.equals(signingCertificate, that.signingCertificate)
				&& Objects.equals(certificateChain, that.certificateChain)
				&& Objects.equals(detachedContents, that.detachedContents)
				&& asicContainerType == that.asicContainerType
				&& signatureLevel == that.signatureLevel
				&& Objects.equals(bLevelParams, that.bLevelParams)
				&& signaturePackaging == that.signaturePackaging
				&& jwsSerializationType == that.jwsSerializationType
				&& sigDMechanism == that.sigDMechanism
				&& digestAlgorithm == that.digestAlgorithm
				&& encryptionAlgorithm == that.encryptionAlgorithm
				&& referenceDigestAlgorithm == that.referenceDigestAlgorithm
				&& Objects.equals(contentTimestamps, that.contentTimestamps)
				&& Objects.equals(contentTimestampParameters, that.contentTimestampParameters)
				&& Objects.equals(signatureTimestampParameters, that.signatureTimestampParameters)
				&& Objects.equals(archiveTimestampParameters, that.archiveTimestampParameters)
				&& Objects.equals(imageParameters, that.imageParameters)
				&& Objects.equals(signatureIdToCounterSign, that.signatureIdToCounterSign);
	}

	@Override
	public int hashCode() {
		int result = Objects.hashCode(signingCertificate);
		result = 31 * result + Objects.hashCode(certificateChain);
		result = 31 * result + Objects.hashCode(detachedContents);
		result = 31 * result + Objects.hashCode(asicContainerType);
		result = 31 * result + Objects.hashCode(signatureLevel);
		result = 31 * result + Objects.hashCode(bLevelParams);
		result = 31 * result + Objects.hashCode(signaturePackaging);
		result = 31 * result + Boolean.hashCode(embedXML);
		result = 31 * result + Boolean.hashCode(manifestSignature);
		result = 31 * result + Objects.hashCode(jwsSerializationType);
		result = 31 * result + Objects.hashCode(sigDMechanism);
		result = 31 * result + Boolean.hashCode(base64UrlEncodedPayload);
		result = 31 * result + Boolean.hashCode(base64UrlEncodedEtsiUComponents);
		result = 31 * result + Objects.hashCode(digestAlgorithm);
		result = 31 * result + Objects.hashCode(encryptionAlgorithm);
		result = 31 * result + Objects.hashCode(referenceDigestAlgorithm);
		result = 31 * result + Objects.hashCode(contentTimestamps);
		result = 31 * result + Objects.hashCode(contentTimestampParameters);
		result = 31 * result + Objects.hashCode(signatureTimestampParameters);
		result = 31 * result + Objects.hashCode(archiveTimestampParameters);
		result = 31 * result + Boolean.hashCode(generateTBSWithoutCertificate);
		result = 31 * result + Objects.hashCode(imageParameters);
		result = 31 * result + Objects.hashCode(signatureIdToCounterSign);
		return result;
	}

}
