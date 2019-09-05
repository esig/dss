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
package eu.europa.esig.dss.ws.signature.dto.parameters;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

@SuppressWarnings("serial")
public class RemoteSignatureParameters implements Serializable {

	private RemoteCertificate signingCertificate;
	private List<RemoteCertificate> certificateChain = new ArrayList<RemoteCertificate>();

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
	 * XAdES: The ds:SignatureMethod indicates the algorithms used to sign ds:SignedInfo.
	 */
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	/**
	 * XAdES: The digest algorithm used to hash ds:SignedInfo.
	 */
	private DigestAlgorithm digestAlgorithm = signatureAlgorithm.getDigestAlgorithm();

	/**
	 * The encryption algorithm shall be automatically extracted from the signing token.
	 */
	private EncryptionAlgorithm encryptionAlgorithm = signatureAlgorithm.getEncryptionAlgorithm();

	/**
	 * XAdES: The digest algorithm used to hash ds:Reference.
	 */
	private DigestAlgorithm referenceDigestAlgorithm;

	/**
	 * The mask generation function
	 */
	private MaskGenerationFunction maskGenerationFunction = signatureAlgorithm.getMaskGenerationFunction();

	/**
	 * The object representing the parameters related to the content timestamp (Baseline-B)
	 */
	private RemoteTimestampParameters contentTimestampParameters;

	/**
	 * The object representing the parameters related to the signature timestamp (Baseline-T)
	 */
	private RemoteTimestampParameters signatureTimestampParameters;

	/**
	 * The object representing the parameters related to the archive timestamp (Baseline-LTA)
	 */
	private RemoteTimestampParameters archiveTimestampParameters;

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;

	/**
	 * This variable indicates if it is possible to generate ToBeSigned data without
	 * the signing certificate.
	 */
	private boolean generateTBSWithoutCertificate = false;

	public RemoteSignatureParameters() {
	}

	public RemoteCertificate getSigningCertificate() {
		return signingCertificate;
	}

	public void setSigningCertificate(RemoteCertificate signingCertificate) {
		this.signingCertificate = signingCertificate;
	}

	public List<RemoteCertificate> getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(List<RemoteCertificate> certificateChain) {
		this.certificateChain = certificateChain;
	}

	public List<RemoteDocument> getDetachedContents() {
		return detachedContents;
	}

	public void setDetachedContents(List<RemoteDocument> detachedContents) {
		this.detachedContents = detachedContents;
	}

	public ASiCContainerType getAsicContainerType() {
		return asicContainerType;
	}

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
		if (signatureLevel == null) {
			throw new NullPointerException("signatureLevel");
		}
		this.signatureLevel = signatureLevel;
	}

	/**
	 * Get the digest algorithm for ds:Reference or message-digest attribute
	 * 
	 * @return the digest algorithm for ds:Reference or message-digest attribute
	 */
	public DigestAlgorithm getReferenceDigestAlgorithm() {
		return referenceDigestAlgorithm;
	}

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
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
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
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
	}

	public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
		this.maskGenerationFunction = maskGenerationFunction;
		if ((this.digestAlgorithm != null) && (this.encryptionAlgorithm != null)) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
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
	 * Gets the signature algorithm.
	 *
	 * @return the signature algorithm
	 */
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
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
	 * Indicates if it is possible to sign with an expired certificate. The default value is false.
	 *
	 * @return true if signature with an expired certificate is allowed
	 */
	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * Allows to change the default behavior regarding the use of an expired certificate.
	 *
	 * @param signWithExpiredCertificate
	 *            true if signature with an expired certificate is allowed
	 */
	public void setSignWithExpiredCertificate(final boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
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

	@Override
	public String toString() {
		return "RemoteSignatureParameters [signWithExpiredCertificate=" + signWithExpiredCertificate + ", signatureLevel=" + signatureLevel + ", generateTBSWithoutCertificate="
				+ generateTBSWithoutCertificate + ", signaturePackaging=" + signaturePackaging + ", signatureAlgorithm=" + signatureAlgorithm + ", encryptionAlgorithm=" 
				+ encryptionAlgorithm + ", digestAlgorithm=" + digestAlgorithm + ", referenceDigestAlgorithm=" + referenceDigestAlgorithm + ", maskGenerationFunction=" 
				+ maskGenerationFunction + ", bLevelParams=" + bLevelParams + ", contentTimestampParameters=" + contentTimestampParameters + ", signatureTimestampParameters=" 
				+ signatureTimestampParameters + ", archiveTimestampParameters=" + archiveTimestampParameters + "]";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((archiveTimestampParameters == null) ? 0 : archiveTimestampParameters.hashCode());
		result = prime * result + ((bLevelParams == null) ? 0 : bLevelParams.hashCode());
		result = prime * result + ((contentTimestampParameters == null) ? 0 : contentTimestampParameters.hashCode());
		result = prime * result + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = prime * result + ((encryptionAlgorithm == null) ? 0 : encryptionAlgorithm.hashCode());
		result = prime * result + (generateTBSWithoutCertificate ? 1231 : 1237);
		result = prime * result + ((maskGenerationFunction == null) ? 0 : maskGenerationFunction.hashCode());
		result = prime * result + ((referenceDigestAlgorithm == null) ? 0 : referenceDigestAlgorithm.hashCode());
		result = prime * result + (signWithExpiredCertificate ? 1231 : 1237);
		result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
		result = prime * result + ((signatureLevel == null) ? 0 : signatureLevel.hashCode());
		result = prime * result + ((signaturePackaging == null) ? 0 : signaturePackaging.hashCode());
		result = prime * result + ((signatureTimestampParameters == null) ? 0 : signatureTimestampParameters.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RemoteSignatureParameters other = (RemoteSignatureParameters) obj;
		if (archiveTimestampParameters == null) {
			if (other.archiveTimestampParameters != null) {
				return false;
			}
		} else if (!archiveTimestampParameters.equals(other.archiveTimestampParameters)) {
			return false;
		}
		if (bLevelParams == null) {
			if (other.bLevelParams != null) {
				return false;
			}
		} else if (!bLevelParams.equals(other.bLevelParams)) {
			return false;
		}
		if (contentTimestampParameters == null) {
			if (other.contentTimestampParameters != null) {
				return false;
			}
		} else if (!contentTimestampParameters.equals(other.contentTimestampParameters)) {
			return false;
		}
		if (digestAlgorithm != other.digestAlgorithm) {
			return false;
		}
		if (encryptionAlgorithm != other.encryptionAlgorithm) {
			return false;
		}
		if (generateTBSWithoutCertificate != other.generateTBSWithoutCertificate) {
			return false;
		}
		if (maskGenerationFunction != other.maskGenerationFunction) {
			return false;
		}
		if (referenceDigestAlgorithm != other.referenceDigestAlgorithm) {
			return false;
		}
		if (signWithExpiredCertificate != other.signWithExpiredCertificate) {
			return false;
		}
		if (signatureAlgorithm != other.signatureAlgorithm) {
			return false;
		}
		if (signatureLevel != other.signatureLevel) {
			return false;
		}
		if (signaturePackaging != other.signaturePackaging) {
			return false;
		}
		if (signatureTimestampParameters == null) {
			if (other.signatureTimestampParameters != null) {
				return false;
			}
		} else if (!signatureTimestampParameters.equals(other.signatureTimestampParameters)) {
			return false;
		}
		return true;
	}

}
