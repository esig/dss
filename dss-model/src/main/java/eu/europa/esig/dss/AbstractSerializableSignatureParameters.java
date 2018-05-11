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

/**
 * Parameters for a Signature creation/extension
 */
@SuppressWarnings("serial")
public abstract class AbstractSerializableSignatureParameters implements Serializable {

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 */
	private boolean signWithExpiredCertificate = false;

	/**
	 * This variable indicates if it is possible to generate ToBeSigned data without
	 * the signing certificate.
	 */
	private boolean generateTBSWithoutCertificate = false;

	/**
	 * This variable indicates the expected signature level
	 */
	private SignatureLevel signatureLevel;

	/**
	 * This variable indicates the expected signature packaging
	 */
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
	 * The mask generation function
	 */
	private MaskGenerationFunction maskGenerationFunction = signatureAlgorithm.getMaskGenerationFunction();

	/**
	 * The object representing the parameters related to B- level.
	 */
	private BLevelParameters bLevelParams = new BLevelParameters();

	/**
	 * The object representing the parameters related to the content timestamp (Baseline-B)
	 */
	private TimestampParameters contentTimestampParameters;

	/**
	 * The object representing the parameters related to the signature timestamp (Baseline-T)
	 */
	private TimestampParameters signatureTimestampParameters;

	/**
	 * The object representing the parameters related to the archive timestamp (Baseline-LTA)
	 */
	private TimestampParameters archiveTimestampParameters;

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
	public boolean isGenerateTBSWithoutCertificate() { return generateTBSWithoutCertificate; }

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

	public MaskGenerationFunction getMaskGenerationFunction() {
		return maskGenerationFunction;
	}

	/**
	 * Get Baseline B parameters (signed properties)
	 * 
	 * @return the Baseline B parameters
	 */
	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	/**
	 * Get Baseline B parameters (signed properties)
	 * 
	 * @return the Baseline B parameters
	 */
	public BLevelParameters getBLevelParams() {
		return bLevelParams;
	}

	/**
	 * Set the Baseline B parameters (signed properties)
	 * 
	 * @param bLevelParams
	 *            the baseline B properties
	 */
	public void setBLevelParams(BLevelParameters bLevelParams) {
		this.bLevelParams = bLevelParams;
	}

	/**
	 * Get the parameters for content timestamp (Baseline-B)
	 * 
	 * @return the parameters to produce a content timestamp
	 */
	public TimestampParameters getContentTimestampParameters() {
		if (contentTimestampParameters == null) {
			contentTimestampParameters = new TimestampParameters();
		}
		return contentTimestampParameters;
	}

	/**
	 * Set the parameters to produce the content timestamp (Baseline-B)
	 * 
	 * @param contentTimestampParameters
	 *            the parameters to produce the content timestamp
	 */
	public void setContentTimestampParameters(TimestampParameters contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	/**
	 * Get the parameters for signature timestamp (Baseline-T)
	 * 
	 * @return the parameters to produce a signature timestamp
	 */
	public TimestampParameters getSignatureTimestampParameters() {
		if (signatureTimestampParameters == null) {
			signatureTimestampParameters = new TimestampParameters();
		}
		return signatureTimestampParameters;
	}

	/**
	 * Set the parameters to produce the signature timestamp (Baseline-T)
	 * 
	 * @param signatureTimestampParameters
	 *            the parameters to produce the signature timestamp
	 */
	public void setSignatureTimestampParameters(TimestampParameters signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	/**
	 * Get the parameters for achive timestamp (Baseline-LTA)
	 * 
	 * @return the parameters to produce an archive timestamp
	 */
	public TimestampParameters getArchiveTimestampParameters() {
		if (archiveTimestampParameters == null) {
			archiveTimestampParameters = new TimestampParameters();
		}
		return archiveTimestampParameters;
	}

	/**
	 * Set the parameters to produce the archive timestamp (Baseline-LTA)
	 * 
	 * @param archiveTimestampParameters
	 *            the parameters to produce the archive timestamp
	 */
	public void setArchiveTimestampParameters(TimestampParameters archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	@Override
	public String toString() {
		return "SignatureParameters{" + "signWithExpiredCertificate=" + signWithExpiredCertificate + ", generateTBSWithoutCertificate=" + generateTBSWithoutCertificate
				+ ", signatureLevel=" + signatureLevel + ", signaturePackaging=" + signaturePackaging + ", signatureAlgorithm=" + signatureAlgorithm
				+ ", encryptionAlgorithm=" + encryptionAlgorithm + ", digestAlgorithm=" + digestAlgorithm + ", bLevelParams=" + bLevelParams
				+ ", signatureTimestampParameters=" + ((signatureTimestampParameters == null) ? null : signatureTimestampParameters.toString())
				+ ", archiveTimestampParameters=" + ((archiveTimestampParameters == null) ? null : archiveTimestampParameters.toString()) + '}';
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = (prime * result) + ((archiveTimestampParameters == null) ? 0 : archiveTimestampParameters.hashCode());
		result = (prime * result) + ((bLevelParams == null) ? 0 : bLevelParams.hashCode());
		result = (prime * result) + ((contentTimestampParameters == null) ? 0 : contentTimestampParameters.hashCode());
		result = (prime * result) + ((digestAlgorithm == null) ? 0 : digestAlgorithm.hashCode());
		result = (prime * result) + ((encryptionAlgorithm == null) ? 0 : encryptionAlgorithm.hashCode());
		result = (prime * result) + (signWithExpiredCertificate ? 1231 : 1237);
		result = (prime * result) + (generateTBSWithoutCertificate ? 1231 : 1237);
		result = (prime * result) + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
		result = (prime * result) + ((signatureLevel == null) ? 0 : signatureLevel.hashCode());
		result = (prime * result) + ((signaturePackaging == null) ? 0 : signaturePackaging.hashCode());
		result = (prime * result) + ((signatureTimestampParameters == null) ? 0 : signatureTimestampParameters.hashCode());
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
		AbstractSerializableSignatureParameters other = (AbstractSerializableSignatureParameters) obj;
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
		if (signWithExpiredCertificate != other.signWithExpiredCertificate) {
			return false;
		}
		if (generateTBSWithoutCertificate != other.generateTBSWithoutCertificate) {
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
