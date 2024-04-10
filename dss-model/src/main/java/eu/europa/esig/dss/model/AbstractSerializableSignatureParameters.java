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
package eu.europa.esig.dss.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;

import java.util.Objects;

/**
 * Parameters for a Signature creation/extension
 *
 * @param <TP> implementation of {@code SerializableTimestampParameters}
 */
@SuppressWarnings("serial")
public abstract class AbstractSerializableSignatureParameters<TP extends SerializableTimestampParameters> implements SerializableSignatureParameters {

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 *
	 * Default : false
	 */
	private boolean signWithExpiredCertificate = false;

	/**
	 * This variable indicates if it is possible to sign with a not yet valid certificate.
	 *
	 * Default : false
	 */
	private boolean signWithNotYetValidCertificate = false;

	/**
	 * This variable indicates whether a signing certificate revocation shall be checked.
	 *
	 * Default : false
	 */
	private boolean checkCertificateRevocation = false;

	/**
	 * This variable indicates if it is possible to generate ToBeSigned data without
	 * the signing certificate.
	 *
	 * Default : false
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
	 * XAdES: The digest algorithm used to hash ds:Reference.
	 */
	private DigestAlgorithm referenceDigestAlgorithm;

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
	protected TP contentTimestampParameters;

	/**
	 * The object representing the parameters related to the signature timestamp (Baseline-T)
	 */
	protected TP signatureTimestampParameters;

	/**
	 * The object representing the parameters related to the archive timestamp (Baseline-LTA)
	 */
	protected TP archiveTimestampParameters;

	/**
	 * Default constructor instantiating object with default values
	 */
	protected AbstractSerializableSignatureParameters() {
		// empty
	}

	@Override
	@Deprecated
	public boolean isSignWithExpiredCertificate() {
		return signWithExpiredCertificate;
	}

	/**
	 * Allows to change the default behavior regarding the use of an expired certificate
	 * on signature creation or T-level extension.
	 *
	 * Default : false (forbid signing with an expired signing certificate)
	 *
	 * @param signWithExpiredCertificate
	 *            true if signature with an expired certificate is allowed
	 * @deprecated since DSS 6.1. Please use {@code CertificateVerifier.setSignatureAlertOnExpiredCertificate} method instead
	 */
	@Deprecated
	public void setSignWithExpiredCertificate(boolean signWithExpiredCertificate) {
		this.signWithExpiredCertificate = signWithExpiredCertificate;
	}

	@Override
	@Deprecated
	public boolean isSignWithNotYetValidCertificate() {
		return signWithNotYetValidCertificate;
	}

	/**
	 * Allows to change the default behavior regarding the use of a not yet valid certificate
	 * on signature creation or T-level extension.
	 *
	 * Default : false (forbid signing with a not yet valid signing certificate)
	 *
	 * @param signWithNotYetValidCertificate
	 *            true if signature with a not yet valid certificate is allowed
	 * @deprecated since DSS 6.1. Please use {@code CertificateVerifier.getSignatureAlertOnNotYetValidCertificate} method instead
	 */
	@Deprecated
	public void setSignWithNotYetValidCertificate(boolean signWithNotYetValidCertificate) {
		this.signWithNotYetValidCertificate = signWithNotYetValidCertificate;
	}

	@Override
	public boolean isCheckCertificateRevocation() {
		return checkCertificateRevocation;
	}

	/**
	 * Allows setting whether a revocation status for a signing certificate should be checked
	 * on signature creation or T-level extension.
	 *
	 * NOTE: in order to specify a behavior for this check, the relevant alerts should be specified within
	 * a {@code CertificateVerifier} instance, used in a service for signing/extension
	 *
	 * Default : false (do not perform revocation data check on signature creation/T-level extension)
	 *
	 * @param checkCertificateRevocation indicated if a certificate revocation check shall be performed
	 */
	public void setCheckCertificateRevocation(boolean checkCertificateRevocation) {
		this.checkCertificateRevocation = checkCertificateRevocation;
	}

	/**
	 * Indicates if it is possible to generate ToBeSigned data without the signing certificate.
	 * The default values is false.
	 *
	 * @return true if signing certificate is not required when generating ToBeSigned data.
	 */
	@Override
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
		Objects.requireNonNull(signatureLevel, "Signature Level cannot be null");
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

	@Override
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
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
		if (this.encryptionAlgorithm != null) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
	}

	/**
	 * Sets the mask generation function if used with the given SignatureAlgorithm
	 *
	 * @param maskGenerationFunction {@link MaskGenerationFunction}
	 */
	public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
		this.maskGenerationFunction = maskGenerationFunction;
		if (this.digestAlgorithm != null && this.encryptionAlgorithm != null) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
	}

	@Override
	public MaskGenerationFunction getMaskGenerationFunction() {
		return maskGenerationFunction;
	}

	@Override
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
		if (this.digestAlgorithm != null) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm, this.maskGenerationFunction);
		}
	}

	@Override
	public SignatureAlgorithm getSignatureAlgorithm() {
		return signatureAlgorithm;
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
	 * Sets the DigestAlgorithm to be used for reference digest calculation
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
	@Override
	public BLevelParameters bLevel() {
		return bLevelParams;
	}

	/**
	 * Set the Baseline B parameters (signed properties)
	 * 
	 * @param bLevelParams
	 *            the baseline B properties
	 */
	public void setBLevelParams(BLevelParameters bLevelParams) {
		Objects.requireNonNull(bLevelParams, "bLevelParams cannot be null!");
		this.bLevelParams = bLevelParams;
	}

	/**
	 * Get the parameters for content timestamp (Baseline-B)
	 * 
	 * @return the parameters to produce a content timestamp
	 */
	public TP getContentTimestampParameters() {
		throw new UnsupportedOperationException("Cannot extract ContentTimestampParameters! Not implemented by default.");
	}

	/**
	 * Set the parameters to produce the content timestamp (Baseline-B)
	 * 
	 * @param contentTimestampParameters
	 *            the parameters to produce the content timestamp
	 */
	public void setContentTimestampParameters(TP contentTimestampParameters) {
		this.contentTimestampParameters = contentTimestampParameters;
	}

	/**
	 * Get the parameters for signature timestamp (Baseline-T)
	 * 
	 * @return the parameters to produce a signature timestamp
	 */
	public TP getSignatureTimestampParameters() {
		throw new UnsupportedOperationException("Cannot extract SignatureTimestampParameters! Not implemented by default.");
	}

	/**
	 * Set the parameters to produce the signature timestamp (Baseline-T)
	 * 
	 * @param signatureTimestampParameters
	 *            the parameters to produce the signature timestamp
	 */
	public void setSignatureTimestampParameters(TP signatureTimestampParameters) {
		this.signatureTimestampParameters = signatureTimestampParameters;
	}

	/**
	 * Get the parameters for archive timestamp (Baseline-LTA)
	 * 
	 * @return the parameters to produce an archive timestamp
	 */
	public TP getArchiveTimestampParameters() {
		throw new UnsupportedOperationException("Cannot extract ArchiveTimestampParameters! Not implemented by default.");
	}

	/**
	 * Set the parameters to produce the archive timestamp (Baseline-LTA)
	 * 
	 * @param archiveTimestampParameters
	 *            the parameters to produce the archive timestamp
	 */
	public void setArchiveTimestampParameters(TP archiveTimestampParameters) {
		this.archiveTimestampParameters = archiveTimestampParameters;
	}

	@Override
	public String toString() {
		return "AbstractSerializableSignatureParameters [signWithExpiredCertificate=" + signWithExpiredCertificate + ", generateTBSWithoutCertificate="
				+ generateTBSWithoutCertificate + ", signatureLevel=" + signatureLevel + ", signaturePackaging=" + signaturePackaging + ", signatureAlgorithm="
				+ signatureAlgorithm + ", encryptionAlgorithm=" + encryptionAlgorithm + ", digestAlgorithm=" + digestAlgorithm + ", referenceDigestAlgorithm="
				+ referenceDigestAlgorithm + ", maskGenerationFunction=" + maskGenerationFunction + ", bLevelParams=" + bLevelParams
				+ ", contentTimestampParameters=" + contentTimestampParameters + ", signatureTimestampParameters=" + signatureTimestampParameters
				+ ", archiveTimestampParameters=" + archiveTimestampParameters + "]";
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

	@SuppressWarnings("unchecked")
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
		AbstractSerializableSignatureParameters<TP> other = (AbstractSerializableSignatureParameters<TP>) obj;
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
