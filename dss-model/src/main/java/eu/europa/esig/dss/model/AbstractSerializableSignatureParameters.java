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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * Parameters for a Signature creation/extension
 *
 * @param <TP> implementation of {@code SerializableTimestampParameters}
 */
@SuppressWarnings("serial")
public abstract class AbstractSerializableSignatureParameters<TP extends SerializableTimestampParameters> implements SerializableSignatureParameters {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractSerializableSignatureParameters.class);

	/**
	 * This variable indicates if it is possible to sign with an expired certificate.
	 *
	 * Default : false
	 * @deprecated since DSS 6.1. Please use {@code CertificateVerifier#alertOnExpiredCertificate} instead.
	 */
	@Deprecated
	private boolean signWithExpiredCertificate = false;

	/**
	 * This variable indicates if it is possible to sign with a not yet valid certificate.
	 *
	 * Default : false
	 * @deprecated since DSS 6.1. Please use {@code CertificateVerifier#alertOnNotYetValidCertificate} instead.
	 */
	@Deprecated
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
	private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1;

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
	 * <p>
	 * NOTE: in order to specify a behavior for this check, the relevant alerts should be specified within
	 * a {@code CertificateVerifier} instance, used in a service for signing/extension
	 * <p>
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
	 * NOTE: when using this method, it is important to ensure the same {@code EncryptionAlgorithm} is provided within
	 *       {@code #setEncryptionAlgorithm} as the one used on a signature value creation
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
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
		}
	}

	/**
	 * Sets the mask generation function if used with the given SignatureAlgorithm
	 *
	 * @param maskGenerationFunction {@link MaskGenerationFunction}
	 * @deprecated since DSS 6.1. Please use {@code #setEncryptionAlgorithm} method with
	 *             value EncryptionAlgorithm.RSASSA_PSS in order to set MGF1, or
	 *             value EncryptionAlgorithm.RSA to reset mask generation function
	 */
	@Deprecated
	public void setMaskGenerationFunction(MaskGenerationFunction maskGenerationFunction) {
		LOG.warn("Use of deprecated method #setMaskGenerationFunction! " +
				"Please use #setEncryptionAlgorithm with EncryptionAlgorithm.RSASSA_PSS value to enable MGF1, " +
				"or EncryptionAlgorithm.RSA to disable.");
		if (MaskGenerationFunction.MGF1 == maskGenerationFunction && EncryptionAlgorithm.RSA == encryptionAlgorithm) {
			LOG.info("MaskGenerationFunction '{}' has been provided. The EncryptionAlgorithm changed to '{}'.",
					maskGenerationFunction, EncryptionAlgorithm.RSASSA_PSS);
			setEncryptionAlgorithm(EncryptionAlgorithm.RSASSA_PSS);
		} else if (maskGenerationFunction == null && EncryptionAlgorithm.RSASSA_PSS == encryptionAlgorithm) {
			LOG.info("MaskGenerationFunction '{}' has been provided. The EncryptionAlgorithm changed to '{}'.",
					maskGenerationFunction, EncryptionAlgorithm.RSA);
			setEncryptionAlgorithm(EncryptionAlgorithm.RSA);
		} else if (!EncryptionAlgorithm.RSA.isEquivalent(encryptionAlgorithm)) {
			LOG.info("Not allowed combination of MaskGenerationFunction '{}' and EncryptionAlgorithm '{}'. The value is skipped.",
					maskGenerationFunction, encryptionAlgorithm);
		}
	}

	@Override
	@Deprecated
	public MaskGenerationFunction getMaskGenerationFunction() {
		if (EncryptionAlgorithm.RSASSA_PSS == encryptionAlgorithm) {
			return MaskGenerationFunction.MGF1;
		}
		return null;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	/**
	 * This method sets encryption algorithm to be used on signature creation.
	 * The method is useful when a specific encryption algorithm is expected.
	 * The defined encryption algorithm shall be the one used to create the SignatureValue.
	 * Note: The encryption algorithm is automatically extracted from the certificate's key
	 * with {@code #setSigningCertificate} method.
	 *
	 * @param encryptionAlgorithm
	 *            the encryption algorithm to use
	 */
	public void setEncryptionAlgorithm(final EncryptionAlgorithm encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
		if (this.digestAlgorithm != null) {
			signatureAlgorithm = SignatureAlgorithm.getAlgorithm(this.encryptionAlgorithm, this.digestAlgorithm);
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
		return "AbstractSerializableSignatureParameters [" +
				"signWithExpiredCertificate=" + signWithExpiredCertificate +
				", signWithNotYetValidCertificate=" + signWithNotYetValidCertificate +
				", checkCertificateRevocation=" + checkCertificateRevocation +
				", generateTBSWithoutCertificate=" + generateTBSWithoutCertificate +
				", signatureLevel=" + signatureLevel +
				", signaturePackaging=" + signaturePackaging +
				", signatureAlgorithm=" + signatureAlgorithm +
				", encryptionAlgorithm=" + encryptionAlgorithm +
				", digestAlgorithm=" + digestAlgorithm +
				", referenceDigestAlgorithm=" + referenceDigestAlgorithm +
				", bLevelParams=" + bLevelParams +
				", contentTimestampParameters=" + contentTimestampParameters +
				", signatureTimestampParameters=" + signatureTimestampParameters +
				", archiveTimestampParameters=" + archiveTimestampParameters +
				']';
	}

	@Override
	public int hashCode() {
		int result = Boolean.hashCode(signWithExpiredCertificate);
		result = 31 * result + Boolean.hashCode(signWithNotYetValidCertificate);
		result = 31 * result + Boolean.hashCode(checkCertificateRevocation);
		result = 31 * result + Boolean.hashCode(generateTBSWithoutCertificate);
		result = 31 * result + Objects.hashCode(signatureLevel);
		result = 31 * result + Objects.hashCode(signaturePackaging);
		result = 31 * result + Objects.hashCode(signatureAlgorithm);
		result = 31 * result + Objects.hashCode(encryptionAlgorithm);
		result = 31 * result + Objects.hashCode(digestAlgorithm);
		result = 31 * result + Objects.hashCode(referenceDigestAlgorithm);
		result = 31 * result + Objects.hashCode(bLevelParams);
		result = 31 * result + Objects.hashCode(contentTimestampParameters);
		result = 31 * result + Objects.hashCode(signatureTimestampParameters);
		result = 31 * result + Objects.hashCode(archiveTimestampParameters);
		return result;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		AbstractSerializableSignatureParameters<?> that = (AbstractSerializableSignatureParameters<?>) o;
		return signWithExpiredCertificate == that.signWithExpiredCertificate
				&& signWithNotYetValidCertificate == that.signWithNotYetValidCertificate
				&& checkCertificateRevocation == that.checkCertificateRevocation
				&& generateTBSWithoutCertificate == that.generateTBSWithoutCertificate
				&& signatureLevel == that.signatureLevel
				&& signaturePackaging == that.signaturePackaging
				&& signatureAlgorithm == that.signatureAlgorithm
				&& encryptionAlgorithm == that.encryptionAlgorithm
				&& digestAlgorithm == that.digestAlgorithm
				&& referenceDigestAlgorithm == that.referenceDigestAlgorithm
				&& Objects.equals(bLevelParams, that.bLevelParams)
				&& Objects.equals(contentTimestampParameters, that.contentTimestampParameters)
				&& Objects.equals(signatureTimestampParameters, that.signatureTimestampParameters)
				&& Objects.equals(archiveTimestampParameters, that.archiveTimestampParameters);
	}

}
