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
package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCryptographicAlgorithm;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Date;

/**
 * Abstract class to perform cryptographic validation
 */
public abstract class AbstractCryptographicChecker extends Chain<XmlCC> {

	/** The name string for a unidentified (unsupported) algorithm */
	private static final String ALGORITHM_UNIDENTIFIED = "UNIDENTIFIED";

	/** The urn for a not identified (unsupported) algorithm */
	private static final String ALGORITHM_UNIDENTIFIED_URN = "urn:etsi:019102:algorithm:unidentified";

	/** The Encryption algorithm */
	protected final EncryptionAlgorithm encryptionAlgorithm;

	/** The Digest algorithm */
	protected final DigestAlgorithm digestAlgorithm;

	/** Mask generation function when present */
	protected final MaskGenerationFunction maskGenerationFunction;

	/** Used Key length */
	protected final String keyLengthUsedToSignThisToken;

	/** The validation time */
	protected final Date validationDate;

	/** Cryptographic constraint */
	protected final CryptographicConstraintWrapper constraintWrapper;

	/** The validation constraint position */
	protected final MessageTag position;

	/** The verified cryptographic algorithm */
	private XmlCryptographicAlgorithm cryptographicAlgorithm;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param constraint {@link CryptographicConstraint}
	 */
	protected AbstractCryptographicChecker(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm,
										   Date validationDate, MessageTag position,
										   CryptographicConstraint constraint) {
		this(i18nProvider, null, digestAlgorithm, null, null,
				validationDate, position, constraint);
	}

	/**
	 * Complete constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param maskGenerationFunction {@link MaskGenerationFunction}
	 * @param keyLengthUsedToSignThisToken {@link String}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param constraint {@link CryptographicConstraint}
	 */
	protected AbstractCryptographicChecker(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgorithm,
										   DigestAlgorithm digestAlgorithm, MaskGenerationFunction maskGenerationFunction,
										   String keyLengthUsedToSignThisToken, Date validationDate,
										   MessageTag position, CryptographicConstraint constraint) {
		super(i18nProvider, new XmlCC());
		
		this.encryptionAlgorithm = encryptionAlgorithm;
		this.digestAlgorithm = digestAlgorithm;
		this.maskGenerationFunction = maskGenerationFunction;
		this.keyLengthUsedToSignThisToken = keyLengthUsedToSignThisToken;
		this.validationDate = validationDate;
		
		this.constraintWrapper = new CryptographicConstraintWrapper(constraint);
		this.position = position;
	}
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.CC;
	}

	/**
	 * Gets if the expiration date if defined for the given {@code digestAlgorithm}
	 *
	 * @param digestAlgorithm {@link DigestAlgorithm} to check expiration date for
	 * @return TRUE if expiration constrains are defines, FALSE otherwise
	 */
	protected boolean isExpirationDateAvailable(DigestAlgorithm digestAlgorithm) {
		return constraintWrapper.getExpirationDate(digestAlgorithm) != null;
	}

	/**
	 * Gets if the expiration date if defined for the given {@code encryptionAlgorithm} and {@code keyLength}
	 *
	 * @param encryptionAlgorithm {@link EncryptionAlgorithm} to check expiration date for
	 * @param keyLength {@link String} used to sign the token
	 * @return TRUE if expiration constrains are defines, FALSE otherwise
	 */
	protected boolean isExpirationDateAvailable(EncryptionAlgorithm encryptionAlgorithm, String keyLength) {
		return constraintWrapper.getExpirationDate(encryptionAlgorithm, keyLength) != null;
	}

	/**
	 * Checks if the {@code encryptionAlgorithm} is acceptable
	 *
	 * @return TRUE if the {@code encryptionAlgorithm} is acceptable, FALSE otherwise
	 */
	protected ChainItem<XmlCC> encryptionAlgorithmReliable() {
		return new EncryptionAlgorithmReliableCheck(i18nProvider, encryptionAlgorithm, result, position, constraintWrapper);
	}

	/**
	 * Checks if the {@code digestAlgorithm} is acceptable
	 *
	 * @return TRUE if the {@code digestAlgorithm} is acceptable, FALSE otherwise
	 */
	protected ChainItem<XmlCC> digestAlgorithmReliable() {
		return new DigestAlgorithmReliableCheck(i18nProvider, digestAlgorithm, result, position, constraintWrapper);
	}

	/**
	 * Checks if the {@code encryptionAlgorithm} is not expired in validation time
	 *
	 * @return TRUE if the {@code encryptionAlgorithm} is not expired in validation time, FALSE otherwise
	 */
	protected ChainItem<XmlCC> encryptionAlgorithmOnValidationTime() {
		return new EncryptionAlgorithmOnValidationTimeCheck(i18nProvider, encryptionAlgorithm, keyLengthUsedToSignThisToken, validationDate, result,
				position, constraintWrapper);
	}

	/**
	 * Checks if the {@code digestAlgorithm} is not expired in validation time
	 *
	 * @return TRUE if the {@code digestAlgorithm} is not expired in validation time, FALSE otherwise
	 */
	protected ChainItem<XmlCC> digestAlgorithmOnValidationTime() {
		return new DigestAlgorithmOnValidationTimeCheck(i18nProvider, digestAlgorithm, validationDate, result, position, constraintWrapper);
	}

	/**
	 * Checks if the {@code keyLengthUsedToSignThisToken} is known
	 *
	 * @return TRUE if the {@code keyLengthUsedToSignThisToken} is known, FALSE otherwise
	 */
	protected ChainItem<XmlCC> publicKeySizeKnown() {
		return new PublicKeySizeKnownCheck(i18nProvider, keyLengthUsedToSignThisToken, result, position, constraintWrapper);
	}

	/**
	 * Checks if the {@code keyLengthUsedToSignThisToken} is acceptable
	 *
	 * @return TRUE if the {@code keyLengthUsedToSignThisToken} is acceptable, FALSE otherwise
	 */
	protected ChainItem<XmlCC> publicKeySizeAcceptable() {
		return new PublicKeySizeAcceptableCheck(i18nProvider, encryptionAlgorithm, keyLengthUsedToSignThisToken, result, position, constraintWrapper);
	}

	@Override
	protected void addAdditionalInfo() {
		super.addAdditionalInfo();
		result.setVerifiedAlgorithm(getAlgorithm());
		result.setNotAfter(getNotAfter());
	}

	/**
	 * Builds and returns the validated algorithm
	 *
	 * @return {@link XmlCryptographicAlgorithm}
	 */
	private XmlCryptographicAlgorithm getAlgorithm() {
		if (cryptographicAlgorithm == null) {
			cryptographicAlgorithm = new XmlCryptographicAlgorithm();
			if (digestAlgorithm == null) {
				// if DigestAlgorithm is not found (unable to build either SignatureAlgorithm nor DigestAlgorithm)
				cryptographicAlgorithm.setName(ALGORITHM_UNIDENTIFIED);
				cryptographicAlgorithm.setUri(ALGORITHM_UNIDENTIFIED_URN);

			} else if (encryptionAlgorithm != null) {
				// if EncryptionAlgorithm and DigestAlgorithm are defined
				SignatureAlgorithm signatureAlgorithm = getSignatureAlgorithm(
						digestAlgorithm, encryptionAlgorithm, maskGenerationFunction);
				cryptographicAlgorithm.setName(signatureAlgorithm.getName());
				cryptographicAlgorithm.setUri(getSignatureAlgorithmUri(signatureAlgorithm));
				cryptographicAlgorithm.setKeyLength(keyLengthUsedToSignThisToken);

			} else {
				// if only DigestAlgorithm is defined
				cryptographicAlgorithm.setName(digestAlgorithm.getName());
				cryptographicAlgorithm.setUri(getDigestAlgorithmUri(digestAlgorithm));
			}
		}
		return cryptographicAlgorithm;
	}

	private SignatureAlgorithm getSignatureAlgorithm(DigestAlgorithm digestAlgorithm,
											EncryptionAlgorithm encryptionAlgorithm, MaskGenerationFunction maskGenerationFunction) {
		return SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm, maskGenerationFunction);
	}

	private String getSignatureAlgorithmUri(SignatureAlgorithm signatureAlgorithm) {
		if (signatureAlgorithm != null) {
			if (signatureAlgorithm.getUri() != null) {
				return signatureAlgorithm.getUri();
			}
			if (signatureAlgorithm.getOid() != null) {
				return signatureAlgorithm.getURIBasedOnOID();
			}
		}
		return ALGORITHM_UNIDENTIFIED_URN;
	}

	private String getDigestAlgorithmUri(DigestAlgorithm digestAlgorithm) {
		if (digestAlgorithm != null) {
			if (digestAlgorithm.getUri() != null) {
				return digestAlgorithm.getUri();
			}
			if (digestAlgorithm.getOid() != null) {
				return digestAlgorithm.getOid();
			}
		}
		return ALGORITHM_UNIDENTIFIED_URN;
	}

	private Date getNotAfter() {
		if (constraintWrapper.isDigestAlgorithmReliable(digestAlgorithm) &&
				constraintWrapper.isEncryptionAlgorithmReliable(encryptionAlgorithm) &&
				constraintWrapper.isEncryptionAlgorithmWithKeySizeReliable(encryptionAlgorithm, keyLengthUsedToSignThisToken)) {
			Date notAfter = constraintWrapper.getExpirationDate(digestAlgorithm);
			Date expirationEncryption = constraintWrapper.getExpirationDate(encryptionAlgorithm, keyLengthUsedToSignThisToken);
			if (notAfter == null || (expirationEncryption != null && expirationEncryption.before(notAfter))) {
				notAfter = expirationEncryption;
			}
			return notAfter;
		}
		return null;
	}

}
