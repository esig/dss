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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Date;

/**
 * Abstract class to perform cryptographic validation
 */
public abstract class AbstractCryptographicChecker extends Chain<XmlCC> {

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
	 * Gets if the expiration dates are available in the policy
	 *
	 * @return TRUE if expiration constrains are defines, FALSE otherwise
	 */
	protected boolean isExpirationDateAvailable() {
		return Utils.isMapNotEmpty(constraintWrapper.getExpirationTimes());
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

}
