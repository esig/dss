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
package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.Date;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public abstract class AbstractCryptographicCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private final CryptographicConstraintWrapper constraintWrapper;
	protected final Date validationDate;

	protected String failedAlgorithm = null;
	protected String failedKeySize = null;
	protected MessageTag errorMessage = MessageTag.EMPTY;

	protected AbstractCryptographicCheck(I18nProvider i18nProvider, T result, Date currentTime, CryptographicConstraint constraint) {
		super(i18nProvider, result, constraint);
		this.validationDate = currentTime;
		this.constraintWrapper = new CryptographicConstraintWrapper(constraint);
	}

	protected boolean isPublicKeySizeKnown(String keyLengthUsedToSignThisToken) {
		if (!Utils.isStringDigits(keyLengthUsedToSignThisToken)) {
			errorMessage = MessageTag.ASCCM_ANS_6;
			return false;
		}
		return true;
	}

	protected boolean publicKeySizeIsAcceptable(EncryptionAlgorithm encryptionAlgo, String keyLengthUsedToSignThisToken) {
		String algoToFind = encryptionAlgo == null ? Utils.EMPTY_STRING : encryptionAlgo.getName();
		Map<String, Integer> minimumKeySizes = constraintWrapper.getMinimumKeySizes();
		if (Utils.isMapNotEmpty(minimumKeySizes)) {
			String keySize = keyLengthUsedToSignThisToken;
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}

			Integer expectedMinimumKeySize = minimumKeySizes.get(algoToFind);
			if (tokenKeySize < expectedMinimumKeySize) {
				errorMessage = MessageTag.ASCCM_ANS_3;
				failedAlgorithm = algoToFind;
				failedKeySize = keyLengthUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean encryptionAlgorithmIsReliable(EncryptionAlgorithm encryptionAlgo) {
		String algoToFind = encryptionAlgo == null ? Utils.EMPTY_STRING : encryptionAlgo.getName();
		List<String> supportedEncryptionAlgorithms = constraintWrapper.getSupportedEncryptionAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedEncryptionAlgorithms)) {
			if (!isIn(algoToFind, supportedEncryptionAlgorithms)) {
				errorMessage = MessageTag.ASCCM_ANS_1;
				failedAlgorithm = algoToFind;
				return false;
			}
		}
		return true;
	}

	protected boolean digestAlgorithmIsReliable(DigestAlgorithm digestAlgo) {
		String algoToFind = digestAlgo == null ? Utils.EMPTY_STRING : digestAlgo.getName();
		List<String> supportedDigestAlgorithms = constraintWrapper.getSupportedDigestAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedDigestAlgorithms)) {
			if (!isIn(algoToFind, supportedDigestAlgorithms)) {
				errorMessage = MessageTag.ASCCM_ANS_2;
				failedAlgorithm = algoToFind;
				return false;
			}
		}
		return true;
	}

	protected boolean digestAlgorithmIsValidOnValidationDate(DigestAlgorithm digestAlgo) {
		String algoToFind = digestAlgo == null ? Utils.EMPTY_STRING : digestAlgo.getName();
		Date expirationDate = constraintWrapper.getDigestAlgorithmExpirationDate(algoToFind);
		if (expirationDate == null) {
			errorMessage = MessageTag.ASCCM_ANS_4;
			failedAlgorithm = algoToFind;
			return false;
		}
		if (expirationDate.before(validationDate)) {
			errorMessage = MessageTag.ASCCM_ANS_5;
			failedAlgorithm = algoToFind;
			return false;
		}
		return true;
	}

	protected boolean encryptionAlgorithmIsValidOnValidationDate(EncryptionAlgorithm encryptionAlgo, String keyLengthUsedToSignThisToken) {
		Integer keyLength = Integer.parseInt(keyLengthUsedToSignThisToken);
		Date expirationDate = constraintWrapper.getExpirationDate(encryptionAlgo.getName(), keyLength);
		if (expirationDate == null) {
			errorMessage = MessageTag.ASCCM_ANS_4;
			failedAlgorithm = encryptionAlgo.getName() + keyLengthUsedToSignThisToken;
			return false;
		}
		if (expirationDate.before(validationDate)) {
			errorMessage = MessageTag.ASCCM_ANS_7;
			failedAlgorithm = encryptionAlgo.getName();
			failedKeySize = keyLengthUsedToSignThisToken;
			return false;
		}
		return true;
	}

	private boolean isIn(String algoToFind, List<String> algos) {
		return algos.contains(algoToFind);
	}

	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ACCM, getPosition());
	}

	@Override
	protected XmlName buildErrorMessage() {
		MessageTag position = getPosition();
		if (position != null) {
			if (failedAlgorithm != null) {
				if (failedKeySize != null) {
					return buildXmlName(errorMessage, failedAlgorithm, failedKeySize, position);
				} else {
					return buildXmlName(errorMessage, failedAlgorithm, position);
				}
			} else {
				return buildXmlName(errorMessage, position);
			}
		}
		return buildXmlName(errorMessage);
	}

	protected abstract MessageTag getPosition();

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

	@Override
	protected String buildAdditionalInfo() {
		String dateTime = ValidationProcessUtils.getFormattedDate(validationDate);
		if (Utils.isStringNotEmpty(failedAlgorithm)) {
			return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE, failedAlgorithm, dateTime);
		} else {
			return i18nProvider.getMessage(MessageTag.VALIDATION_TIME, dateTime);
		}
	}

	protected boolean isExpirationDateAvailable(CryptographicConstraint constraint) {
		AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
		return (algoExpirationDate != null && Utils.isCollectionNotEmpty(algoExpirationDate.getAlgo()));
	}

}
