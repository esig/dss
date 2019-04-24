package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;

public abstract class AbstractCryptographicCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private final CryptographicConstraintWrapper constraintWrapper;
	protected final Date validationDate;

	protected String failedAlgorithm = null;
	protected MessageTag errorMessage = MessageTag.EMPTY;

	protected AbstractCryptographicCheck(T result, Date currentTime, CryptographicConstraint constraint) {
		super(result, constraint);
		this.validationDate = currentTime;
		this.constraintWrapper = new CryptographicConstraintWrapper(constraint);
	}

	protected boolean encryptionAlgorithmIsReliable(String encryptionAlgoUsedToSignThisToken) {
		List<String> supportedEncryptionAlgorithms = constraintWrapper.getSupportedEncryptionAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedEncryptionAlgorithms)) {
			if (!isIn(encryptionAlgoUsedToSignThisToken, supportedEncryptionAlgorithms)) {
				errorMessage = MessageTag.ASCCM_ANS_1;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean digestAlgorithmIsReliable(String digestAlgoUsedToSignThisToken) {
		List<String> supportedDigestAlgorithms = constraintWrapper.getSupportedDigestAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedDigestAlgorithms)) {
			if (!isIn(digestAlgoUsedToSignThisToken, supportedDigestAlgorithms)) {
				errorMessage = MessageTag.ASCCM_ANS_2;
				failedAlgorithm = digestAlgoUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean publicKeySizeIsAcceptable(String encryptionAlgoUsedToSignThisToken, String keyLengthUsedToSignThisToken) {
		Map<String, Integer> minimumKeySizes = constraintWrapper.getMinimumKeySizes();
		if (Utils.isMapNotEmpty(minimumKeySizes)) {
			String keySize = keyLengthUsedToSignThisToken;
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}

			Integer expectedMinimumKeySize = minimumKeySizes.get(encryptionAlgoUsedToSignThisToken);
			if (tokenKeySize < expectedMinimumKeySize) {
				errorMessage = MessageTag.ASCCM_ANS_3;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean digestAlgorithmIsValidOnValidationDate(String digestAlgoUsedToSignThisToken) {
		Map<String, Date> expirationDates = constraintWrapper.getExpirationTimes();
		if (Utils.isMapNotEmpty(expirationDates)) {
			Date expirationDate = expirationDates.get(digestAlgoUsedToSignThisToken);
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				failedAlgorithm = digestAlgoUsedToSignThisToken;
				return false;
			}
			if (expirationDate.before(validationDate)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
				failedAlgorithm = digestAlgoUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean encryptionAlgorithmIsValidOnValidationDate(String encryptionAlgoUsedToSignThisToken, String keyLengthUsedToSignThisToken) {
		Map<String, Date> expirationDates = constraintWrapper.getExpirationTimes();
		if (Utils.isMapNotEmpty(expirationDates)) {
			String algoToFind = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
			Date expirationDate = expirationDates.get(algoToFind);
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
				return false;
			}
			if (expirationDate.before(validationDate)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	private boolean isIn(String algoToFind, List<String> algos) {
		return algos.contains(algoToFind);
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.ASCCM;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return errorMessage;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
	}

	@Override
	protected String getAdditionalInfo() {
		SimpleDateFormat sdf = new SimpleDateFormat(AdditionalInfo.DATE_FORMAT);
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String addInfo = null;
		Object[] params = null;
		String dateTime = sdf.format(validationDate);
		if (Utils.isStringNotEmpty(failedAlgorithm)) {
			addInfo = AdditionalInfo.CRYPTOGRAPHIC_CHECK_FAILURE;
			params = new Object[] { failedAlgorithm, dateTime };
		} else {
			addInfo = AdditionalInfo.VALIDATION_TIME;
			params = new Object[] { dateTime };
		}
		return MessageFormat.format(addInfo, params);
	}

}
