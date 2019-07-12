package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
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

	protected boolean encryptionAlgorithmIsReliable(EncryptionAlgorithm encryptionAlgo) {
		String algoToFind = encryptionAlgo == null ? "" : encryptionAlgo.name();
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
		String algoToFind = digestAlgo == null ? "" : digestAlgo.getName();
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

	protected boolean publicKeySizeIsAcceptable(EncryptionAlgorithm encryptionAlgo, String keyLengthUsedToSignThisToken) {
		String algoToFind = encryptionAlgo == null ? "" : encryptionAlgo.name();
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
				failedAlgorithm = algoToFind + keyLengthUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}

	protected boolean digestAlgorithmIsValidOnValidationDate(DigestAlgorithm digestAlgo) {
		String algoToFind = digestAlgo == null ? "" : digestAlgo.getName();
		Map<String, Date> expirationDates = constraintWrapper.getExpirationTimes();
		if (Utils.isMapNotEmpty(expirationDates)) {
			Date expirationDate = expirationDates.get(algoToFind);
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
		}
		return true;
	}

	protected boolean encryptionAlgorithmIsValidOnValidationDate(EncryptionAlgorithm encryptionAlgo, String keyLengthUsedToSignThisToken) {
		String algoToFind = encryptionAlgo == null ? "" : encryptionAlgo.name() + keyLengthUsedToSignThisToken;
		Map<String, Date> expirationDates = constraintWrapper.getExpirationTimes();
		if (Utils.isMapNotEmpty(expirationDates)) {
			Date expirationDate = expirationDates.get(algoToFind);
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
