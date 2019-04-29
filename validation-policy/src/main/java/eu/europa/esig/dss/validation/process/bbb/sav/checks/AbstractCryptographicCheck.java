package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;

public abstract class AbstractCryptographicCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {
	
	private static final Logger LOG = LoggerFactory.getLogger(AbstractCryptographicCheck.class);

	private static final String DATE_FORMAT = "yyyy-MM-dd";

	protected final CryptographicConstraint constraint;
	protected final Date validationDate;

	protected String failedAlgorithm = null;
	protected MessageTag errorMessage = MessageTag.EMPTY;

	protected AbstractCryptographicCheck(T result, Date currentTime, CryptographicConstraint constraint) {
		super(result, constraint);
		this.validationDate = currentTime;
		this.constraint = constraint;
	}
	
	protected boolean encryptionAlgorithmIsReliable(String encryptionAlgoUsedToSignThisToken) {
		ListAlgo acceptableEncryptionAlgo = constraint.getAcceptableEncryptionAlgo();
		if ((acceptableEncryptionAlgo != null) && Utils.isCollectionNotEmpty(acceptableEncryptionAlgo.getAlgo())) {
			if (!isIn(encryptionAlgoUsedToSignThisToken, acceptableEncryptionAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_1;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}
	
	protected boolean digestAlgorithmIsReliable(String digestAlgoUsedToSignThisToken) {
		ListAlgo acceptableDigestAlgo = constraint.getAcceptableDigestAlgo();
		if ((acceptableDigestAlgo != null) && Utils.isCollectionNotEmpty(acceptableDigestAlgo.getAlgo())) {
			if (!isIn(digestAlgoUsedToSignThisToken, acceptableDigestAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_2;
				failedAlgorithm = digestAlgoUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}
	
	protected boolean publicKeySizeIsAcceptable(String encryptionAlgoUsedToSignThisToken, String keyLengthUsedToSignThisToken) {
		ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
		if ((miniPublicKeySize != null) && Utils.isCollectionNotEmpty(miniPublicKeySize.getAlgo())) {
			String keySize = keyLengthUsedToSignThisToken;
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}
			int expectedMinimumKeySize = getExpectedKeySize(encryptionAlgoUsedToSignThisToken, miniPublicKeySize.getAlgo());
			if (tokenKeySize < expectedMinimumKeySize) {
				errorMessage = MessageTag.ASCCM_ANS_3;
				failedAlgorithm = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
				return false;
			}
		}
		return true;
	}
	
	protected boolean digestAlgorithmIsValidOnValidationDate(String digestAlgoUsedToSignThisToken) {
		AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
		if ((algoExpirationDate != null) && Utils.isCollectionNotEmpty(algoExpirationDate.getAlgo())) {
			Date expirationDate = getExpirationDate(digestAlgoUsedToSignThisToken, algoExpirationDate.getAlgo(), algoExpirationDate.getFormat());
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
		AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
		if ((algoExpirationDate != null) && Utils.isCollectionNotEmpty(algoExpirationDate.getAlgo())) {
			String algoToFind = encryptionAlgoUsedToSignThisToken + keyLengthUsedToSignThisToken;
			Date expirationDate = getExpirationDate(algoToFind, algoExpirationDate.getAlgo(), algoExpirationDate.getFormat());
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

	private Date getExpirationDate(String algoToFind, List<Algo> algos, String format) {
		SimpleDateFormat dateFormat = new SimpleDateFormat(Utils.isStringEmpty(format) ? DATE_FORMAT : format);
		Date result = null;
		for (Algo algo : algos) {
			if (Utils.areStringsEqual(algoToFind, algo.getValue()) && Utils.isStringNotEmpty(algo.getDate())) {
				try {
					result = dateFormat.parse(algo.getDate());
					break;
				} catch (Exception e) {
					LOG.warn("Unable to parse date with pattern '{}' : {}", dateFormat.toPattern(), e.getMessage());
				}
			}
		}
		return result;
	}

	private int getExpectedKeySize(String encryptionAlgo, List<Algo> algos) {
		int expectedSize = 0;
		for (Algo algo : algos) {
			if (Utils.areStringsEqual(algo.getValue(), encryptionAlgo)) {
				String size = algo.getSize();
				if (Utils.isStringDigits(size)) {
					expectedSize = Integer.parseInt(size);
				}
			}
		}
		return expectedSize;
	}

	private boolean isIn(String algoToFind, List<Algo> algos) {
		for (Algo algo : algos) {
			if (Utils.areStringsEqual(algo.getValue(), algoToFind)) {
				return true;
			}
		}
		return false;
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
