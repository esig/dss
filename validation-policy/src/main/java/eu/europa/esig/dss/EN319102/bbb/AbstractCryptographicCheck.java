package eu.europa.esig.dss.EN319102.bbb;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlAbstractBasicBuildingBlock;
import eu.europa.esig.dss.validation.TokenProxy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;

public abstract class AbstractCryptographicCheck<T extends XmlAbstractBasicBuildingBlock> extends ChainItem<T> {

	private static final Logger logger = LoggerFactory.getLogger(AbstractCryptographicCheck.class);

	private static final String DATE_FORMAT = "yyyy-MM-dd";

	private final Date currentTime;
	private final TokenProxy token;
	private final CryptographicConstraint constraint;
	private MessageTag errorMessage = MessageTag.EMPTY;

	public AbstractCryptographicCheck(T result, TokenProxy token, Date currentTime, CryptographicConstraint constraint) {
		super(result, constraint);
		this.currentTime = currentTime;
		this.token = token;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {

		// Check encryption algorithm
		ListAlgo acceptableEncryptionAlgo = constraint.getAcceptableEncryptionAlgo();
		if ((acceptableEncryptionAlgo != null) && CollectionUtils.isNotEmpty(acceptableEncryptionAlgo.getAlgo())) {
			if (!isIn(token.getEncryptionAlgoUsedToSignThisToken(), acceptableEncryptionAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_1;
				return false;
			}
		}

		// Check digest algorithm
		ListAlgo acceptableDigestAlgo = constraint.getAcceptableDigestAlgo();
		if ((acceptableDigestAlgo != null) && CollectionUtils.isNotEmpty(acceptableDigestAlgo.getAlgo())) {
			if (!isIn(token.getDigestAlgoUsedToSignThisToken(), acceptableDigestAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_2;
				return false;
			}
		}

		// Check public key size
		ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
		if ((miniPublicKeySize != null) && CollectionUtils.isNotEmpty(miniPublicKeySize.getAlgo())) {
			String keySize = token.getKeyLengthUsedToSignThisToken();
			int tokenKeySize = 0;
			if (NumberUtils.isDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}
			int expectedMinimumKeySize = getExpectedKeySize(token.getEncryptionAlgoUsedToSignThisToken(), miniPublicKeySize.getAlgo());
			if (tokenKeySize < expectedMinimumKeySize) {
				errorMessage = MessageTag.ASCCM_ANS_3;
				return false;
			}
		}

		// Check algorithm expiration date
		AlgoExpirationDate algoExpirationDate = constraint.getAlgoExpirationDate();
		if ((algoExpirationDate != null) && CollectionUtils.isNotEmpty(algoExpirationDate.getAlgo())) {

			// Digest algorithm
			Date expirationDate = getExpirationDate(token.getDigestAlgoUsedToSignThisToken(), algoExpirationDate.getAlgo());
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				return false;
			}
			if (expirationDate.before(currentTime)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
				return false;
			}

			// Encryption algorithm
			String algoToFind = token.getEncryptionAlgoUsedToSignThisToken() + token.getKeyLengthUsedToSignThisToken();
			expirationDate = getExpirationDate(algoToFind, algoExpirationDate.getAlgo());
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				return false;
			}
			if (expirationDate.before(currentTime)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
				return false;
			}
		}

		return true;
	}

	private Date getExpirationDate(String algoToFind, List<Algo> algos) {
		SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
		Date result = null;
		for (Algo algo : algos) {
			if (StringUtils.equals(algoToFind, algo.getValue())) {
				try {
					result = dateFormat.parse(algo.getDate());
				} catch (Exception e) {
					logger.warn("Unable to parse date with pattern '" + DATE_FORMAT + "' :" + e.getMessage());
				}
			}
		}
		return result;
	}

	private int getExpectedKeySize(String encryptionAlgo, List<Algo> algos) {
		int expectedSize = 0;
		for (Algo algo : algos) {
			if (StringUtils.equals(algo.getValue(), encryptionAlgo)) {
				String size = algo.getSize();
				if (NumberUtils.isDigits(size)) {
					expectedSize = Integer.parseInt(size);
				}
			}
		}
		return expectedSize;
	}

	private boolean isIn(String algoToFind, List<Algo> algos) {
		for (Algo algo : algos) {
			if (StringUtils.equals(algo.getValue(), algoToFind)) {
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

}
