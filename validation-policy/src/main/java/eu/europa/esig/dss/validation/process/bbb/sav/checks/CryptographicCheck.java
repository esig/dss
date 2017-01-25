package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraintsConclusion;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.TokenProxy;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.AlgoExpirationDate;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.ListAlgo;

public class CryptographicCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

	private static final Logger logger = LoggerFactory.getLogger(CryptographicCheck.class);

	private static final String DATE_FORMAT = "yyyy-MM-dd";

	private final Date validationDate;
	private final TokenProxy token;
	private final CryptographicConstraint constraint;
	private MessageTag errorMessage = MessageTag.EMPTY;

	public CryptographicCheck(T result, TokenProxy token, Date currentTime, CryptographicConstraint constraint) {
		super(result, constraint);
		this.validationDate = currentTime;
		this.token = token;
		this.constraint = constraint;
	}

	@Override
	protected boolean process() {

		// Check encryption algorithm
		ListAlgo acceptableEncryptionAlgo = constraint.getAcceptableEncryptionAlgo();
		if ((acceptableEncryptionAlgo != null) && Utils.isCollectionNotEmpty(acceptableEncryptionAlgo.getAlgo())) {
			if (!isIn(token.getEncryptionAlgoUsedToSignThisToken(), acceptableEncryptionAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_1;
				return false;
			}
		}

		// Check digest algorithm
		ListAlgo acceptableDigestAlgo = constraint.getAcceptableDigestAlgo();
		if ((acceptableDigestAlgo != null) && Utils.isCollectionNotEmpty(acceptableDigestAlgo.getAlgo())) {
			if (!isIn(token.getDigestAlgoUsedToSignThisToken(), acceptableDigestAlgo.getAlgo())) {
				errorMessage = MessageTag.ASCCM_ANS_2;
				return false;
			}
		}

		// Check public key size
		ListAlgo miniPublicKeySize = constraint.getMiniPublicKeySize();
		if ((miniPublicKeySize != null) && Utils.isCollectionNotEmpty(miniPublicKeySize.getAlgo())) {
			String keySize = token.getKeyLengthUsedToSignThisToken();
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
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
		if ((algoExpirationDate != null) && Utils.isCollectionNotEmpty(algoExpirationDate.getAlgo())) {

			// Digest algorithm
			Date expirationDate = getExpirationDate(token.getDigestAlgoUsedToSignThisToken(), algoExpirationDate.getAlgo(), algoExpirationDate.getFormat());
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				return false;
			}
			if (expirationDate.before(validationDate)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
				return false;
			}

			// Encryption algorithm
			String algoToFind = token.getEncryptionAlgoUsedToSignThisToken() + token.getKeyLengthUsedToSignThisToken();
			expirationDate = getExpirationDate(algoToFind, algoExpirationDate.getAlgo(), algoExpirationDate.getFormat());
			if (expirationDate == null) {
				errorMessage = MessageTag.ASCCM_ANS_4;
				return false;
			}
			if (expirationDate.before(validationDate)) {
				errorMessage = MessageTag.ASCCM_ANS_5;
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
				} catch (Exception e) {
					logger.warn("Unable to parse date with pattern '" + dateFormat.toPattern() + "' : " + e.getMessage());
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
		Object[] params = new Object[] { sdf.format(validationDate) };
		return MessageFormat.format(AdditionalInfo.VALIDATION_TIME, params);
	}

}
