package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

import java.util.Date;

/**
 * Check DigestAlgorithm in validation time
 */
public class DigestAlgorithmOnValidationTimeCheck extends AbstractCryptographicCheck {

	/** The algorithm to check */
	private final DigestAlgorithm digestAlgo;

	/** The validation date */
	private final Date validationDate;

	/** The error message if occurred */
	private MessageTag errorMessage;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgo {@link DigestAlgorithm}
	 * @param validationDate {@link Date}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected DigestAlgorithmOnValidationTimeCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgo,
												   Date validationDate, XmlCC result, MessageTag position,
												   CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.digestAlgo = digestAlgo;
		this.validationDate = validationDate;
	}

	@Override
	protected boolean process() {
		String algoToFind = digestAlgo == null ? Utils.EMPTY_STRING : digestAlgo.getName();		
		Date expirationDate = constraintWrapper.getDigestAlgorithmExpirationDate(algoToFind);
		if (expirationDate == null) {
			errorMessage = MessageTag.ASCCM_AR_ANS_AEDND;
			return false;
		} else if (expirationDate.before(validationDate)) {
			errorMessage = MessageTag.ASCCM_AR_ANS_ANR;
			return false;
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_AR, digestAlgo);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(errorMessage, digestAlgo, position);
	}

}
