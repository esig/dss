package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class DigestAlgorithmOnValidationTimeCheck extends AbstractCryptographicCheck {
	
	private final DigestAlgorithm digestAlgo;
	private final Date validationDate;
	
	private MessageTag errorMessage;

	protected DigestAlgorithmOnValidationTimeCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgo, Date validationDate, 
			XmlCC result, MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
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
