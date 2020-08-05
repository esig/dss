package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class EncryptionAlgorithmOnValidationTimeCheck extends AbstractCryptographicCheck {
	
	private final EncryptionAlgorithm encryptionAlgo;
	private final String keySize;
	private final Date validationDate;
	
	private MessageTag errorMessage;

	protected EncryptionAlgorithmOnValidationTimeCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo, String keySize, Date validationDate, 
			XmlCC result, MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
		this.keySize = keySize;
		this.validationDate = validationDate;
	}

	@Override
	protected boolean process() {
		Integer keyLength = Integer.parseInt(keySize);
		Date expirationDate = constraintWrapper.getExpirationDate(encryptionAlgo.getName(), keyLength);
		if (expirationDate == null) {
			errorMessage = MessageTag.ASCCM_AR_ANS_AEDND;
			return false;
		}
		if (expirationDate.before(validationDate)) {
			errorMessage = MessageTag.ASCCM_AR_ANS_AKSNR;
			return false;
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_AR, encryptionAlgo);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		if (MessageTag.ASCCM_AR_ANS_AKSNR.equals(errorMessage)) {
			return buildXmlName(errorMessage, encryptionAlgo, keySize, position);
		} else {
			return buildXmlName(errorMessage, encryptionAlgo, position);
		}
	}

}
