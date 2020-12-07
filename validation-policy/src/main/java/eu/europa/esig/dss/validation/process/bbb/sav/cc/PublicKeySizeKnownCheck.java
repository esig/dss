package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class PublicKeySizeKnownCheck extends AbstractCryptographicCheck {
	
	private final String keySize;

	protected PublicKeySizeKnownCheck(I18nProvider i18nProvider, String keySize, XmlCC result, MessageTag position, 
			CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.keySize = keySize;
	}

	@Override
	protected boolean process() {
		if (!Utils.isStringDigits(keySize)) {
			return false;
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_PKSK);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(MessageTag.ASCCM_PKSK_ANS, position);
	}

}
