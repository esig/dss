package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

/**
 * Check if EncryptionAlgorithm is public key size is known
 */
public class PublicKeySizeKnownCheck extends AbstractCryptographicCheck {

	/** Used key size */
	private final String keySize;

	/** The constraint position */
	private final MessageTag position;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param keySize {@link String}
	 * @param result {@link XmlCC}
	 * @param position {@link MessageTag}
	 * @param constraintWrapper {@link CryptographicConstraintWrapper}
	 */
	protected PublicKeySizeKnownCheck(I18nProvider i18nProvider, String keySize, XmlCC result, MessageTag position, 
			CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.keySize = keySize;
		this.position = position;
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
