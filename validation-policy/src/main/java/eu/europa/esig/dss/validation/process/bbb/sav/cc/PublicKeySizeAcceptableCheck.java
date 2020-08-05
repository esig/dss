package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Map;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class PublicKeySizeAcceptableCheck extends AbstractCryptographicCheck {
	
	private final EncryptionAlgorithm encryptionAlgo;
	private final String keySize;

	protected PublicKeySizeAcceptableCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo, String keySize, 
			XmlCC result, MessageTag position, CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
		this.keySize = keySize;
	}

	@Override
	protected boolean process() {
		String algoToFind = encryptionAlgo == null ? Utils.EMPTY_STRING : encryptionAlgo.getName();
		Map<String, Integer> minimumKeySizes = constraintWrapper.getMinimumKeySizes();
		if (Utils.isMapNotEmpty(minimumKeySizes)) {
			int tokenKeySize = 0;
			if (Utils.isStringDigits(keySize)) {
				tokenKeySize = Integer.parseInt(keySize);
			}
	
			Integer expectedMinimumKeySize = minimumKeySizes.get(algoToFind);
			if (tokenKeySize < expectedMinimumKeySize) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_APKSA, encryptionAlgo, keySize);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(MessageTag.ASCCM_APKSA_ANS, encryptionAlgo, keySize, position);
	}

}
