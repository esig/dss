package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.List;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicConstraintWrapper;

public class EncryptionAlgorithmReliableCheck extends AbstractCryptographicCheck {
	
	private final EncryptionAlgorithm encryptionAlgo;

	protected EncryptionAlgorithmReliableCheck(I18nProvider i18nProvider, EncryptionAlgorithm encryptionAlgo, XmlCC result, MessageTag position, 
			CryptographicConstraintWrapper constraintWrapper) {
		super(i18nProvider, result, position, constraintWrapper);
		this.encryptionAlgo = encryptionAlgo;
	}

	@Override
	protected boolean process() {
		String algoToFind = encryptionAlgo == null ? Utils.EMPTY_STRING : encryptionAlgo.getName();
		List<String> supportedEncryptionAlgorithms = constraintWrapper.getSupportedEncryptionAlgorithms();
		if (Utils.isCollectionNotEmpty(supportedEncryptionAlgorithms)) {
			if (!supportedEncryptionAlgorithms.contains(algoToFind)) {
				return false;
			}
		}
		return true;
	}
	
	@Override
	protected XmlName buildConstraintMessage() {
		return buildXmlName(MessageTag.ASCCM_EAA, encryptionAlgo);
	}
	
	@Override
	protected XmlName buildErrorMessage() {
		return buildXmlName(MessageTag.ASCCM_EAA_ANS, encryptionAlgo, position);
	}

}
