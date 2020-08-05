package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

public class CryptographicChecker extends AbstractCryptographicChecker {

	public CryptographicChecker(I18nProvider i18nProvider, TokenProxy token, Date validationDate, MessageTag position, CryptographicConstraint constraint) {
		super(i18nProvider, token.getEncryptionAlgorithm(), token.getDigestAlgorithm(), 
				token.getMaskGenerationFunction(), token.getKeyLengthUsedToSignThisToken(), validationDate, position, constraint);
	}

	@Override
	protected void initChain() {
		
		// Check if there are any expiration dates
		boolean expirationCheckRequired = isExpirationDateAvailable();
		
		ChainItem<XmlCC> item = firstItem = encryptionAlgorithmReliable();
		
		item = item.setNextItem(digestAlgorithmReliable());
		
		if (expirationCheckRequired) {
			item = item.setNextItem(digestAlgorithmOnValidationTime());
		}
		
		item = item.setNextItem(publicKeySizeKnown());
		
		item = item.setNextItem(publicKeySizeAcceptable());
		
		if (expirationCheckRequired) {
			item = item.setNextItem(encryptionAlgorithmOnValidationTime());
		}
		
	}

}
