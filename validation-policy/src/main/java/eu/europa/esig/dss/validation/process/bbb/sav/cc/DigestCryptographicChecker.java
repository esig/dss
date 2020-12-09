package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.Date;

/**
 * Checks the digest algorithm
 */
public class DigestCryptographicChecker extends AbstractCryptographicChecker {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param digestAlgorithm {@link DigestAlgorithm}
	 * @param validationDate {@link Date}
	 * @param position {@link MessageTag}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public DigestCryptographicChecker(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, Date validationDate,
									  MessageTag position, CryptographicConstraint constraint) {
		super(i18nProvider, digestAlgorithm, validationDate, position, constraint);
	}

	@Override
	protected void initChain() {
		
		// Check if there are any expiration dates
		boolean expirationCheckRequired = isExpirationDateAvailable();
		
		ChainItem<XmlCC> item = firstItem = digestAlgorithmReliable();
		
		if (expirationCheckRequired) {
			item = item.setNextItem(digestAlgorithmOnValidationTime());
		}
		
	}

}
