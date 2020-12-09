package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.DigestCryptographicChecker;

import java.util.Date;

/**
 * Verifies the {@code DigestAlgorithm}
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class DigestCryptographicCheck<T extends XmlConstraintsConclusion> extends DigestCryptographicCheckerResultCheck<T> {

	public DigestCryptographicCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, T result, Date validationDate, MessageTag position,
			CryptographicConstraint constraint) {
		super(i18nProvider, result, validationDate, position, 
				execute(i18nProvider, digestAlgorithm, validationDate, position, constraint), constraint);
	}

	public DigestCryptographicCheck(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, T result, Date validationDate, MessageTag position,
			String referenceName, CryptographicConstraint constraint) {
		super(i18nProvider, result, validationDate, position, referenceName, 
				execute(i18nProvider, digestAlgorithm, validationDate, position, constraint), constraint);
	}
	
	private static XmlCC execute(I18nProvider i18nProvider, DigestAlgorithm digestAlgorithm, Date validationDate,
			MessageTag position, CryptographicConstraint constraint) {
		DigestCryptographicChecker dac = new DigestCryptographicChecker(i18nProvider, digestAlgorithm, validationDate, position, constraint);
		return dac.execute();
	}

}
