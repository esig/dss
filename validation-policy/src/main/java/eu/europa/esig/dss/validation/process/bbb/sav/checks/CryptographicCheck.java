package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicChecker;

import java.util.Date;

/**
 * The cryptographic check
 *
 * @param <T> {@code XmlConstraintsConclusion}
 */
public class CryptographicCheck<T extends XmlConstraintsConclusion> extends CryptographicCheckerResultCheck<T> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param token {@link TokenProxy}
	 * @param position {@link MessageTag}
	 * @param validationDate {@link Date}
	 * @param constraint {@link CryptographicConstraint}
	 */
	public CryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position,
							  Date validationDate, CryptographicConstraint constraint) {
		super(i18nProvider, result, token, validationDate, position,
				execute(i18nProvider, token, validationDate, position, constraint), constraint);
	}
	
	private static XmlCC execute(I18nProvider i18nProvider, TokenProxy token, Date validationDate,
			MessageTag position, CryptographicConstraint constraint) {
		CryptographicChecker cc = new CryptographicChecker(i18nProvider, token, validationDate, position, constraint);
		return cc.execute();
	}

}
