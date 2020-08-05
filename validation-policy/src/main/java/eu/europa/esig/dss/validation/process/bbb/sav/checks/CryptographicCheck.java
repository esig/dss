package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.cc.CryptographicChecker;

public class CryptographicCheck<T extends XmlConstraintsConclusion> extends CryptographicCheckerResultCheck<T> {

	public CryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position, Date validationDate, 
			CryptographicConstraint constraint) {
		super(i18nProvider, result, token, validationDate, position, execute(i18nProvider, token, validationDate, position, constraint), constraint);
	}
	
	private static XmlCC execute(I18nProvider i18nProvider, TokenProxy token, Date validationDate,
			MessageTag position, CryptographicConstraint constraint) {
		CryptographicChecker cc = new CryptographicChecker(i18nProvider, token, validationDate, position, constraint);
		return cc.execute();
	}

}
