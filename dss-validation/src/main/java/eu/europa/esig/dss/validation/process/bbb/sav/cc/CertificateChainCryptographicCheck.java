package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheckerResultCheck;

import java.util.Date;

public class CertificateChainCryptographicCheck<T extends XmlConstraintsConclusion> extends CryptographicCheckerResultCheck<T> {

    public CertificateChainCryptographicCheck(final I18nProvider i18nProvider, final T result,
                                              final Date validationDate, final MessageTag position, final XmlCC ccResult,
                                              final LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, position, ccResult, constraint);
    }

    protected CertificateChainCryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token,
                                                 Date validationDate, MessageTag position, XmlCC ccResult,
                                                 LevelConstraint constraint) {
        super(i18nProvider, result, validationDate, position, ccResult, constraint, token.getId());
    }

}
