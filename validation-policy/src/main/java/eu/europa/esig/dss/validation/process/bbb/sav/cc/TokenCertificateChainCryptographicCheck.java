package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Date;

public class TokenCertificateChainCryptographicCheck<T extends XmlConstraintsConclusion> extends CertificateChainCryptographicCheck<T> {

    /** Token, which certificate chain will be validated */
    private final TokenProxy token;

    public TokenCertificateChainCryptographicCheck(I18nProvider i18nProvider, T result, TokenProxy token,
                                                   Date validationDate, MessageTag position, XmlCC ccResult,
                                                   LevelConstraint constraint) {
        super(i18nProvider, result, token, validationDate, position, ccResult, constraint);
        this.token = token;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_ID_RESULT, super.buildAdditionalInfo(), token.getId());
    }

}
