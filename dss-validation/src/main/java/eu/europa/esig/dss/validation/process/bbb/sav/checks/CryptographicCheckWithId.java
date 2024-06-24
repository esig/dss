package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;

import java.util.Date;

public class CryptographicCheckWithId<T extends XmlConstraintsConclusion> extends CryptographicCheck<T> {

    /** Token, which certificate chain will be validated */
    private final TokenProxy token;

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
    public CryptographicCheckWithId(I18nProvider i18nProvider, T result, TokenProxy token, MessageTag position,
                                    Date validationDate, CryptographicConstraint constraint) {
        super(i18nProvider, result, token, position, validationDate, constraint, token.getId());
        this.token = token;
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.ACCM_DESC_WITH_ID_RESULT, super.buildAdditionalInfo(), token.getId());
    }

}
