package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Checks if the signature is intact for the given token, with a difference
 * that provides the token's Id to the additional information
 *
 */
public class SignatureIntactWithIdCheck extends SignatureIntactCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       the result
     * @param token        {@link TokenProxy}
     * @param context      {@link Context}
     * @param constraint   {@link LevelConstraint}
     */
    public SignatureIntactWithIdCheck(I18nProvider i18nProvider, XmlConstraintsConclusion result, TokenProxy token,
                                      Context context, LevelConstraint constraint) {
        super(i18nProvider, result, token, context, constraint);
    }

    @Override
    protected String buildAdditionalInfo() {
        return i18nProvider.getMessage(MessageTag.TOKEN_ID, token.getId());
    }

}
