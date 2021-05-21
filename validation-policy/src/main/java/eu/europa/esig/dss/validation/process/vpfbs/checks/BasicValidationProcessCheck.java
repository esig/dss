package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * Verifies if the Basic Signature Validation Process succeeds
 *
 */
public class BasicValidationProcessCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The final check conclusion */
    private final XmlConclusion xmlConclusion;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param xmlConclusion {@link XmlConclusion}
     * @param token {@link TokenProxy}
     * @param constraint {@link LevelConstraint}
     */
    public BasicValidationProcessCheck(I18nProvider i18nProvider, T result,
                                       XmlConclusion xmlConclusion, TokenProxy token, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, token.getId());
        this.xmlConclusion = xmlConclusion;
    }

    @Override
    protected boolean process() {
        return isValidConclusion(xmlConclusion);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return xmlConclusion.getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return xmlConclusion.getSubIndication();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_ROBVPIIC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_ROBVPIIC_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (!isValidConclusion(xmlConclusion)) {
            String indication = String.format("%s/%s", xmlConclusion.getIndication(), xmlConclusion.getSubIndication());
            return i18nProvider.getMessage(MessageTag.BASIC_SIGNATURE_VALIDATION_RESULT, indication);
        }
        return null;
    }

}
