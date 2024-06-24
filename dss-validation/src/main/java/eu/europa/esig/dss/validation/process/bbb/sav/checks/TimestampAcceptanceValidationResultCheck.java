package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * This class verifies output of "5.2.8 Signature Acceptance Validation" with a timestamp provided as the input
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class TimestampAcceptanceValidationResultCheck<T extends XmlConstraintsConclusion> extends SignatureAcceptanceValidationResultCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       the result
     * @param savResult    {@link XmlSAV}
     * @param constraint   {@link LevelConstraint}
     */
    public TimestampAcceptanceValidationResultCheck(I18nProvider i18nProvider, T result, XmlSAV savResult, LevelConstraint constraint) {
        super(i18nProvider, result, savResult, constraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_TAV_ISVA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_TAV_ISVA_ANS;
    }

}
