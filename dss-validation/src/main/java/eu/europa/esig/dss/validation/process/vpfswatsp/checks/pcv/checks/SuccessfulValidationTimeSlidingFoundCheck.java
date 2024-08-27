package eu.europa.esig.dss.validation.process.vpfswatsp.checks.pcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

/**
 * This class verifies whether a successful Validation Time Sliding process was found
 *
 */
public class SuccessfulValidationTimeSlidingFoundCheck extends ChainItem<XmlPCV> {

    /** The best successful VTS result */
    private final XmlVTS vts;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlPCV}
     * @param vts {@link XmlVTS}
     * @param constraint {@link LevelConstraint}
     */
    public SuccessfulValidationTimeSlidingFoundCheck(I18nProvider i18nProvider, XmlPCV result, XmlVTS vts,
                                                     LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.vts = vts;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.VTS;
    }

    @Override
    protected boolean process() {
        return vts != null && isValid(vts);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PCV_ICCSVTSF;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PCV_ICCSVTSF_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.NO_POE;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (vts != null) {
            return i18nProvider.getMessage(MessageTag.CONTROL_TIME_WITH_TRUST_ANCHOR, vts.getTrustAnchor(),
                    ValidationProcessUtils.getFormattedDate(vts.getControlTime()));
        }
        return null;
    }

}
