package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlVTS;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class verifies the control time determined during the Validation Time Sliding process
 *
 */
public class ControlTimeCheck extends ChainItem<XmlVTS> {

    /** The control time */
    private final Date controlTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlVTS}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public ControlTimeCheck(I18nProvider i18nProvider, XmlVTS result, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.controlTime = controlTime;
    }

    @Override
    protected boolean process() {
        return controlTime != null;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.PSV_ICTD;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.PSV_ICTD_ANS;
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
        if (controlTime != null) {
            return i18nProvider.getMessage(MessageTag.CONTROL_TIME_ALONE, ValidationProcessUtils.getFormattedDate(controlTime));
        }
        return null;
    }

}
