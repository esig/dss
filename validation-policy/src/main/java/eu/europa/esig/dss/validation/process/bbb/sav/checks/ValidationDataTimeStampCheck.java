package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Checks if a validation-data-time-stamp attribute is present
 *
 */
public class ValidationDataTimeStampCheck extends AbstractTimeStampCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public ValidationDataTimeStampCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
                                   LevelConstraint constraint) {
        super(i18nProvider, result, signature, constraint);
    }

    @Override
    protected TimestampType getTimestampType() {
        return TimestampType.VALIDATION_DATA_TIMESTAMP;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_SAV_IUQPVDTSP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_SAV_IUQPVDTSP_ANS;
    }

}
