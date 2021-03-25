package eu.europa.esig.dss.validation.process.vpfswatsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

public class MessageImprintDigestAlgorithmValidationCheck extends ChainItem<XmlValidationProcessArchivalData> {

    /** The timestamp to check */
    private final TimestampWrapper timestamp;

    /** Message-imprint Digest Algorithm validation result */
    private final XmlSAV davResult;

    /** Defined the validation time */
    private final Date currentTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessArchivalData}
     * @param timestamp {@link TimestampWrapper}
     * @param davResult {@link XmlSAV}
     * @param currentTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public MessageImprintDigestAlgorithmValidationCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result,
                                                  TimestampWrapper timestamp,
                                                  XmlSAV davResult, Date currentTime,
                                                  LevelConstraint constraint) {
        super(i18nProvider, result, constraint, timestamp.getId());
        this.timestamp = timestamp;
        this.davResult = davResult;
        this.currentTime = currentTime;
    }

    @Override
    protected boolean process() {
        return isValid(davResult);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ARCH_ICHFCRLPOET;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ARCH_ICHFCRLPOET_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        String dateTime = ValidationProcessUtils.getFormattedDate(currentTime);
        if (isValid(davResult)) {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_SUCCESS_DM_WITH_ID,
                    timestamp.getMessageImprint().getDigestMethod(), dateTime, timestamp.getId());
        } else {
            return i18nProvider.getMessage(MessageTag.CRYPTOGRAPHIC_CHECK_FAILURE_WITH_ID,
                    timestamp.getMessageImprint().getDigestMethod(), dateTime, timestamp.getId());
        }
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return davResult.getConclusion().getIndication();
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return davResult.getConclusion().getSubIndication();
    }

}
