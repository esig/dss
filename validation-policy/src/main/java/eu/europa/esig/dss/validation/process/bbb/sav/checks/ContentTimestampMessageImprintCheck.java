package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampMessageImprintCheck;

/**
 * Checks if the computed message-imprint matches for a content timestamp
 */
public class ContentTimestampMessageImprintCheck extends TimestampMessageImprintCheck<XmlSAV> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       {@link XmlSAV}
     * @param timestamp    {@link TimestampWrapper}
     * @param constraint   {@link LevelConstraint}
     */
    public ContentTimestampMessageImprintCheck(I18nProvider i18nProvider, XmlSAV result, TimestampWrapper timestamp,
                                               LevelConstraint constraint) {
        super(i18nProvider, result, timestamp, constraint);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_SAV_DMICTSTMCMI;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_SAV_DMICTSTMCMI_ANS;
    }

}
