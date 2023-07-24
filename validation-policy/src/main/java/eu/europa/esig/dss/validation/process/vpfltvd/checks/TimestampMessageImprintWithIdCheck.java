package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.vpftspwatsp.checks.TimestampMessageImprintCheck;

/**
 * This class checks a timestamp's message-imprint and returns an Id of the provided token
 *
 * @param <T> implementation of the block's conclusion
 */
public class TimestampMessageImprintWithIdCheck<T extends XmlConstraintsConclusion> extends TimestampMessageImprintCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       {@link XmlSAV}
     * @param timestamp    {@link TimestampWrapper}
     * @param constraint   {@link LevelConstraint}
     */
    public TimestampMessageImprintWithIdCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                              LevelConstraint constraint) {
        super(i18nProvider, result, timestamp, constraint, timestamp.getId());
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                ValidationProcessUtils.getTimestampTypeMessageTag(timestamp.getType()), timestamp.getId(), date);
    }

}
