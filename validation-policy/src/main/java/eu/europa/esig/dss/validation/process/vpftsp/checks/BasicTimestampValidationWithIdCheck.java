package eu.europa.esig.dss.validation.process.vpftsp.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessBasicTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public class BasicTimestampValidationWithIdCheck<T extends XmlConstraintsConclusion> extends BasicTimestampValidationCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link T}
     * @param timestamp {@link TimestampWrapper}
     * @param timestampValidationResult {@link XmlValidationProcessBasicTimestamp}
     * @param constraint {@link LevelConstraint}
     */
    public BasicTimestampValidationWithIdCheck(I18nProvider i18nProvider, T result, TimestampWrapper timestamp,
                                         XmlValidationProcessBasicTimestamp timestampValidationResult,
                                         LevelConstraint constraint) {
        super(i18nProvider, result, timestamp, timestampValidationResult, constraint, timestamp.getId());
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION,
                ValidationProcessUtils.getTimestampTypeMessageTag(timestamp.getType()), timestamp.getId(), date);
    }

}
