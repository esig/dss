package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

public class SignatureTimestampMessageImprintCheck extends TimestampMessageImprintCheck<XmlValidationProcessLongTermData> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result       {@link XmlValidationProcessLongTermData}
     * @param timestamp    {@link TimestampWrapper}
     * @param constraint   {@link LevelConstraint}
     */
    public SignatureTimestampMessageImprintCheck(I18nProvider i18nProvider, XmlValidationProcessLongTermData result,
                                                 TimestampWrapper timestamp, LevelConstraint constraint) {
        super(i18nProvider, result, timestamp, constraint);
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.TST_BBB;
    }

    @Override
    protected String buildAdditionalInfo() {
        String date = ValidationProcessUtils.getFormattedDate(timestamp.getProductionTime());
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_VALIDATION, timestamp.getId(), date);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.ADEST_DMISTSTMCMI;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.ADEST_DMISTSTMCMI_ANS;
    }

}
