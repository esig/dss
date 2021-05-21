package eu.europa.esig.dss.validation.process.vpftsp;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.validation.process.vpfbs.AbstractBasicValidationProcess;

import java.util.Map;

/**
 * Performs Time-stamp validation building block as per clause 5.4
 *
 */
public class TimestampBasicValidationProcess extends AbstractBasicValidationProcess<XmlValidationProcessTimestamp> {

    /**
     * Timestamp being validated
     */
    private final TimestampWrapper timestamp;

    /**
     * Default constructor
     *
     * @param i18nProvider   {@link I18nProvider}
     * @param diagnosticData {@link DiagnosticData}
     * @param timestamp {@link TimestampWrapper}
     * @param bbbs           map of BasicBuildingBlocks
     */
    public TimestampBasicValidationProcess(I18nProvider i18nProvider, DiagnosticData diagnosticData,
                                           TimestampWrapper timestamp, Map<String, XmlBasicBuildingBlocks> bbbs) {
        super(i18nProvider, new XmlValidationProcessTimestamp(), diagnosticData, timestamp, bbbs);
        this.timestamp = timestamp;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VPFTSP;
    }

    @Override
    protected void addAdditionalInfo() {
        result.setType(timestamp.getType().name());
        result.setProductionTime(timestamp.getProductionTime());
    }

}
