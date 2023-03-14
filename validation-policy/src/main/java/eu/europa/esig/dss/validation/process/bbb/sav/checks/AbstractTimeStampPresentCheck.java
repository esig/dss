package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessTimestamp;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Collection;
import java.util.Map;

/**
 * This an abstract class performing analysis if a valid timestamp from the given set is present
 */
public abstract class AbstractTimeStampPresentCheck extends ChainItem<XmlValidationProcessArchivalData> {

    /** Map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** List of timestamps */
    private final Collection<XmlTimestamp> xmlTimestamps;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessArchivalData}
     * @param bbbs map between token ids and corresponding {@code XmlBasicBuildingBlocks}
     * @param xmlTimestamps a collection of {@link XmlTimestamp}s
     * @param constraint {@link LevelConstraint}
     */
    public AbstractTimeStampPresentCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result,
                                         Map<String, XmlBasicBuildingBlocks> bbbs, Collection<XmlTimestamp> xmlTimestamps,
                                         LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.bbbs = bbbs;
        this.xmlTimestamps = xmlTimestamps;
    }

    @Override
    protected boolean process() {
        for (TimestampWrapper timestamp : getTimestamps()) {
            XmlValidationProcessTimestamp timestampBasicValidation = getTimestampBasicValidation(timestamp);
            if (timestampBasicValidation != null && ValidationProcessUtils.isAllowedBasicTimestampValidation(timestampBasicValidation.getConclusion())) {
                if (isValidConclusion(timestampBasicValidation.getConclusion())) {
                    return true;
                }
                XmlPSV tstPSV = getPastSignatureValidationForTimestamp(timestamp);
                if (tstPSV != null && isValidConclusion(tstPSV.getConclusion())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns a collection of timestamps to be checked for a presence of a valid one
     *
     * @return collection of {@link TimestampWrapper}s
     */
    protected abstract Collection<TimestampWrapper> getTimestamps();

    private XmlValidationProcessTimestamp getTimestampBasicValidation(TimestampWrapper timestamp) {
        for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
            if (timestamp.getId().equals(xmlTimestamp.getId())) {
                return xmlTimestamp.getValidationProcessTimestamp();
            }
        }
        return null;
    }

    private XmlPSV getPastSignatureValidationForTimestamp(TimestampWrapper timestampWrapper) {
        XmlBasicBuildingBlocks tstBBB = bbbs.get(timestampWrapper.getId());
        if (tstBBB != null) {
            return tstBBB.getPSV();
        }
        return null;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
    }

}