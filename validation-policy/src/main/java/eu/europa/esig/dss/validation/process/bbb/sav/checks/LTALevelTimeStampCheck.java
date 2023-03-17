package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessArchivalData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Collection;
import java.util.Map;

/**
 * Verifies if there is at least one valid LTA-level timestamp
 */
public class LTALevelTimeStampCheck extends AbstractTimeStampPresentCheck {

    /** The signature to check */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlValidationProcessArchivalData}
     * @param signature {@link SignatureWrapper}
     * @param bbbs map between token ids and corresponding {@code XmlBasicBuildingBlocks}
     * @param xmlTimestamps a collection of {@link XmlTimestamp}s
     * @param constraint {@link LevelConstraint}
     */
    public LTALevelTimeStampCheck(I18nProvider i18nProvider, XmlValidationProcessArchivalData result, SignatureWrapper signature,
                                Map<String, XmlBasicBuildingBlocks> bbbs, Collection<XmlTimestamp> xmlTimestamps,
                                LevelConstraint constraint) {
        super(i18nProvider, result, bbbs, xmlTimestamps, constraint);
        this.signature = signature;
    }

    @Override
    protected Collection<TimestampWrapper> getTimestamps() {
        return signature.getALevelTimestamps();
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_SAV_IVLTATSTP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_SAV_IVLTATSTP_ANS;
    }

}
