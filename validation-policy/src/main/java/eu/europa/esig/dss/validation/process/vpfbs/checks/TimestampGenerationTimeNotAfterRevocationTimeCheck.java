package eu.europa.esig.dss.validation.process.vpfbs.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBlockType;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;

import java.util.Date;

/**
 * This class checks if the generation time of a content timestamp is not after
 * the revocation time of a signature's signing certificate
 *
 */
public class TimestampGenerationTimeNotAfterRevocationTimeCheck<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** The content timestamp */
    private final TimestampWrapper contentTimestamp;

    /** Revocation time of the signing certificate */
    private final Date signingCertificateRevocationTime;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param contentTimestamp {@link TimestampWrapper}
     * @param signingCertificateRevocationTime {@link Date} the time when the signing certificate has been revoked
     * @param constraint {@link LevelConstraint}
     */
    public TimestampGenerationTimeNotAfterRevocationTimeCheck(I18nProvider i18nProvider, T result,
                        TimestampWrapper contentTimestamp, Date signingCertificateRevocationTime, LevelConstraint constraint) {
        super(i18nProvider, result, constraint, contentTimestamp.getId());
        this.contentTimestamp = contentTimestamp;
        this.signingCertificateRevocationTime = signingCertificateRevocationTime;
    }

    @Override
    protected XmlBlockType getBlockType() {
        return XmlBlockType.CNT_TST_BBB;
    }

    @Override
    protected boolean process() {
        return contentTimestamp.getProductionTime() != null &&
                !contentTimestamp.getProductionTime().after(signingCertificateRevocationTime);
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.REVOKED;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BSV_ICTGTNASCRT;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BSV_ICTGTNASCRT_ANS;
    }

    @Override
    protected String buildAdditionalInfo() {
        String tstGenerationTime = contentTimestamp.getProductionTime() == null ? " ? " : ValidationProcessUtils.getFormattedDate(contentTimestamp.getProductionTime());
        String revocationTime = signingCertificateRevocationTime == null ? " ? " : ValidationProcessUtils.getFormattedDate(signingCertificateRevocationTime);
        return i18nProvider.getMessage(MessageTag.TIMESTAMP_AND_REVOCATION_TIME, contentTimestamp.getId(), tstGenerationTime, revocationTime);
    }
}
