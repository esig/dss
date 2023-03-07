package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;

/**
 * This class verifies a presence of a time-stamp token in a signature of the given time-stamp type
 *
 */
public abstract class AbstractTimeStampCheck extends ChainItem<XmlSAV> {

    /** The signature to check */
    private final SignatureWrapper signature;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public AbstractTimeStampCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
                                  LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.signature = signature;
    }

    @Override
    protected boolean process() {
        for (TimestampWrapper timestampWrapper : signature.getTimestampList()) {
            if (getTimestampType() == timestampWrapper.getType()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the associated {@code TimestampType} to be verified against
     *
     * @return {@link TimestampType}
     */
    protected abstract TimestampType getTimestampType();

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.SIG_CONSTRAINTS_FAILURE;
    }

}
