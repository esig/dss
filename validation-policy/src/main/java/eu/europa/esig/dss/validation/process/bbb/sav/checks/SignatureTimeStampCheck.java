package eu.europa.esig.dss.validation.process.bbb.sav.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Checks if a signature-time-stamp attribute is present
 *
 */
public class SignatureTimeStampCheck extends AbstractTimeStampCheck {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlSAV}
     * @param signature {@link SignatureWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public SignatureTimeStampCheck(I18nProvider i18nProvider, XmlSAV result, SignatureWrapper signature,
                                   LevelConstraint constraint) {
        super(i18nProvider, result, signature, constraint);
    }

    @Override
    protected TimestampType getTimestampType() {
        return TimestampType.SIGNATURE_TIMESTAMP;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_SAV_IUQPSTSP;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_SAV_IUQPSTSP_ANS;
    }

}
