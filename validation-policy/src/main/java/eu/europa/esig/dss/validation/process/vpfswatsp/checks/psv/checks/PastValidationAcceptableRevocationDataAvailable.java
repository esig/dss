package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Checks if an acceptable revocation data is present for a Past Signature Validation process
 *
 */
public class PastValidationAcceptableRevocationDataAvailable<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Revocation data to check */
    private final List<CertificateRevocationWrapper> revocationData;

    /**
     * Constructor without certificate
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param revocationData a list of {@link CertificateRevocationWrapper}s
     * @param constraint {@link LevelConstraint}
     */
    public PastValidationAcceptableRevocationDataAvailable(I18nProvider i18nProvider, T result,
                                                           List<CertificateRevocationWrapper> revocationData,
                                                           LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.revocationData = revocationData;
    }

    @Override
    protected boolean process() {
        return Utils.isCollectionNotEmpty(revocationData);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_IARDPFC;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_IARDPFC_ANS;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.INDETERMINATE;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return SubIndication.TRY_LATER;
    }

    @Override
    protected String buildAdditionalInfo() {
        if (Utils.isCollectionNotEmpty(revocationData)) {
            List<String> revocationDataIds = revocationData.stream().map(r -> r.getId()).collect(Collectors.toList());
            return i18nProvider.getMessage(MessageTag.ACCEPTABLE_REVOCATION, revocationDataIds);
        }
        return null;
    }

}
