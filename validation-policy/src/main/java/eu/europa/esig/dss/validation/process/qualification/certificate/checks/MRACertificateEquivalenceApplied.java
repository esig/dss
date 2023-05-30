package eu.europa.esig.dss.validation.process.qualification.certificate.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateContentEquivalence;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * This class verifies whether the certificate content equivalence information has been applied for the certificate
 *
 * @param <T> implementation of the block's conclusion
 */
public class MRACertificateEquivalenceApplied<T extends XmlConstraintsConclusion> extends ChainItem<T> {

    /** Certificate to be verified */
    private final CertificateWrapper certificateWrapper;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlConstraintsConclusion}
     * @param certificateWrapper {@link CertificateWrapper}
     * @param constraint {@link LevelConstraint}
     */
    public MRACertificateEquivalenceApplied(I18nProvider i18nProvider, T result,
                                            CertificateWrapper certificateWrapper, LevelConstraint constraint) {
        super(i18nProvider, result, constraint);
        this.certificateWrapper = certificateWrapper;
    }

    @Override
    protected boolean process() {
        if (!certificateWrapper.isEnactedMRA()) {
            return false;
        }
        for (XmlCertificateContentEquivalence certificateContentEquivalence : certificateWrapper.getMRACertificateContentEquivalenceList()) {
            if (!certificateContentEquivalence.isEnacted()) {
                return false;
            }
        }
        return true;
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.QUAL_HAS_METS_HCCECBA;
    }


    @Override
    protected XmlMessage buildErrorMessage() {
        if (!certificateWrapper.isEnactedMRA()) {
            return buildXmlMessage(MessageTag.QUAL_HAS_METS_HCCECBA_ANS);
        }
        Collection<String> uriList = getFailedCertificateEquivalenceContextUris();
        MessageTag errorTag = Utils.collectionSize(uriList) == 1 ? MessageTag.QUAL_HAS_METS_HCCECBA_ANS_2 : MessageTag.QUAL_HAS_METS_HCCECBA_ANS_3;
        String argument = Utils.collectionSize(uriList) == 1 ? uriList.iterator().next() : uriList.toString();
        return buildXmlMessage(errorTag, argument);
    }

    private Collection<String> getFailedCertificateEquivalenceContextUris() {
        List<String> result = new ArrayList<>();
        for (XmlCertificateContentEquivalence certificateContentEquivalence : certificateWrapper.getMRACertificateContentEquivalenceList()) {
            if (!certificateContentEquivalence.isEnacted()) {
                result.add(certificateContentEquivalence.getUri());
            }
        }
        return result;
    }

    @Override
    protected Indication getFailedIndicationForConclusion() {
        return Indication.FAILED;
    }

    @Override
    protected SubIndication getFailedSubIndicationForConclusion() {
        return null;
    }

}
