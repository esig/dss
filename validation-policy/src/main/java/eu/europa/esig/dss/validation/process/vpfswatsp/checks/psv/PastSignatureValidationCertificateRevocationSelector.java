package eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.RevocationIssuerTrustedCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.LongTermValidationCertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.POEExistsWithinCertificateValidityRangeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.psv.checks.PastValidationAcceptableRevocationDataAvailable;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Filters revocation data on a "Past Signature Validation" process
 *
 */
public class PastSignatureValidationCertificateRevocationSelector extends LongTermValidationCertificateRevocationSelector {

    /** POE container */
    private final POEExtraction poe;

    /** A list of acceptable revocation data for the given {@code certificate} */
    private final List<CertificateRevocationWrapper> acceptableCertificateRevocations = new ArrayList<>();

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param certificate      {@link CertificateWrapper}
     * @param currentTime      {@link Date} validation time
     * @param bbbs             a map of {@link XmlBasicBuildingBlocks}
     * @param tokenId          {@link String} current token id being validated
     * @param poe              {@link POEExtraction}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public PastSignatureValidationCertificateRevocationSelector(
            I18nProvider i18nProvider, CertificateWrapper certificate, Date currentTime,
            Map<String, XmlBasicBuildingBlocks> bbbs, String tokenId, POEExtraction poe, ValidationPolicy validationPolicy) {
        super(i18nProvider, certificate, currentTime, bbbs, tokenId, validationPolicy);
        this.poe = poe;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.PSV_CRS;
    }

    @Override
    protected ChainItem<XmlCRS> verifyRevocationData(ChainItem<XmlCRS> item, CertificateRevocationWrapper revocationWrapper) {
        item = super.verifyRevocationData(item, revocationWrapper);

        Boolean validity = revocationDataValidityMap.get(revocationWrapper);
        if (validity) {
            CertificateWrapper revocationIssuer = revocationWrapper.getSigningCertificate();

            if (revocationIssuer != null) {

                if (revocationIssuer.isTrusted()) {

                    item = item.setNextItem(revocationDataIssuerTrusted(revocationIssuer));

                    acceptableCertificateRevocations.add(revocationWrapper);
                    result.getAcceptableRevocationId().add(revocationWrapper.getId());

                    revocationDataValidityMap.put(revocationWrapper, true);

                } else {

                    item = item.setNextItem(poeForRevocationDataIssuerExists(revocationIssuer));

                    validity = poe.isPOEExistInRange(revocationIssuer.getId(),
                            revocationIssuer.getNotBefore(), revocationIssuer.getNotAfter());

                    if (validity) {
                        acceptableCertificateRevocations.add(revocationWrapper);
                        result.getAcceptableRevocationId().add(revocationWrapper.getId());
                    }

                    // update the validity map
                    revocationDataValidityMap.put(revocationWrapper, validity);

                }

            }
        }


        return item;
    }

    @Override
    protected XmlConclusion getRevocationBBBConclusion(CertificateRevocationWrapper revocationWrapper) {
        XmlBasicBuildingBlocks revocationBBB = bbbs.get(revocationWrapper.getId());
        if (revocationBBB != null) {
            return revocationBBB.getConclusion();
        }
        return null;
    }

    private ChainItem<XmlCRS> revocationDataIssuerTrusted(CertificateWrapper revocationIssuer) {
        return new RevocationIssuerTrustedCheck(i18nProvider, result, revocationIssuer, getWarnLevelConstraint());
    }

    private ChainItem<XmlCRS> poeForRevocationDataIssuerExists(CertificateWrapper revocationIssuer) {
        return new POEExistsWithinCertificateValidityRangeCheck(i18nProvider, result, revocationIssuer, poe,
                getWarnLevelConstraint());
    }

    @Override
    protected ChainItem<XmlCRS> acceptableRevocationDataAvailable() {
        return new PastValidationAcceptableRevocationDataAvailable(i18nProvider, result,
                acceptableCertificateRevocations, getFailLevelConstraint());
    }

    @Override
    public CertificateRevocationWrapper getLatestAcceptableCertificateRevocation() {
        // not applicable
        return null;
    }

    /**
     * Returns a list of acceptable certificate revocation data in the past validation process
     *
     * @return a list of {@link CertificateRevocationWrapper}s
     */
    public List<CertificateRevocationWrapper> getAcceptableCertificateRevocations() {
        return acceptableCertificateRevocations;
    }

}
