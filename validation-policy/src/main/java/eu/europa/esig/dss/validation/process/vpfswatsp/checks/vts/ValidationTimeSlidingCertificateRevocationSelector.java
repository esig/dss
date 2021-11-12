package eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts;

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TokenProxy;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.vpfltvd.LongTermValidationCertificateRevocationSelector;
import eu.europa.esig.dss.validation.process.vpfswatsp.POEExtraction;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.POEExistsAtOrBeforeControlTimeCheck;
import eu.europa.esig.dss.validation.process.vpfswatsp.checks.vts.checks.RevocationIssuedBeforeControlTimeCheck;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Filters revocation data on a "Validation Time Sliding" process
 *
 */
public class ValidationTimeSlidingCertificateRevocationSelector extends LongTermValidationCertificateRevocationSelector {

    /** POE container */
    private final POEExtraction poe;

    /** List of acceptable certificate revocation data for VTS processing */
    private final List<CertificateRevocationWrapper> certificateRevocationData;

    /**
     * Default constructor
     *
     * @param i18nProvider     {@link I18nProvider}
     * @param certificate      {@link CertificateWrapper}
     * @param certificateRevocationData a list of {@link CertificateRevocationWrapper}s
     * @param currentTime      {@link Date} validation time
     * @param bbbs             a map of {@link XmlBasicBuildingBlocks}
     * @param tokenId          {@link String} current token id being validated
     * @param poe              {@link POEExtraction}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public ValidationTimeSlidingCertificateRevocationSelector(
            I18nProvider i18nProvider, CertificateWrapper certificate, List<CertificateRevocationWrapper> certificateRevocationData,
            Date currentTime, Map<String, XmlBasicBuildingBlocks> bbbs, String tokenId, POEExtraction poe, ValidationPolicy validationPolicy) {
        super(i18nProvider, certificate, currentTime, bbbs, tokenId, validationPolicy);
        this.certificateRevocationData = certificateRevocationData;
        this.poe = poe;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.VTS_CRS;
    }

    @Override
    public List<CertificateRevocationWrapper> getCertificateRevocationData() {
        return certificateRevocationData;
    }

    @Override
    protected ChainItem<XmlCRS> verifyRevocationData(ChainItem<XmlCRS> item, CertificateRevocationWrapper revocationWrapper) {
        item = super.verifyRevocationData(item, revocationWrapper);

        Boolean validity = revocationDataValidityMap.get(revocationWrapper);
        if (validity) {
            item = item.setNextItem(revocationIssuedBeforeControlTime(revocationWrapper, currentTime));

            validity = revocationWrapper.getThisUpdate() != null && revocationWrapper.getThisUpdate().before(currentTime);

            if (validity) {

                item = item.setNextItem(poeExistsAtOrBeforeControlTime(certificate, TimestampedObjectType.CERTIFICATE, currentTime));

                item = item.setNextItem(poeExistsAtOrBeforeControlTime(revocationWrapper, TimestampedObjectType.REVOCATION, currentTime));

                validity = poe.isPOEExists(certificate.getId(), currentTime) && poe.isPOEExists(revocationWrapper.getId(), currentTime);

            }

            // update the validity map
            revocationDataValidityMap.put(revocationWrapper, validity);
        }

        return item;
    }

    private ChainItem<XmlCRS> revocationIssuedBeforeControlTime(RevocationWrapper revocation, Date controlTime) {
        return new RevocationIssuedBeforeControlTimeCheck(i18nProvider, result, revocation, controlTime, getWarnLevelConstraint());
    }

    private ChainItem<XmlCRS> poeExistsAtOrBeforeControlTime(TokenProxy token, TimestampedObjectType objectType, Date controlTime) {
        return new POEExistsAtOrBeforeControlTimeCheck(i18nProvider, result, token, objectType, controlTime, poe, getWarnLevelConstraint());
    }

}
