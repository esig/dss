package eu.europa.esig.dss.validation.process.bbb.xcv.crs;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCRS;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.RevocationAcceptanceChecker;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.RevocationAcceptanceCheckerResultCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.AcceptableRevocationDataAvailableCheck;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * This class validates revocation data for a given certificate and returns the latest valid entry
 *
 */
public class CertificateRevocationSelector extends Chain<XmlCRS> {

    /** Certificate to get a latest valid revocation data for */
    private final CertificateWrapper certificate;

    /** Validation time */
    private final Date currentTime;

    /** Validation context */
    private final Context context;

    /** Validation subContext */
    private final SubContext subContext;

    /** Validation policy */
    private final ValidationPolicy validationPolicy;

    /** The latest acceptable certificate revocation, to be returned after the selector execution */
    private CertificateRevocationWrapper latestCertificateRevocation;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param certificate {@link CertificateWrapper}
     * @param currentTime {@link Date} validation time
     * @param context {@link Context}
     * @param subContext {@link SubContext}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public CertificateRevocationSelector(I18nProvider i18nProvider, CertificateWrapper certificate, Date currentTime,
                                         Context context, SubContext subContext, ValidationPolicy validationPolicy) {
        super(i18nProvider, new XmlCRS());
        this.certificate = certificate;
        this.currentTime = currentTime;
        this.context = context;
        this.subContext = subContext;
        this.validationPolicy = validationPolicy;
    }

    @Override
    protected void initChain() {
        ChainItem<XmlCRS> item = null;

        Map<CertificateRevocationWrapper, XmlRAC> revocationAcceptanceResultMap = getRevocationAcceptanceResult(certificate);
        for (Map.Entry<CertificateRevocationWrapper, XmlRAC> revocationAcceptanceResult : revocationAcceptanceResultMap.entrySet()) {
            CertificateRevocationWrapper currentRevocation = revocationAcceptanceResult.getKey();
            XmlRAC currentRAC = revocationAcceptanceResult.getValue();

            result.getRAC().add(currentRAC);

            if (item == null) {
                item = firstItem = item.setNextItem(revocationAcceptable(currentRAC));
            } else {
                item = item.setNextItem(revocationAcceptable(currentRAC));
            }

            if (isValid(currentRAC) &&
                    (latestCertificateRevocation == null || currentRevocation.getProductionDate().after(latestCertificateRevocation.getProductionDate()))) {
                latestCertificateRevocation = currentRevocation;
            }
        }

        if (item == null) {
            item = firstItem = item.setNextItem(acceptableRevocationDataAvailable(latestCertificateRevocation));
        } else {
            item = item.setNextItem(acceptableRevocationDataAvailable(latestCertificateRevocation));
        }
    }

    /**
     * This method returns the latest acceptable certificate revocation data
     *
     * NOTE: method {@code execute()} shall be called before
     *
     * @return {@link CertificateRevocationWrapper}
     */
    public CertificateRevocationWrapper getLatestAcceptableCertificateRevocation() {
        return latestCertificateRevocation;
    }

    private Map<CertificateRevocationWrapper, XmlRAC> getRevocationAcceptanceResult(CertificateWrapper certificate) {
        Map<CertificateRevocationWrapper, XmlRAC> revocationAcceptanceResultMap = new HashMap<>();

        for (CertificateRevocationWrapper revocationWrapper : certificate.getCertificateRevocationData()) {
            RevocationAcceptanceChecker rac = new RevocationAcceptanceChecker(i18nProvider, certificate, revocationWrapper, currentTime, validationPolicy);
            XmlRAC racResult = rac.execute();
            revocationAcceptanceResultMap.put(revocationWrapper, racResult);
        }

        return revocationAcceptanceResultMap;
    }

    private ChainItem<XmlCRS> revocationAcceptable(XmlRAC racResult) {
        return new RevocationAcceptanceCheckerResultCheck<>(i18nProvider, result, racResult, getWarnLevelConstraint());
    }

    private ChainItem<XmlCRS> acceptableRevocationDataAvailable(RevocationWrapper revocationData) {
        LevelConstraint constraint = validationPolicy.getRevocationDataAvailableConstraint(context, subContext);
        return new AcceptableRevocationDataAvailableCheck<>(i18nProvider, result, certificate, revocationData, constraint);
    }

}
