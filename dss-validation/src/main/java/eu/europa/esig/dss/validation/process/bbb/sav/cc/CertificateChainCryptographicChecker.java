package eu.europa.esig.dss.validation.process.bbb.sav.cc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlCC;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.validation.process.Chain;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CryptographicCheckerResultCheck;

import java.util.Date;
import java.util.List;

public class CertificateChainCryptographicChecker extends Chain<XmlCC> {

    /** The signing-certificate */
    private final CertificateWrapper signingCertificate;

    /** The certificate chain */
    private final List<CertificateWrapper> certificateChain;

    /** Time of the validation */
    private final Date validationTime;

    /** Validation context */
    private final Context context;

    /** Position of the token being validated */
    private final MessageTag position;

    /** Validation policy to be used */
    private final ValidationPolicy validationPolicy;

    /** Cached copy of the validation result */
    private XmlCC ccResult;

    /**
     * Common constructor
     *
     * @param i18nProvider the access to translations
     */
    public CertificateChainCryptographicChecker(final I18nProvider i18nProvider, final CertificateWrapper signingCertificate,
                                                final List<CertificateWrapper> certificateChain, final Date validationTime,
                                                final Context context, final MessageTag position, final ValidationPolicy validationPolicy) {
        super(i18nProvider, new XmlCC());
        this.signingCertificate = signingCertificate;
        this.certificateChain = certificateChain;
        this.validationTime = validationTime;
        this.context = context;
        this.position = position;
        this.validationPolicy = validationPolicy;
    }

    @Override
    protected void initChain() {
        ChainItem<XmlCC> item = null;

        for (CertificateWrapper certificate : certificateChain) {
            if (certificate.isTrusted()) {
                break;
            }

            SubContext subContext = signingCertificate.getId().equals(certificate.getId()) ? SubContext.SIGNING_CERT : SubContext.CA_CERTIFICATE;
            CryptographicConstraint constraint = validationPolicy.getCertificateCryptographicConstraint(context, subContext);

            CryptographicChecker cc = new CryptographicChecker(i18nProvider, certificate, validationTime, position, constraint);
            XmlCC xmlCC = cc.execute();

            ChainItem<XmlCC> certCryptoValidation = tokenUsedAlgorithmsAreSecureAtTime(validationTime, position, xmlCC, constraint);
            if (item == null) {
                firstItem = item = certCryptoValidation;
            } else {
                item = item.setNextItem(certCryptoValidation);
            }

            if (ccResult == null || !isValid(xmlCC)) {
                ccResult = xmlCC;
            }
        }
    }

    private ChainItem<XmlCC> tokenUsedAlgorithmsAreSecureAtTime(Date validationDate, MessageTag position, XmlCC cc,
                                                                CryptographicConstraint constraint) {
        return new CryptographicCheckerResultCheck<>(i18nProvider, result, validationDate, position, cc, constraint);
    }

    @Override
    protected void addAdditionalInfo() {
        super.addAdditionalInfo();
        if (ccResult != null) {
            result.setVerifiedAlgorithm(ccResult.getVerifiedAlgorithm());
            result.setNotAfter(ccResult.getNotAfter());
        }
    }

}
