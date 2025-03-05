package eu.europa.esig.dss.validation.process.vpfltvd.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Date;

/**
 * This check returns information whether the signing-certificate is known to not be revoked and revocation data is acceptable,
 * but always returns the Basic Signature Validation conclusion.
 *
 */
public class CertificateKnownToBeNotRevokedEnforceFailCheck extends CertificateKnownToBeNotRevokedCheck<XmlValidationProcessLongTermData> {

    /**
     * Default constructor
     *
     * @param i18nProvider                  {@link I18nProvider}
     * @param result                        {@link XmlConstraintsConclusion}
     * @param certificate                   {@link CertificateWrapper}
     * @param revocationData                {@link CertificateRevocationWrapper}
     * @param isRevocationDataIssuerTrusted whether the revocation issuer is trusted
     * @param currentTime                   {@link Date}
     * @param bsConclusion                  {@link XmlConclusion}
     * @param constraint                    {@link LevelConstraint}
     */
    public CertificateKnownToBeNotRevokedEnforceFailCheck(I18nProvider i18nProvider,
            XmlValidationProcessLongTermData result, CertificateWrapper certificate, CertificateRevocationWrapper revocationData,
            boolean isRevocationDataIssuerTrusted, Date currentTime, XmlConclusion bsConclusion, LevelConstraint constraint) {
        super(i18nProvider, result, certificate, revocationData, isRevocationDataIssuerTrusted, currentTime, bsConclusion, constraint);
    }

    @Override
    protected boolean process() {
        return false;
    }

}
