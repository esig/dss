package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Date;

/**
 * This class verifies whether a validation time is before certificate's trust sunset date, with a certificate id provided
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CertificateValidationBeforeSunsetDateWithIdCheck<T extends XmlConstraintsConclusion> extends CertificateValidationBeforeSunsetDateCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateValidationBeforeSunsetDateWithIdCheck(I18nProvider i18nProvider, T result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, certificate, controlTime, constraint, certificate.getId());
    }

}
