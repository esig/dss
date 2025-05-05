package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.policy.CertificateApplicabilityRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.CertificateValuesConstraint} into a {@code eu.europa.esig.dss.model.policy.CertificateApplicabilityRule}
 *
 */
public class CertificateValuesConstraintWrapper extends LevelConstraintWrapper implements CertificateApplicabilityRule {

    /**
     * Default constructor
     *
     * @param constraint {@link CertificateValuesConstraint}
     */
    public CertificateValuesConstraintWrapper(final CertificateValuesConstraint constraint) {
        super(constraint);
    }

    @Override
    public MultiValuesRule getCertificateExtensions() {
        return new MultiValuesConstraintWrapper(((CertificateValuesConstraint) constraint).getCertificateExtensions());
    }

    @Override
    public MultiValuesRule getCertificatePolicies() {
        return new MultiValuesConstraintWrapper(((CertificateValuesConstraint) constraint).getCertificatePolicies());
    }

}
