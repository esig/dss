package eu.europa.esig.dss.model.policy;

/**
 * Contains certificate properties for execution checks applicability rules
 *
 */
public interface CertificateApplicabilityRule extends LevelRule {

    /**
     * Returns a list of certificate extensions satisfying the condition
     *
     * @return {@link MultiValuesRule}
     */
    MultiValuesRule getCertificateExtensions();

    /**
     * Returns a list of certificate policies satisfying the condition
     *
     * @return {@link MultiValuesRule}
     */
    MultiValuesRule getCertificatePolicies();

}
