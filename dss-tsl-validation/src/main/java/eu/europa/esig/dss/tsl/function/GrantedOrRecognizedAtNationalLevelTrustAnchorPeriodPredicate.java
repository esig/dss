package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;

/**
 * Verifies whether the given ServiceInformation or ServiceHistoryInstance has a granted status (before and after eIDAS)
 * or recognized or valid at national level
 *
 */
public class GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate implements TrustAnchorPeriodPredicate {

    /**
     * Default constructor
     */
    public GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate() {
        // empty
    }

    @Override
    public boolean test(TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformationExtensions) {
        return trustServiceStatusAndInformationExtensions != null &&
                (TrustServiceStatus.isAcceptableStatusAfterEIDAS(trustServiceStatusAndInformationExtensions.getStatus())
                        || TrustServiceStatus.isAcceptableStatusBeforeEIDAS(trustServiceStatusAndInformationExtensions.getStatus())
                        || TrustServiceStatus.isSetByNationalLawAfterEIDAS(trustServiceStatusAndInformationExtensions.getStatus())
                        || TrustServiceStatus.isRecognizedAtNationalLevelAfterEIDAS(trustServiceStatusAndInformationExtensions.getStatus()));
    }

}
