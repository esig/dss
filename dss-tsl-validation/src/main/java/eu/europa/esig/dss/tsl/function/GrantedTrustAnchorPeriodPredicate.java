package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;

/**
 * This class verifies whether a corresponding ServiceInformation or ServiceHistoryInstance has a granted status
 * (before and after eIDAS)
 *
 */
public class GrantedTrustAnchorPeriodPredicate implements TrustAnchorPeriodPredicate {

    /**
     * Default constructor
     */
    public GrantedTrustAnchorPeriodPredicate() {
        // empty
    }

    @Override
    public boolean test(TrustServiceStatusAndInformationExtensions trustServiceStatusAndInformationExtensions) {
        return trustServiceStatusAndInformationExtensions != null &&
                (TrustServiceStatus.isAcceptableStatusAfterEIDAS(trustServiceStatusAndInformationExtensions.getStatus())
                    || TrustServiceStatus.isAcceptableStatusBeforeEIDAS(trustServiceStatusAndInformationExtensions.getStatus()));
    }

}
