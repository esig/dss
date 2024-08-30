package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;
import eu.europa.esig.dss.validation.process.qualification.trust.TrustServiceStatus;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GrantedTrustAnchorPeriodPredicateTest {

    @Test
    void test() {
        TrustServiceStatusAndInformationExtensions trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.GRANTED.getUri()).build();
        assertTrue(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.WITHDRAWN.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.SET_BY_NATIONAL_LAW.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.RECONIZED_AT_NATIONAL_LEVEL.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.DEPRECATED_BY_NATIONAL_LAW.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.DEPRECATED_AT_NATIONAL_LEVEL.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.UNDER_SUPERVISION.getUri()).build();
        assertTrue(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.SUPERVISION_OF_SERVICE_IN_CESSATION.getUri()).build();
        assertTrue(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.SUPERVISION_CEASED.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.SUPERVISION_REVOKED.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.ACCREDITED.getUri()).build();
        assertTrue(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.ACCREDITATION_CEASED.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));

        trustServiceStatus = new TrustServiceStatusAndInformationExtensions
                .TrustServiceStatusAndInformationExtensionsBuilder().setStatus(TrustServiceStatus.ACCREDITATION_REVOKED.getUri()).build();
        assertFalse(new GrantedTrustAnchorPeriodPredicate().test(trustServiceStatus));
    }

}
