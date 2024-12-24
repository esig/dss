/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
