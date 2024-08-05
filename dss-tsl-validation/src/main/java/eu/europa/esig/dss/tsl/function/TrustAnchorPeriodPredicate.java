package eu.europa.esig.dss.tsl.function;

import eu.europa.esig.dss.model.tsl.TrustServiceStatusAndInformationExtensions;

import java.util.function.Predicate;

/**
 * This interface is used to verify an acceptance of an SDI as a trust anchor during the period of time covered
 * by a provided {@code TrustServiceStatusAndInformationExtensions}
 *
 */
public interface TrustAnchorPeriodPredicate extends Predicate<TrustServiceStatusAndInformationExtensions> {
}
