package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.policy.DurationRule;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.TimeConstraint} into a {@code eu.europa.esig.dss.model.policy.DurationRule}
 *
 */
public class TimeConstraintWrapper extends LevelConstraintWrapper implements DurationRule {

    /**
     * Default constructor
     *
     * @param constraint {@link TimeConstraint}
     */
    public TimeConstraintWrapper(final TimeConstraint constraint) {
        super(constraint);
    }

    @Override
    public long getDuration() {
        return constraint != null ? RuleUtils.convertDuration((TimeConstraint) constraint) : 0;
    }

}
