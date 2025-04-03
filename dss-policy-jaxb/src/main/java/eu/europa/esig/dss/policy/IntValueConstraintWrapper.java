package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.policy.NumericValueRule;
import eu.europa.esig.dss.policy.jaxb.IntValueConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.IntValueConstraint} into a {@code eu.europa.esig.dss.model.policy.NumericValueRule}
 *
 */
public class IntValueConstraintWrapper extends LevelConstraintWrapper implements NumericValueRule {

    /**
     * Default constructor
     *
     * @param constraint {@link IntValueConstraint}
     */
    public IntValueConstraintWrapper(final IntValueConstraint constraint) {
        super(constraint);
    }

    @Override
    public Number getValue() {
        return constraint != null ? ((IntValueConstraint) constraint).getValue() : null;
    }

}
