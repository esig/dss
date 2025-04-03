package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.policy.ValueRule;
import eu.europa.esig.dss.policy.jaxb.ValueConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.ValueConstraint} into a {@code eu.europa.esig.dss.model.policy.ValueRule}
 *
 */
public class ValueConstraintWrapper extends LevelConstraintWrapper implements ValueRule {

    /**
     * Default constructor
     *
     * @param constraint {@link ValueConstraint}
     */
    public ValueConstraintWrapper(final ValueConstraint constraint) {
        super(constraint);
    }

    @Override
    public String getValue() {
        return constraint != null ? ((ValueConstraint) constraint).getValue() : null;
    }

}
