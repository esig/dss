package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;

import java.util.Collections;
import java.util.List;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint} into a {@code eu.europa.esig.dss.model.policy.MultiValuesRule}
 *
 */
public class MultiValuesConstraintWrapper extends LevelConstraintWrapper implements MultiValuesRule {

    /**
     * Default constructor
     *
     * @param constraint {@link MultiValuesConstraint}
     */
    public MultiValuesConstraintWrapper(final MultiValuesConstraint constraint) {
        super(constraint);
    }

    @Override
    public List<String> getValues() {
        return constraint != null ? ((MultiValuesConstraint) constraint).getId() : Collections.emptyList();
    }

}
