package eu.europa.esig.dss.policy;

import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

/**
 * Wraps {@code eu.europa.esig.dss.policy.jaxb.LevelConstraint} into a {@code eu.europa.esig.dss.model.policy.LevelRule}
 *
 */
public class LevelConstraintWrapper implements LevelRule {

    /** The constraint containing the behavior rules for the corresponding check execution */
    protected final LevelConstraint constraint;

    /**
     * Default constructor
     *
     * @param constraint {@link CryptographicConstraint}
     */
    public LevelConstraintWrapper(final LevelConstraint constraint) {
        this.constraint = constraint;
    }

    @Override
    public Level getLevel() {
        if (constraint != null) {
            return constraint.getLevel();
        }
        return null;
    }

    /**
     * Gets the original constraint
     *
     * @return {@link LevelConstraint}
     */
    public LevelConstraint getConstraint() {
        return constraint;
    }

}
