package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.enumerations.Level;

/**
 * Validation Policy execution condition
 *
 */
public interface LevelRule {

    /**
     * Gets the constraint execution level
     *
     * @return {@link Level}
     */
    Level getLevel();

}
