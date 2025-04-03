package eu.europa.esig.dss.model.policy;

/**
 * Defines a String value for an execution check applicability rules
 *
 */
public interface ValueRule extends LevelRule {

    /**
     * Gets a value satisfying the condition
     *
     * @return {@link String}
     */
    String getValue();

}
