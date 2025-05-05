package eu.europa.esig.dss.model.policy;

/**
 * Defines a numeric value for an execution check applicability rules
 *
 */
public interface NumericValueRule extends LevelRule {

    /**
     * Gets a numeric value of the condition rule
     *
     * @return {@link Number}
     */
    Number getValue();

}
