package eu.europa.esig.dss.model.policy;

/**
 * Defines time-dependent execution check applicability rules
 *
 */
public interface DurationRule extends LevelRule {

    /**
     * Gets the duration period in milliseconds
     *
     * @return duration period in milliseconds
     */
    long getDuration();

}
