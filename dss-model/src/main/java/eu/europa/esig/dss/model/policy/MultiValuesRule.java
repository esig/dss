package eu.europa.esig.dss.model.policy;

import java.util.List;

/**
 * Defines a list of values for an execution check applicability rules
 *
 */
public interface MultiValuesRule extends LevelRule {

    /**
     * Returns a list of values satisfying the condition
     *
     * @return a list of {@link String}s
     */
    List<String> getValues();

}
