package eu.europa.esig.dss.model.identifier;

import java.io.Serializable;

/**
 * Builds a {@code eu.europa.esig.dss.model.identifier.Identifier}
 *
 */
public interface IdentifierBuilder extends Serializable {

    /**
     * Builds {@code Identifier}
     *
     * @return {@link Identifier}
     */
    Identifier build();

}
