package eu.europa.esig.dss.model.identifier;

import java.security.Key;

/**
 * This class creates a unique identifier for a {@code java.security.Key} object
 *
 */
public final class KeyIdentifier extends Identifier {

    /**
     * Default constructor with a key
     *
     * @param key {@link Key}
     */
    public KeyIdentifier(final Key key) {
        super("PK-", key.getEncoded());
    }

}
