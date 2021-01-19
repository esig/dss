package eu.europa.esig.dss.model.identifier;

/**
 * Defines the object having an identifier (e.g. AdvancedSignature, Token, etc.)
 */
public interface IdentifierBasedObject {

    /**
     * Returns the {@code Identifier} of the object
     *
     * @return {@link Identifier}
     */
    Identifier getDSSId();

}
