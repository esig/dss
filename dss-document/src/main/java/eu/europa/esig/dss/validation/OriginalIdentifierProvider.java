package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.IdentifierBasedObject;

/**
 * Returns the original hash-based calculated {@code java.lang.String} identifier for the given token
 */
public class OriginalIdentifierProvider implements TokenIdentifierProvider {

    @Override
    public String getIdAsString(IdentifierBasedObject object) {
        return object.getDSSId().asXmlId();
    }

}
