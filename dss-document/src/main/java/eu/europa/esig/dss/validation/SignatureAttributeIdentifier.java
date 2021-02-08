package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.Identifier;

/**
 * Identifies uniquely an unsigned attribute of a signature
 */
public class SignatureAttributeIdentifier extends Identifier {

    /**
     * Default constructor
     *
     * @param data byte array to compute the identifier
     */
    protected SignatureAttributeIdentifier(byte[] data) {
        super("SA-", data);
    }

}
