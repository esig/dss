package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.model.identifier.Identifier;

/**
 * Identifies uniquely an unsigned attribute of a signature
 */
public class SignatureAttributeIdentifier extends Identifier {

    private static final long serialVersionUID = -137902040976540872L;

    /**
     * Default constructor
     *
     * @param data byte array to compute the identifier
     */
    protected SignatureAttributeIdentifier(byte[] data) {
        super("SA-", data);
    }

}
