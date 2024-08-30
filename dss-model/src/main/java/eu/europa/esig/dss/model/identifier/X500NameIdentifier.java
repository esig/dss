package eu.europa.esig.dss.model.identifier;

import javax.security.auth.x500.X500Principal;

/**
 * This class is used to create a unique identifier for a Relative Distinguished Name (RDN)
 *
 */
public class X500NameIdentifier extends Identifier {

    /**
     * Default constructor with an X500Principal
     *
     * @param x500Principal {@link X500Principal}
     */
    public X500NameIdentifier(final X500Principal x500Principal) {
        super("RDN-", x500Principal.getEncoded());
    }

}
