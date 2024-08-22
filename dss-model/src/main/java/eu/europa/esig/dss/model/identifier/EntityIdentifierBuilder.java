package eu.europa.esig.dss.model.identifier;

import eu.europa.esig.dss.model.DSSException;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;

/**
 * Builds a {@code eu.europa.esig.dss.model.identifier.EntityIdentifier} for
 * the given {@code java.security.PublicKey} and {@code javax.security.auth.x500.X500Principal} pair
 *
 */
public class EntityIdentifierBuilder implements IdentifierBuilder {

    /** Public key */
    private final PublicKey publicKey;

    /** Subject name */
    private final X500Principal subjectName;

    /**
     * Default constructor
     *
     * @param publicKey {@link PublicKey}
     * @param subjectName {@link X500Principal}
     */
    public EntityIdentifierBuilder(final PublicKey publicKey, final X500Principal subjectName) {
        this.publicKey = publicKey;
        this.subjectName = subjectName;
    }

    @Override
    public EntityIdentifier build() {
        return new EntityIdentifier(buildBinaries());
    }

    /**
     * Builds unique binary data describing the signature object
     *
     * @return a byte array
     */
    protected byte[] buildBinaries() {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            if (publicKey != null) {
                baos.write(publicKey.getEncoded());
            }
            if (subjectName != null) {
                baos.write(subjectName.getEncoded());
            }
            return baos.toByteArray();

        } catch (IOException e) {
            throw new DSSException(String.format("An error occurred while building an Identifier : %s", e.getMessage()), e);
        }
    }

}
