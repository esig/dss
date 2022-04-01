package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * This class represents an in-memory implementation of {@code DSSResourcesFactory}.
 * Using this class, all the objects handling during document signing will be stored in memory.
 *
 * NOTE: this class is used as a default implementation in DSS
 */
public class InMemoryResourcesFactory implements DSSResourcesFactory {

    @Override
    public OutputStream createOutputStream() {
        return new ByteArrayOutputStream();
    }

    @Override
    public DSSDocument toDSSDocument(OutputStream os) {
        Objects.requireNonNull(os, "OutputStream shall be provided!");
        if (!(os instanceof ByteArrayOutputStream)) {
            throw new UnsupportedOperationException(String.format(
                    "Unable to create a DSSDocument using an OutputStream of class '%s'!", os.getClass()));
        }
        return new InMemoryDocument(((ByteArrayOutputStream)os).toByteArray());
    }

}
