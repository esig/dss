package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This class represents an in-memory implementation of {@code DSSResourcesFactory}.
 * Using this class, all the objects handling during document signing will be stored in memory.
 *
 * NOTE: this class is used as a default implementation in DSS
 */
public class InMemoryResourcesHandler extends AbstractResourcesHandler {

    @Override
    protected ByteArrayOutputStream buildOutputStream() throws IOException {
        return new ByteArrayOutputStream();
    }

    @Override
    public DSSDocument writeToDSSDocument() throws IOException {
        try (OutputStream os = getOutputStream()) {
            if (!(os instanceof ByteArrayOutputStream)) {
                throw new IllegalStateException("The OutputStream shall be an implementation of ByteArrayOutputStream class!");
            }
            return new InMemoryDocument(((ByteArrayOutputStream) os).toByteArray());
        }
    }

}
