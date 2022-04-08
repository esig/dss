package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * This class represents an in-memory implementation of {@code DSSResourcesFactory}.
 * Using this class, all the objects handling during document signing will be stored in memory.
 *
 * NOTE: this class is used as a default implementation in DSS
 */
public class InMemoryResourcesHandler extends AbstractResourcesHandler<ByteArrayOutputStream> {

    @Override
    protected ByteArrayOutputStream buildOutputStream() throws IOException {
        return new ByteArrayOutputStream();
    }

    @Override
    public DSSDocument writeToDSSDocument() throws IOException {
        try (ByteArrayOutputStream baos = getOutputStream()) {
            return new InMemoryDocument(baos.toByteArray());
        }
    }

}
