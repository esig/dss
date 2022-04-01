package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.IOException;
import java.io.OutputStream;

/**
 * This class is used to create objects required for a document signing process
 * (e.g. temporary OutputStream, returned DSSDocument, etc.).
 *
 */
public interface DSSResourcesFactory {

    /**
     * This method creates a new {@code OutputStream} to be used as an output for
     * a temporary signature document
     *
     * @return {@link OutputStream}
     * @throws IOException if an exception occurs during OutputStream creation
     */
    OutputStream createOutputStream() throws IOException;

    /**
     * This method creates a new {@code DSSDocument} representing a signed document,
     * based on the obtained {@code OutputStream}.
     *
     * @param os {@link OutputStream} containing a signed document
     * @return {@link DSSDocument}
     * @throws IOException if an exception occurs during DSSDocument creation
     */
    DSSDocument toDSSDocument(OutputStream os) throws IOException;

}
