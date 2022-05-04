package eu.europa.esig.dss.signature.resources;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Abstract class used to create OutputStream to be used across DSS code
 *
 */
public abstract class AbstractResourcesHandler implements DSSResourcesHandler {

    /** OutputStream instance */
    private OutputStream os;

    @Override
    public OutputStream createOutputStream() throws IOException {
        if (os != null) {
            throw new IllegalStateException("Cannot create OutputStream! The OutputStream has been already created!");
        }
        this.os = buildOutputStream();
        return os;
    }

    /**
     * Builds {@code OutputStream}
     *
     * @return {@link OutputStream}
     * @throws IOException if an error occurs while building OutputStream
     */
    protected abstract OutputStream buildOutputStream() throws IOException;

    /**
     * This method returns the internal OutputStream instance
     *
     * @return {@link OutputStream}
     */
    protected OutputStream getOutputStream() {
        if (os == null) {
            throw new IllegalStateException("Method #createOutputStream() shall be called before!");
        }
        return os;
    }

    @Override
    public void close() throws IOException {
        if (os != null) {
            os.close();
        }
    }

}
