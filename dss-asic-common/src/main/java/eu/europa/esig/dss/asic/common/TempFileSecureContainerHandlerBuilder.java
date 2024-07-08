package eu.europa.esig.dss.asic.common;

/**
 * This class is used to build a {@code TempFileSecureContainerHandler} instance in order to process a ZIP archive
 * using a temporary file, instead of in-memory handling.
 *
 */
public class TempFileSecureContainerHandlerBuilder extends SecureContainerHandlerBuilder {

    /**
     * Default constructor
     */
    public TempFileSecureContainerHandlerBuilder() {
        // empty
    }

    @Override
    public SecureContainerHandler build() {
        return new TempFileSecureContainerHandler();
    }

}
