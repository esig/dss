package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSException;

import java.io.File;

/**
 * This class creates a {@code TempFileResourcesHandlerBuilder} storing temporary objects to temporary filesystem documents
 */
public class TempFileResourcesHandlerBuilder implements DSSResourcesHandlerBuilder {

    /** The default prefix of a temporary created file */
    private final static String DEFAULT_PREFIX = "dss-";

    /** The default suffix of a temporary created file */
    private final static String DEFAULT_SUFFIX = ".tmp";

    /**
     * The prefix (beginning) of a filename to be used for created documents
     *
     * Default : "dss-"
     */
    private String fileNamePrefix = DEFAULT_PREFIX;

    /**
     * The suffix (ending/extension) of a filename to be used for created documents
     *
     * Default : ".tmp"
     */
    private String fileNameSuffix = DEFAULT_SUFFIX;

    /**
     * The directory containing created documents.
     *
     * Default : temporary system-dependent location
     */
    private File tempFileDirectory = new File(System.getProperty("java.io.tmpdir"));

    /**
     * Sets the filename prefix (beginning) for created temporary documents
     *
     * Default : "dss-"
     *
     * @param fileNamePrefix {@link String}
     * @return {@link TempFileResourcesHandlerBuilder} this builder
     */
    public TempFileResourcesHandlerBuilder setFileNamePrefix(String fileNamePrefix) {
        this.fileNamePrefix = fileNamePrefix;
        return this;
    }

    /**
     * Sets the filename suffix (ending/extension) for created temporary documents
     *
     * Default : ".tmp"
     *
     * @param fileNameSuffix {@link String}
     * @return {@link TempFileResourcesHandlerBuilder} this builder
     */
    public TempFileResourcesHandlerBuilder setFileNameSuffix(String fileNameSuffix) {
        this.fileNameSuffix = fileNameSuffix;
        return this;
    }

    /**
     * Sets a file directory to be used for staring created documents
     *
     * Default : temporary system-dependent location
     *
     * @param tempFileDirectory {@link File} representing a directory for storing the temporary files
     * @return {@link TempFileResourcesHandlerBuilder} this builder
     */
    public TempFileResourcesHandlerBuilder setTempFileDirectory(File tempFileDirectory) {
        this.tempFileDirectory = tempFileDirectory;
        return this;
    }

    @Override
    public TempFileResourcesHandler createResourcesHandler() {
        if (!tempFileDirectory.exists()) {
            boolean dirCreated = tempFileDirectory.mkdirs();
            if (!dirCreated) {
                throw new DSSException(String.format("Unable to create a new directory '%s'!", tempFileDirectory.getPath()));
            }
        }
        return new TempFileResourcesHandler(fileNamePrefix, fileNameSuffix, tempFileDirectory);
    }

}
