/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.signature.resources;

import eu.europa.esig.dss.model.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * This class creates a {@code TempFileResourcesHandlerBuilder} storing temporary objects to temporary filesystem documents
 */
public class TempFileResourcesHandlerBuilder implements DSSResourcesHandlerBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(TempFileResourcesHandlerBuilder.class);

    /** The default prefix of a temporary created file */
    private final static String DEFAULT_PREFIX = "dss-";

    /** The default suffix of a temporary created file */
    private final static String DEFAULT_SUFFIX = ".tmp";

    /** Cached list of created handlers by the current builder */
    private final List<TempFileResourcesHandler> handlers = new ArrayList<>();

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
                if (LOG.isDebugEnabled()) {
                    LOG.debug("An occurred when trying to create a directory '{}'", tempFileDirectory.getAbsolutePath());
                }
                throw new DSSException(String.format("Unable to create TempFileResourcesHandler for a file with name '%s'!",
                        tempFileDirectory.getName()));
            }
        }
        TempFileResourcesHandler handler = new TempFileResourcesHandler(fileNamePrefix, fileNameSuffix, tempFileDirectory);
        handlers.add(handler);
        return handler;
    }

    /**
     * This method is used to remove all handlers created by the current builder,
     * as well as temporary files from the filesystem. This method is not executed in a normal DSS operating,
     * and should be called on user's side when the temporary files are no longer needed.
     *
     * NOTE: do not forget to preserve the output documents, such as a FileDocument returned by a
     *       {@code #signDocument()} method.
     */
    public void clear() {
        for (TempFileResourcesHandler handler : handlers) {
            handler.forceDelete();
        }
        handlers.clear();
    }

}
