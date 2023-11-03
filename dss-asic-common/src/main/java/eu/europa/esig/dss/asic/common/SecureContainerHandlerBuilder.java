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
package eu.europa.esig.dss.asic.common;

/**
 * Default implementation of a builder,
 * building a new instance of {@code eu.europa.esig.dss.asic.common.SecureContainerHandler}
 *
 */
public class SecureContainerHandlerBuilder implements ZipContainerHandlerBuilder<SecureContainerHandler> {

    /**
     * Minimum file size to be analyzed on zip bombing
     */
    private long threshold = 1000000; // 1 MB

    /**
     * Maximum compression ratio.
     */
    private long maxCompressionRatio = 100;

    /**
     * Defines the maximal amount of files that can be inside a ZIP container
     */
    private int maxAllowedFilesAmount = 1000;

    /**
     * Max iteration over the zip entries
     */
    private int maxMalformedFiles = 100;

    /**
     * Defines whether comments of ZIP entries shall be extracted.
     * Default : false (not extracted)
     */
    private boolean extractComments = false;

    /**
     * Sets the maximum allowed threshold after exceeding each the security checks
     * are enforced
     * <p>
     * Default : 1000000 (1 MB)
     *
     * @param threshold in bytes
     * @return {@link SecureContainerHandlerBuilder}
     */
    public SecureContainerHandlerBuilder setThreshold(long threshold) {
        this.threshold = threshold;
        return this;
    }

    /**
     * Sets the maximum allowed compression ratio If the container compression ratio
     * exceeds the value, an exception is being thrown
     * <p>
     * Default : 100
     *
     * @param maxCompressionRatio the maximum compression ratio
     * @return {@link SecureContainerHandlerBuilder}
     */
    public SecureContainerHandlerBuilder setMaxCompressionRatio(long maxCompressionRatio) {
        this.maxCompressionRatio = maxCompressionRatio;
        return this;
    }

    /**
     * Sets the maximum allowed amount of files inside a container
     * <p>
     * Default : 1000
     *
     * @param maxAllowedFilesAmount the maximum number of allowed files
     * @return {@link SecureContainerHandlerBuilder}
     */
    public SecureContainerHandlerBuilder setMaxAllowedFilesAmount(int maxAllowedFilesAmount) {
        this.maxAllowedFilesAmount = maxAllowedFilesAmount;
        return this;
    }

    /**
     * Sets the maximum allowed amount of malformed files
     * <p>
     * Default : 100
     *
     * @param maxMalformedFiles the maximum number of malformed files
     * @return {@link SecureContainerHandlerBuilder}
     */
    public SecureContainerHandlerBuilder setMaxMalformedFiles(int maxMalformedFiles) {
        this.maxMalformedFiles = maxMalformedFiles;
        return this;
    }

    /**
     * Sets whether comments of ZIP entries shall be extracted.
     * <p>
     * Enabling of the feature can be useful when editing an existing archive,
     * in order to preserve the existing data (i.e. comments).
     * When enabled, slightly decreases the performance (about 10% for {@code extractContainerContent(zipArchive)} method).
     * <p>
     * Reason : All ZIP entries from a ZIP archive are extracted using {@code java.util.zip.ZipInputStream},
     * that is not able to extract comments for entries. In order to extract comments, the archive shall be read
     * again using {@code java.util.zip.ZipFile}.
     * For more information about limitations please see {@code <a href="https://stackoverflow.com/a/70848140">the link</a>}.
     * <p>
     * Default : false (not extracted)
     *
     * @param extractComments whether comments shall be extracted
     * @return {@link SecureContainerHandlerBuilder}
     */
    public SecureContainerHandlerBuilder setExtractComments(boolean extractComments) {
        this.extractComments = extractComments;
        return this;
    }

    @Override
    public SecureContainerHandler build() {
        final SecureContainerHandler secureContainerHandler = new SecureContainerHandler();
        secureContainerHandler.setThreshold(threshold);
        secureContainerHandler.setMaxCompressionRatio(maxCompressionRatio);
        secureContainerHandler.setMaxAllowedFilesAmount(maxAllowedFilesAmount);
        secureContainerHandler.setMaxMalformedFiles(maxMalformedFiles);
        secureContainerHandler.setExtractComments(extractComments);
        return secureContainerHandler;
    }

}
