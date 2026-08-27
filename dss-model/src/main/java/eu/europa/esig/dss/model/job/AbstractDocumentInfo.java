/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.job;

import eu.europa.esig.dss.model.identifier.Identifier;

import java.io.Serializable;
import java.util.Objects;

/**
 * Abstract representation of a document validation result,
 * containing information abour the downoad, parsing and validation statuses.
 *
 * @param <P> {@link DocumentInfo}
 */
public abstract class AbstractDocumentInfo<P extends DocumentInfo> implements DocumentInfo, Serializable {

    private static final long serialVersionUID = -5439324653080984894L;

    /** Address of the source */
    private final String url;

    /** The parent LOTL/TL referencing the current Trusted List */
    private final P parent;

    /** The download result record */
    private final DownloadInfoRecord downloadCacheInfo;

    /** The parsing result record */
    private final ParsingInfoRecord parsingCacheInfo;

    /** The validation result record */
    private final ValidationInfoRecord validationCacheInfo;

    /** Cached Identifier instance */
    private Identifier identifier;

    /**
     * The default constructor
     *
     * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
     * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
     * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
     * @param url {@link String} address used to extract the entry
     */
    protected AbstractDocumentInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo,
                                final ValidationInfoRecord validationCacheInfo, final String url) {
        this(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, null);
    }

    /**
     * The default constructor with parent TLInfo
     *
     * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
     * @param parsingCacheInfo {@link ParsingInfoRecord} a parsing cache result
     * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
     * @param url {@link String} address used to extract the entry
     * @param parent {@link DocumentInfo} referencing the current Trusted List
     */
    protected AbstractDocumentInfo(final DownloadInfoRecord downloadCacheInfo, final ParsingInfoRecord parsingCacheInfo,
                                final ValidationInfoRecord validationCacheInfo, final String url, final P parent) {
        Objects.requireNonNull(url, "URL String shall be provided!");

        this.downloadCacheInfo = downloadCacheInfo;
        this.parsingCacheInfo = parsingCacheInfo;
        this.validationCacheInfo = validationCacheInfo;
        this.url = url;
        this.parent = parent;
    }

    @Override
    public DownloadInfoRecord getDownloadCacheInfo() {
        return downloadCacheInfo;
    }

    @Override
    public ParsingInfoRecord getParsingCacheInfo() {
        return parsingCacheInfo;
    }

    @Override
    public ValidationInfoRecord getValidationCacheInfo() {
        return validationCacheInfo;
    }

    @Override
    public String getUrl() {
        return url;
    }

    @Override
    public P getParent() {
        return parent;
    }

    @Override
    public Identifier getDSSId() {
        if (identifier == null) {
            identifier = buildIdentifier();
        }
        return identifier;
    }

    /**
     * Builds the identifier
     *
     * @return {@link Identifier}
     */
    protected abstract Identifier buildIdentifier();

    @Override
    public String getDSSIdAsString() {
        return getDSSId().asXmlId();
    }

}
