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
package eu.europa.esig.dss.model.lote;

import eu.europa.esig.dss.model.identifier.Identifier;
import eu.europa.esig.dss.model.job.AbstractDocumentInfo;
import eu.europa.esig.dss.model.job.DownloadInfoRecord;
import eu.europa.esig.dss.model.job.ValidationInfoRecord;
import eu.europa.esig.dss.model.lote.identifier.LoTEIdentifier;
import eu.europa.esig.dss.model.lote.record.LoTEParsingInfoRecord;

/**
 * Contains information about the TS 119 602 List of Trusted Entities
 *
 */
public class LoTEInfo extends AbstractDocumentInfo<LoLoTEInfo> {

    private static final long serialVersionUID = -1505115221927652721L;

    /** OtherListPointer element extracted from the pointing LoLoTE/LoTE */
    private final OtherListPointer otherListPointer;

    /** Cached Identifier instance */
    private Identifier identifier;

    /**
     * The default constructor
     *
     * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
     * @param parsingCacheInfo {@link LoTEParsingInfoRecord} a parsing cache result
     * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
     * @param url {@link String} address used to extract the entry
     */
    public LoTEInfo(final DownloadInfoRecord downloadCacheInfo, final LoTEParsingInfoRecord parsingCacheInfo,
                  final ValidationInfoRecord validationCacheInfo, final String url) {
        this(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, null);
    }

    /**
     * The default constructor with parent LoTEInfo
     *
     * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
     * @param parsingCacheInfo {@link LoTEParsingInfoRecord} a parsing cache result
     * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
     * @param url {@link String} address used to extract the entry
     * @param parent {@link LoLoTEInfo} referencing the parent LoLoTE
     */
    public LoTEInfo(final DownloadInfoRecord downloadCacheInfo, final LoTEParsingInfoRecord parsingCacheInfo,
                    final ValidationInfoRecord validationCacheInfo, final String url, final LoLoTEInfo parent) {
        this(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, parent, null);
    }

    /**
     * The constructor with parent LoLoTEInfo
     *
     * @param downloadCacheInfo {@link DownloadInfoRecord} a download cache result
     * @param parsingCacheInfo {@link LoTEParsingInfoRecord} a parsing cache result
     * @param validationCacheInfo {@link ValidationInfoRecord} a validation cache result
     * @param url {@link String} address used to extract the entry
     * @param parent {@link LoLoTEInfo} referencing the parent LoLoTE
     * @param otherListPointer {@link OtherListPointer} element from the pointing LoTE/LoLoTE
     */
    public LoTEInfo(final DownloadInfoRecord downloadCacheInfo, final LoTEParsingInfoRecord parsingCacheInfo,
                    final ValidationInfoRecord validationCacheInfo, final String url, final LoLoTEInfo parent,
                    final OtherListPointer otherListPointer) {
        super(downloadCacheInfo, parsingCacheInfo, validationCacheInfo, url, parent);
        this.otherListPointer = otherListPointer;
    }

    /**
     * Returns Parsing Cache Info
     *
     * @return {@link LoTEParsingInfoRecord}
     */
    @Override
    public LoTEParsingInfoRecord getParsingCacheInfo() {
        return (LoTEParsingInfoRecord) super.getParsingCacheInfo();
    }

    /**
     * Gets the pointer to the current LoTE
     *
     * @return {@link OtherListPointer}
     */
    public OtherListPointer getListPointer() {
        return otherListPointer;
    }

    /**
     * Returns the TL id
     *
     * @return {@link String} id
     */
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
    @Override
    protected Identifier buildIdentifier() {
        return new LoTEIdentifier(this);
    }

}
