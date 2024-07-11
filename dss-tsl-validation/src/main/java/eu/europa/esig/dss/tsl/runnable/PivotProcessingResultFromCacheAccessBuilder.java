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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.tsl.OtherTSLPointer;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.tsl.parsing.ParsingUtils;

/**
 * This class creates an instance of {@code eu.europa.esig.dss.tsl.runnable.PivotProcessingResult}
 * from a given {@code CacheAccessByKey}
 *
 */
public class PivotProcessingResultFromCacheAccessBuilder {

    /** Cache access to the given pivot */
    private final CacheAccessByKey cacheAccessByKey;

    /**
     * Default constructor
     *
     * @param cacheAccessByKey {@link CacheAccessByKey}
     */
    public PivotProcessingResultFromCacheAccessBuilder(final CacheAccessByKey cacheAccessByKey) {
        this.cacheAccessByKey = cacheAccessByKey;
    }

    /**
     * Builds the {@code PivotProcessingResult}
     *
     * @return {@link PivotProcessingResult}
     */
    public PivotProcessingResult build() {
        OtherTSLPointer xmlLotlPointer = ParsingUtils.getXMLLOTLPointer(cacheAccessByKey.getParsingReadOnlyResult());
        return new PivotProcessingResult(getDocument(), getCertificateSource(xmlLotlPointer), getLotlLocation(xmlLotlPointer));
    }

    private DSSDocument getDocument() {
        if (cacheAccessByKey.getDownloadReadOnlyResult() != null) {
            return cacheAccessByKey.getDownloadReadOnlyResult().getDocument();
        }
        return null;
    }

    private CertificateSource getCertificateSource(OtherTSLPointer xmlLotlPointer) {
        if (xmlLotlPointer != null) {
            return ParsingUtils.getLOTLAnnouncedCertificateSource(xmlLotlPointer);
        }
        return null;
    }

    private String getLotlLocation(OtherTSLPointer xmlLotlPointer) {
        if (xmlLotlPointer != null) {
            return xmlLotlPointer.getTSLLocation();
        }
        return null;
    }

}
