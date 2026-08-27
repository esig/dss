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
package eu.europa.esig.dss.lote.summary;

import eu.europa.esig.dss.lote.dto.LoTEParsingCacheDTO;
import eu.europa.esig.dss.lote.job.LoTEReadOnlyCacheAccess;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.lote.LoLoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import eu.europa.esig.dss.model.lote.LoTEValidationJobSummary;
import eu.europa.esig.dss.model.lote.OtherListPointer;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.job.cache.CacheKey;
import eu.europa.esig.dss.validation.job.summary.ValidationJobSummaryBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * Builds a {@code eu.europa.esig.dss.model.lote.LoTEValidationJobSummary}
 */

public class LoTEValidationJobSummaryBuilder implements ValidationJobSummaryBuilder<LoTEInfo, LoLoTEInfo> {

    /**
     * A read-only access for the cache of the current Validation Job
     */
    private final LoTEReadOnlyCacheAccess readOnlyCacheAccess;

    /**
     * List of sources to extract summary for
     */
    private final LoTESource[] loteSources;

    /**
     * List of lists of sources to extract summary for
     */
    private final LoLoTESource[] loloteSources;

    /**
     * Default constructor
     *
     * @param readOnlyCacheAccess {@link LoTEReadOnlyCacheAccess}
     * @param loteSources {@link LoTESource}s
     * @param loloteSources {@link LoLoTESource}s
     */
    public LoTEValidationJobSummaryBuilder(final LoTEReadOnlyCacheAccess readOnlyCacheAccess,
                                           final LoTESource[] loteSources, final LoLoTESource[] loloteSources) {
        this.readOnlyCacheAccess = readOnlyCacheAccess;
        this.loteSources = loteSources;
        this.loloteSources = loloteSources;
    }

    /**
     * Builds the {@code LoTEValidationJobSummary}
     *
     * @return {@link LoTEValidationJobSummary}
     */
    public LoTEValidationJobSummary build() {
        final List<LoTEInfo> otherLoTEInfos = new ArrayList<>();
        if (Utils.isArrayNotEmpty(loteSources)) {
            for (LoTESource loteSource : loteSources) {
                otherLoTEInfos.add(buildLoTEInfo(loteSource));
            }
        }

        final List<LoLoTEInfo> loloteList = new ArrayList<>();
        if (Utils.isArrayNotEmpty(loloteSources)) {

            for (LoLoTESource loloteSource : loloteSources) {
                LoTEParsingCacheDTO loloteParsingResult = readOnlyCacheAccess.getParsingInfoRecord(loloteSource.getCacheKey());

                LoLoTEInfo loloteInfo = buildLoLoTEInfo(loloteSource);

                List<LoTEInfo> loteInfos = new ArrayList<>();
                List<LoTESource> currentLoTESources = extractLoTESources(loloteParsingResult);
                for (LoTESource loteSource : currentLoTESources) {
                    OtherListPointer otherListPointer = getOtherTSLPointer(loloteParsingResult.getOtherListPointers(), loteSource.getUrl());
                    LoTEInfo loteInfo = buildLoTEInfo(loteSource, loloteInfo, otherListPointer);
                    loteInfos.add(loteInfo);
                }
                loloteInfo.setChildrenInfos(loteInfos);

                // TODO : no pivot support yet

                loloteList.add(loloteInfo);
            }
        }

        return new LoTEValidationJobSummary(loloteList, otherLoTEInfos);
    }

    private LoLoTEInfo buildLoLoTEInfo(LoLoTESource loloteSource) {
        CacheKey cacheKey = loloteSource.getCacheKey();
        return new LoLoTEInfo(readOnlyCacheAccess.getDownloadInfoRecord(cacheKey), readOnlyCacheAccess.getParsingInfoRecord(cacheKey),
                readOnlyCacheAccess.getValidationInfoRecord(cacheKey), loloteSource.getUrl());
    }

    private LoTEInfo buildLoTEInfo(LoTESource loteSource) {
        CacheKey cacheKey = loteSource.getCacheKey();
        return new LoTEInfo(readOnlyCacheAccess.getDownloadInfoRecord(cacheKey), readOnlyCacheAccess.getParsingInfoRecord(cacheKey),
                readOnlyCacheAccess.getValidationInfoRecord(cacheKey), loteSource.getUrl());
    }

    private LoTEInfo buildLoTEInfo(LoTESource loteSource, LoLoTEInfo parentInfo, OtherListPointer otherListPointer) {
        CacheKey cacheKey = loteSource.getCacheKey();
        return new LoTEInfo(readOnlyCacheAccess.getDownloadInfoRecord(cacheKey), readOnlyCacheAccess.getParsingInfoRecord(cacheKey),
                readOnlyCacheAccess.getValidationInfoRecord(cacheKey), loteSource.getUrl(), parentInfo, otherListPointer);
    }

    private List<LoTESource> extractLoTESources(LoTEParsingCacheDTO loteParsingResult) {
        List<LoTESource> result = new ArrayList<>();
        if (loteParsingResult != null && loteParsingResult.isResultExist()) {
            List<OtherListPointer> otherListPointers = loteParsingResult.getOtherListPointers();
            if (Utils.isCollectionNotEmpty(otherListPointers)) {
                for (OtherListPointer otherListPointerDTO : otherListPointers) {
                    LoTESource loteSource = new LoTESource();
                    loteSource.setUrl(otherListPointerDTO.getLocationUrl());
                    result.add(loteSource);
                }
            }
        }
        return result;
    }

    private OtherListPointer getOtherTSLPointer(List<OtherListPointer> loteOtherPointers, String listPointerLocation) {
        for (OtherListPointer otherTSLPointer : loteOtherPointers) {
            if (Utils.areStringsEqual(listPointerLocation, otherTSLPointer.getLocationUrl())) {
                return otherTSLPointer;
            }
        }
        return null;
    }

}
