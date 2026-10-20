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
package eu.europa.esig.dss.lote.runnable;

import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;

import java.util.Iterator;
import java.util.ServiceLoader;
import java.util.concurrent.CountDownLatch;

/**
 * Performs analysis for the List of TS 119 602 Lists Of Trusted Entities
 *
 */
public class LoLoTEAnalysis extends AbstractRunnableLoTEAnalysis<LoLoTESource> {

    /**
     * Default constructor
     *
     * @param source {@link LoLoTESource}
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     * @deprecated since DSS 6.6. Please use
     *             {@link LoLoTEAnalysis(LoLoTESource, CacheAccessByKey, DSSFileLoader, CountDownLatch, ValidationPolicy)} instead
     */
    @Deprecated
    public LoLoTEAnalysis(LoLoTESource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
                        CountDownLatch latch) {
        this(source, cacheAccess, dssFileLoader, latch, null);
    }

    /**
     * Default constructor
     *
     * @param source {@link LoLoTESource}
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     */
    public LoLoTEAnalysis(LoLoTESource source, CacheAccessByKey cacheAccess, DSSFileLoader dssFileLoader,
                          CountDownLatch latch, ValidationPolicy validationPolicy) {
        super(source, cacheAccess, dssFileLoader, latch, validationPolicy);
    }

    @Override
    protected LoLoTEAnalysisExecutor getAnalysisExecutor(DSSDocument document) {
        ServiceLoader<LoLoTEAnalysisExecutor> serviceLoaders = ServiceLoader.load(LoLoTEAnalysisExecutor.class);
        for (LoLoTEAnalysisExecutor executor : serviceLoaders) {
            if (executor.isSupported(document)) {
                return executor;
            }
        }
        Iterator<LoLoTEAnalysisExecutor> iterator = serviceLoaders.iterator();
        if (iterator.hasNext()) {
            return iterator.next();
        }
        throw new UnsupportedOperationException("Please ensure that at least one of dss-lote-validation-xml or " +
                "dss-lote-validation-json modules is added within the dependencies list.");
    }

}
