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
package eu.europa.esig.dss.tsl.runnable;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.download.XmlDownloadTask;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.tsl.validation.TLValidatorTask;
import eu.europa.esig.dss.validation.job.cache.access.CacheAccessByKey;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.runnable.AbstractRunnableAnalysis;
import eu.europa.esig.dss.validation.job.source.DocumentSource;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;

import java.util.concurrent.CountDownLatch;

/**
 * Abstract implementation for performing a Trusted List analysis
 *
 */
public abstract class AbstractRunnableTLAnalysis extends AbstractRunnableAnalysis {

    /**
     * Default constructor
     *
     * @param source {@link DocumentSource} representing a TL or LOTL
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     * @deprecated since DSS 6.6. Please use
     *             {@link AbstractRunnableTLAnalysis(TLSource, CacheAccessByKey, DSSFileLoader dssFileLoader, CountDownLatch, ValidationPolicy)}
     */
    @Deprecated
    protected AbstractRunnableTLAnalysis(final TLSource source, final CacheAccessByKey cacheAccess,
                                         final DSSFileLoader dssFileLoader, CountDownLatch latch) {
        this(source, cacheAccess, dssFileLoader, latch, null);
    }

    /**
     * Default constructor
     *
     * @param source {@link DocumentSource} representing a TL or LOTL
     * @param cacheAccess {@link CacheAccessByKey}
     * @param dssFileLoader {@link DSSFileLoader}
     * @param latch {@link CountDownLatch}
     * @param validationPolicy {@link ValidationPolicy}
     */
    protected AbstractRunnableTLAnalysis(final TLSource source, final CacheAccessByKey cacheAccess,
                                         final DSSFileLoader dssFileLoader, final CountDownLatch latch,
                                         ValidationPolicy validationPolicy) {
        super(source, cacheAccess, dssFileLoader, latch, validationPolicy);
    }

    @Override
    protected DownloadTask getDownloadTask(DSSFileLoader dssFileLoader, String url) {
        return new XmlDownloadTask(dssFileLoader, url);
    }

    @Override
    protected ValidationTask getValidationTask(DSSDocument document, CertificateSource certificateSource) {
        return new TLValidatorTask(document, certificateSource, getValidationPolicy());
    }

}
