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

import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;

/**
 * Common interface to perform LoTE analysis
 *
 * @param <S> {@link LoTESource}
 */
public interface ILoTEAnalysisExecutor<S extends LoTESource> {

    /**
     * Verifies if the List document is supported by the current executor
     *
     * @param document {@link DSSDocument} to be analyzed
     * @return TRUE if the document is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument document);

    /**
     * Gets the download task
     *
     * @param document {@link DSSDocument} to be processed
     * @param url {@link String}
     * @return {@link DownloadTask}
     */
    DownloadTask getDownloadTask(DSSDocument document, String url);

    /**
     * Gets the parsing task
     *
     * @param document {@link DSSDocument} to be processed
     * @param source {@link LoTESource}
     * @return {@link ParsingTask}
     */
    ParsingTask getParsingTask(DSSDocument document, S source);

    /**
     * Gets the validation task
     *
     * @param document {@link DSSDocument} to be processed
     * @param signingCertificateSource {@link CertificateSource} containing signing certificate candidates
     * @return {@link ValidationTask}
     * @deprecated since DSS 6.6. Please use
     *             {@link #getValidationTask(DSSDocument, CertificateSource, ValidationPolicy)} instead.
     */
    @Deprecated
    ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource);

    /**
     * Gets the validation task
     *
     * @param document {@link DSSDocument} to be processed
     * @param signingCertificateSource {@link CertificateSource} containing signing certificate candidates
     * @return {@link ValidationTask}
     */
    ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource,
                                     ValidationPolicy validationPolicy);

}
