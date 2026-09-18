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
package eu.europa.esig.dss.lote.json.runnable;

import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.lote.json.download.JsonLoTEDownloadTask;
import eu.europa.esig.dss.lote.json.parsing.JsonLoTEParsingTask;
import eu.europa.esig.dss.lote.json.validation.JsonLoTEValidationTask;
import eu.europa.esig.dss.lote.runnable.LoTEAnalysisExecutor;
import eu.europa.esig.dss.lote.source.LoTESource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;

/**
 * This class is used to run the analysis for the TS 119 602 JSON List of Trusted Entities validation,
 * signed by a Compact Serialized JWS/JAdES
 *
 */
public class JsonLoTEAnalysisExecutor implements LoTEAnalysisExecutor {

    /**
     * Default constructor
     */
    public JsonLoTEAnalysisExecutor() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        if (document == null) {
            return true; // accept
        }
        return new JWSCompactSerializationParser(document).isSupported();
    }

    @Override
    public DownloadTask getDownloadTask(DSSDocument document, String url) {
        return new JsonLoTEDownloadTask(document, url);
    }

    @Override
    public ParsingTask getParsingTask(DSSDocument document, LoTESource source) {
        return new JsonLoTEParsingTask(document, source);
    }

    @Override
    @Deprecated
    public ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource) {
        return getValidationTask(document, signingCertificateSource, null);
    }

    @Override
    public ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource, ValidationPolicy validationPolicy) {
        return new JsonLoTEValidationTask(document, signingCertificateSource, validationPolicy);
    }

}
