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
package eu.europa.esig.dss.lote.xml.runnable;

import eu.europa.esig.dss.lote.runnable.LoLoTEAnalysisExecutor;
import eu.europa.esig.dss.lote.source.LoLoTESource;
import eu.europa.esig.dss.lote.xml.download.XmlLoTEDownloadTask;
import eu.europa.esig.dss.lote.xml.parsing.XmlLoLoTEParsingTask;
import eu.europa.esig.dss.lote.xml.validation.XmlLoTEValidationTask;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.job.download.DownloadTask;
import eu.europa.esig.dss.validation.job.parsing.ParsingTask;
import eu.europa.esig.dss.validation.job.validation.ValidationTask;
import eu.europa.esig.dss.xml.utils.DomUtils;

/**
 * Performs analysis of an XML List of TS 119 602 List of Trusted Entities
 */
public class XmlLoLoTEAnalysisExecutor implements LoLoTEAnalysisExecutor {

    /**
     * Default constructor
     */
    public XmlLoLoTEAnalysisExecutor() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        if (document == null) {
            return true; // accept
        }
        return DomUtils.isDOM(document);
    }

    @Override
    public DownloadTask getDownloadTask(DSSDocument document, String url) {
        return new XmlLoTEDownloadTask(document, url);
    }

    @Override
    public ParsingTask getParsingTask(DSSDocument document, LoLoTESource source) {
        return new XmlLoLoTEParsingTask(document, source);
    }

    @Override
    public ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource) {
        return getValidationTask(document, signingCertificateSource, null);
    }

    @Override
    public ValidationTask getValidationTask(DSSDocument document, CertificateSource signingCertificateSource, ValidationPolicy validationPolicy) {
        return new XmlLoTEValidationTask(document, signingCertificateSource, validationPolicy);
    }

}
