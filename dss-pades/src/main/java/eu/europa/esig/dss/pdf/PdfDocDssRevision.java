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
package eu.europa.esig.dss.pdf;

import eu.europa.esig.dss.pades.validation.dss.PdfCompositeDssDictionary;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pdf.modifications.PdfModificationDetection;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pades.validation.PdfSignatureDictionary;
import eu.europa.esig.dss.pades.validation.PdfSignatureField;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class represents an LT-level PDF revision containing a DSS dictionary
 *
 */
public class PdfDocDssRevision implements PdfRevision {

    private static final long serialVersionUID = -1369264311522424583L;

    /** The composite DSS dictionary combined from all /DSS revisions' content */
    private final PdfCompositeDssDictionary compositeDssDictionary;

    /** The DSS dictionary from the revision */
    private final PdfDssDict dssDictionary;

    /** Cached certificate source */
    private PdfDssDictCertificateSource certificateSource;

    /** Cached CRL source */
    private PdfDssDictCRLSource crlSource;

    /** Cached OCSP source */
    private PdfDssDictOCSPSource ocspSource;

    /**
     * Default constructor
     *
     * @param compositeDssDictionary {@link PdfCompositeDssDictionary}
     * @param dssDictionary {@link PdfDssDict}
     */
    public PdfDocDssRevision(final PdfCompositeDssDictionary compositeDssDictionary, final PdfDssDict dssDictionary) {
        Objects.requireNonNull(compositeDssDictionary, "Composite DSS dictionary cannot be null!");
        Objects.requireNonNull(dssDictionary, "The dssDictionary cannot be null!");
        this.compositeDssDictionary = compositeDssDictionary;
        this.dssDictionary = dssDictionary;
    }

    /**
     * Returns DSS dictionary
     *
     * @return {@link PdfDssDict}
     */
    public PdfDssDict getDssDictionary() {
        return dssDictionary;
    }

    @Override
    public PdfSignatureDictionary getPdfSigDictInfo() {
        // not applicable for DSS revision
        return null;
    }

    @Override
    public List<PdfSignatureField> getFields() {
        // not applicable for DSS revision
        return Collections.emptyList();
    }

    @Override
    public PdfModificationDetection getModificationDetection() {
        // not applicable
        return null;
    }

    /**
     * Returns a corresponding {@code CertificateSource}
     *
     * @return {@link PdfDssDictCertificateSource}
     */
    public PdfDssDictCertificateSource getCertificateSource() {
        if (certificateSource == null) {
            certificateSource = new PdfDssDictCertificateSource(compositeDssDictionary.getCertificateSource(), dssDictionary);
        }
        return certificateSource;
    }

    /**
     * Returns a corresponding {@code CRLSource}
     *
     * @return {@link PdfDssDictCRLSource}
     */
    public PdfDssDictCRLSource getCRLSource() {
        if (crlSource == null) {
            crlSource = new PdfDssDictCRLSource(compositeDssDictionary.getCrlSource(), dssDictionary);
        }
        return crlSource;
    }

    /**
     * Returns a corresponding {@code OCSPSource}
     *
     * @return {@link PdfDssDictOCSPSource}
     */
    public PdfDssDictOCSPSource getOCSPSource() {
        if (ocspSource == null) {
            ocspSource = new PdfDssDictOCSPSource(compositeDssDictionary.getOcspSource(), dssDictionary);
        }
        return ocspSource;
    }

}
