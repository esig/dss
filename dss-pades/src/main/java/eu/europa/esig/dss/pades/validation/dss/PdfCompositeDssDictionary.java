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
package eu.europa.esig.dss.pades.validation.dss;

import eu.europa.esig.dss.pdf.PdfDssDict;

import java.io.Serializable;

/**
 * This class represents a merged result of all /DSS dictionaries' content extracted from a PDF document
 *
 */
@SuppressWarnings("serial")
public class PdfCompositeDssDictionary implements Serializable {

    /** Represents a merged result of certificate sources extracted from PDF document */
    private final PdfCompositeDssDictCertificateSource certificateSource;

    /** Represents a merged result of CRL sources extracted from PDF document */
    private final PdfCompositeDssDictCRLSource crlSource;

    /** Represents a merged result of OCSP sources extracted from PDF document */
    private final PdfCompositeDssDictOCSPSource ocspSource;

    /**
     * Default constructor
     */
    public PdfCompositeDssDictionary() {
        this.certificateSource = new PdfCompositeDssDictCertificateSource();
        this.crlSource = new PdfCompositeDssDictCRLSource();
        this.ocspSource = new PdfCompositeDssDictOCSPSource();
    }

    /**
     * Gets the composite certificate source
     *
     * @return {@link PdfCompositeDssDictCertificateSource}
     */
    public PdfCompositeDssDictCertificateSource getCertificateSource() {
        return certificateSource;
    }

    /**
     * Gets the composite CRL source
     *
     * @return {@link PdfCompositeDssDictCRLSource}
     */
    public PdfCompositeDssDictCRLSource getCrlSource() {
        return crlSource;
    }

    /**
     * Gets the composite OCSP source
     *
     * @return {@link PdfCompositeDssDictOCSPSource}
     */
    public PdfCompositeDssDictOCSPSource getOcspSource() {
        return ocspSource;
    }

    /**
     * This method is used to populate certificate and revocation sources with data extracted from /DSS revision
     *
     * @param dssDict {@link PdfDssDict} representing PDF revision's content
     */
    public void populateFromDssDictionary(PdfDssDict dssDict) {
        if (dssDict != null) {
            certificateSource.populateFromDssDictionary(dssDict);
            crlSource.populateFromDssDictionary(dssDict);
            ocspSource.populateFromDssDictionary(dssDict);
        }
    }

}
