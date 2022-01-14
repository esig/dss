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
package eu.europa.esig.dss.pades.validation.timestamp;

import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.dss.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.timestamp.AbstractTimestampSource;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.validation.timestamp.TimestampedReference;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Extracts a timestamp from a single {@code PdfRevision}
 */
public class PdfRevisionTimestampSource extends AbstractTimestampSource {

    /** The PdfRevision */
    private final PdfRevision pdfRevision;

    /** Merged CertificateSource to find certificate binaries from */
    private final ListCertificateSource certificateSource;

    /** Merged CRL source */
    private final ListRevocationSource<CRL> crlSource;

    /** Merged OCSP source */
    private final ListRevocationSource<OCSP> ocspSource;

    /**
     * Default constructor
     *
     * @param pdfRevision {@link PdfRevision} to extract references from
     * @param certificateSource {@link CertificateSource} a merged certificate source to search certificate binaries
     * @param crlSource {@link ListRevocationSource} merged CRL source
     * @param ocspSource {@link ListRevocationSource} merged OCSP source
     */
    public PdfRevisionTimestampSource(final PdfRevision pdfRevision, final ListCertificateSource certificateSource,
                                      final ListRevocationSource<CRL> crlSource, final ListRevocationSource<OCSP> ocspSource) {
        this.pdfRevision = pdfRevision;
        this.certificateSource = certificateSource;
        this.crlSource = crlSource;
        this.ocspSource = ocspSource;
    }

    /**
     * Returns incorporated references for the revision
     *
     * @return a list of {@link TimestampedReference}s
     */
    public List<TimestampedReference> getIncorporatedReferences() {
        if (pdfRevision instanceof PdfDocTimestampRevision) {
            PdfDocTimestampRevision pdfDocTimestampRevision = (PdfDocTimestampRevision) pdfRevision;

            final TimestampToken timestampToken = pdfDocTimestampRevision.getTimestampToken();
            return getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource);

        } else if (pdfRevision instanceof PdfDocDssRevision) {
            PdfDocDssRevision pdfDocDssRevision = (PdfDocDssRevision) pdfRevision;

            final List<TimestampedReference> references = new ArrayList<>();

            PdfDssDictCertificateSource dssCertificateSource = pdfDocDssRevision.getCertificateSource();
            addReferences(references, createReferencesForCertificates(dssCertificateSource.getCertificates()));

            PdfDssDictCRLSource dssCRLSource = pdfDocDssRevision.getCRLSource();
            addReferences(references, createReferencesForCRLBinaries(dssCRLSource.getDSSDictionaryBinaries()));
            addReferences(references, createReferencesForCRLBinaries(dssCRLSource.getVRIDictionaryBinaries()));

            PdfDssDictOCSPSource dssOCSPSource = pdfDocDssRevision.getOCSPSource();
            addReferences(references, createReferencesForOCSPBinaries(dssOCSPSource.getDSSDictionaryBinaries(), certificateSource));
            addReferences(references, createReferencesForOCSPBinaries(dssOCSPSource.getVRIDictionaryBinaries(), certificateSource));

            return references;
        }

        return Collections.emptyList();
    }

}
