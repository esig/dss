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

import eu.europa.esig.dss.pades.validation.PdfDssDictCRLSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictCertificateSource;
import eu.europa.esig.dss.pades.validation.PdfDssDictOCSPSource;
import eu.europa.esig.dss.pades.validation.PdfRevision;
import eu.europa.esig.dss.pdf.PdfDocDssRevision;
import eu.europa.esig.dss.pdf.PdfDocTimestampRevision;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.spi.x509.CertificateSource;
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

    /**
     * Default constructor
     *
     * @param pdfRevision {@link PdfRevision}
     */
    public PdfRevisionTimestampSource(final PdfRevision pdfRevision) {
        this.pdfRevision = pdfRevision;
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
            return getReferencesFromTimestamp(timestampToken);

        } else if (pdfRevision instanceof PdfDocDssRevision) {
            PdfDocDssRevision pdfDocDssRevision = (PdfDocDssRevision) pdfRevision;

            PdfDssDict dssDictionary = pdfDocDssRevision.getDssDictionary();
            final List<TimestampedReference> references = new ArrayList<>();

            CertificateSource certificateSource = new PdfDssDictCertificateSource(dssDictionary);
            addReferences(references, createReferencesForCertificates(certificateSource.getCertificates()));

            PdfDssDictCRLSource crlSource = new PdfDssDictCRLSource(dssDictionary);
            addReferences(references, createReferencesForCRLBinaries(crlSource.getDSSDictionaryBinaries()));
            addReferences(references, createReferencesForCRLBinaries(crlSource.getVRIDictionaryBinaries()));

            PdfDssDictOCSPSource ocspSource = new PdfDssDictOCSPSource(dssDictionary);
            addReferences(references, createReferencesForOCSPBinaries(ocspSource.getDSSDictionaryBinaries()));
            addReferences(references, createReferencesForOCSPBinaries(ocspSource.getVRIDictionaryBinaries()));

            return references;
        }

        return Collections.emptyList();
    }

}
