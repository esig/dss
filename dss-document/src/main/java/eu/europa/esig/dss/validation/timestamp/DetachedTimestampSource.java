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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.validation.ListRevocationSource;
import eu.europa.esig.dss.validation.ManifestFile;

import java.util.ArrayList;
import java.util.List;

/**
 * Performs processing of detached timestamps
 */
public class DetachedTimestampSource extends AbstractTimestampSource {

    /** A list of detached timestamps */
    private final List<TimestampToken> detachedTimestamps = new ArrayList<>();

    /** Merged certificate source from timestamps */
    private final ListCertificateSource certificateSource = new ListCertificateSource();

    /** Merged CRL source */
    private final ListRevocationSource<CRL> crlSource = new ListRevocationSource<>();

    /** Merged OCSP source */
    private final ListRevocationSource<OCSP> ocspSource = new ListRevocationSource<>();

    /**
     * Default constructor instantiating object with empty resources
     */
    public DetachedTimestampSource() {
        // empty
    }

    /**
     * Returns a list of processed detached timestamps
     *
     * @return a list of {@link TimestampToken}s
     */
    public List<TimestampToken> getDetachedTimestamps() {
        return detachedTimestamps;
    }

    /**
     * Adds the external timestamp to the source
     *
     * @param timestamp {@link TimestampToken}
     */
    public void addExternalTimestamp(TimestampToken timestamp) {
        processExternalTimestamp(timestamp);
        detachedTimestamps.add(timestamp);
    }

    private void processExternalTimestamp(TimestampToken externalTimestamp) {
        certificateSource.add(externalTimestamp.getCertificateSource());
        crlSource.add(externalTimestamp.getCRLSource());
        ocspSource.add(externalTimestamp.getOCSPSource());

        ManifestFile manifestFile = externalTimestamp.getManifestFile();
        if (manifestFile != null) {
            for (TimestampToken timestampToken : detachedTimestamps) {
                if (manifestFile.isDocumentCovered(timestampToken.getFileName())) {
                    addReferences(externalTimestamp.getTimestampedReferences(),
                            getReferencesFromTimestamp(timestampToken, certificateSource, crlSource, ocspSource));
                }
            }
        }
    }

}
