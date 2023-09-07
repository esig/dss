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
package eu.europa.esig.dss.spi.x509.revocation.crl;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Map.Entry;

/**
 * This class allows to retrieve a CRL with different sources. The composite will try all sources until to get a
 * non-empty response.
 */
public class CompositeCRLSource implements CRLSource {

    private static final long serialVersionUID = 948088043702414489L;

    private static final Logger LOG = LoggerFactory.getLogger(CompositeCRLSource.class);

    /**
     * A map of source keys and corresponding TSP Sources
     */
    private Map<String, CRLSource> cRLSources;

    /**
     * Default constructor instantiating object with null values
     */
    public CompositeCRLSource() {
        // empty
    }

    /**
     * This setter allows to provide multiple cRLSources. Be careful, all given cRLSources MUST accept the same digest
     * algorithm.
     *
     * @param cRLSources a {@code Map} of String and CRLSource with a label and its corresponding source
     */
    public void setCRLSources(Map<String, CRLSource> cRLSources) {
        this.cRLSources = cRLSources;
    }

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        for (Entry<String, CRLSource> entry : cRLSources.entrySet()) {
            String sourceKey = entry.getKey();
            CRLSource source = entry.getValue();
            LOG.debug("Trying to get timestamp with CRLSource '{}'", sourceKey);
            try {
                CRLToken crlToken = source.getRevocationToken(certificateToken, issuerCertificateToken);
                if (crlToken != null) {
                    LOG.debug("Successfully retrieved crlToken with CRLSource '{}'", sourceKey);
                    return crlToken;
                }
            } catch (Exception e) {
                LOG.warn("Unable to retrieve the crlToken with CRLSource '{}' : {}", sourceKey, e.getMessage());
            }
        }
        LOG.warn("Unable to retrieve the crlToken (" + cRLSources.size() + " tries)");
        return null;
    }
}
