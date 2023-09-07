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
package eu.europa.esig.dss.spi.x509.revocation.ocsp;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Map.Entry;

/**
 * This class allows to retrieve a RevocationToken with different sources. The composite will try all sources until to get a
 * non-empty response.
 */
public class CompositeSource<T extends Revocation,R extends RevocationSource<T>> implements RevocationSource<T> {

    private static final long serialVersionUID = 948088043702414489L;

    private static final Logger LOG = LoggerFactory.getLogger(CompositeSource.class);

    /**
     * A map of source keys and corresponding  Sources
     */
    private Map<String, R> compositeRevocationSources;

    /**
     * Default constructor instantiating object with null values
     */
    public CompositeSource() {
        // empty
    }

    /**
     * This setter allows to provide multiple revocationSources.
     *
     * @param compositeRevocationSources a {@code Map} of String and RevocationSources with a label and its corresponding source
     */
    public void setSources(Map<String, R> compositeRevocationSources) {
        this.compositeRevocationSources = compositeRevocationSources;
    }

    @Override
    public RevocationToken<T> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        for (Entry<String, R> entry : compositeRevocationSources.entrySet()) {
            String sourceKey = entry.getKey();
            RevocationSource<T> source = entry.getValue();
            LOG.debug("Trying to get revocation token with Source '{}'", sourceKey);
            try {
                RevocationToken<T> ocspToken = source.getRevocationToken(certificateToken, issuerCertificateToken);
                if (ocspToken != null) {
                    LOG.debug("Successfully retrieved revocation token with Source '{}'", sourceKey);
                    return ocspToken;
                }
            } catch (Exception e) {
                LOG.warn("Unable to retrieve the revocation token with Source '{}' : {}", sourceKey, e.getMessage());
            }
        }
        LOG.warn("Unable to retrieve the ocsp token (" + compositeRevocationSources.size() + " tries)");
        return null;
    }
}
