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
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * This class allows to retrieve a AIA with different sources. The composite will try all sources until to get a
 * non-empty response.
 */
public class CompositeAIASource implements AIASource {

    private static final long serialVersionUID = 948088043702414489L;

    private static final Logger LOG = LoggerFactory.getLogger(CompositeAIASource.class);

    /**
     * A map of source keys and corresponding TSP Sources
     */
    private Map<String, AIASource> aIASource;

    /**
     * Default constructor instantiating object with null values
     */
    public CompositeAIASource() {
        // empty
    }

    /**
     * This setter allows to provide multiple aIASource. Be careful, all given aIASource MUST accept the same digest
     * algorithm.
     *
     * @param aIASource a {@code Map} of String and AIASource with a label and its corresponding source
     */
    public void setAIASources(Map<String, AIASource> aIASource) {
        this.aIASource = aIASource;
    }


    @Override
    public Set<CertificateToken> getCertificatesByAIA(CertificateToken certificateToken) {
        for (Entry<String, AIASource> entry : aIASource.entrySet()) {
            String sourceKey = entry.getKey();
            AIASource source = entry.getValue();
            LOG.debug("Trying to get timestamp with AIASource '{}'", sourceKey);
            try {
                Set<CertificateToken> certificateTokens = source.getCertificatesByAIA(certificateToken);
                if (certificateTokens != null) {
                    LOG.debug("Successfully retrieved certificateTokens with AiaSource Source '{}'", sourceKey);
                    return certificateTokens;
                }
            } catch (Exception e) {
                LOG.warn("Unable to retrieve the certificateTokens with AIA Source '{}' : {}", sourceKey, e.getMessage());
            }
        }
        throw new DSSExternalResourceException("Unable to retrieve the certificateTokens (" + aIASource.size() + " tries)");
    }
}
