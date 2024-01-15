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
package eu.europa.esig.dss.spi.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import eu.europa.esig.dss.spi.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The class is used to download issuer certificates by AIA from remote sources
 *
 */
public class DefaultAIASource implements AIASource {

    private static final long serialVersionUID = 3968373722847675203L;

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAIASource.class);

    /**
     * The used {@code DataLoader} to download data
     */
    private DataLoader dataLoader;

    /**
     * Collection of protocols to be accepted and used by the source
     * Default: all protocols are accepted (FILE, HTTP, HTTPS, LDAP, FTP).
     */
    private Collection<Protocol> acceptedProtocols = Arrays.asList(Protocol.values());

    /**
     * Empty constructor.
     * Instantiates a {@code NativeHTTPDataLoader} as a default data loader
     */
    public DefaultAIASource() {
        this(new NativeHTTPDataLoader());
    }

    /**
     * Default constructor with a defined {@code DataLoader}
     *
     * @param dataLoader {@link DataLoader} to be used
     */
    public DefaultAIASource(DataLoader dataLoader) {
        Objects.requireNonNull(dataLoader, "dataLoader cannot be null!");
        this.dataLoader = dataLoader;
    }

    /**
     * Sets the data loader to be used to download a certificate token by AIA
     *
     * @param dataLoader {@link DataLoader}
     */
    public void setDataLoader(DataLoader dataLoader) {
        Objects.requireNonNull(dataLoader, "dataLoader cannot be null!");
        this.dataLoader = dataLoader;
    }

    /**
     * Defines a set of protocols to be accepted and used by the AIA Source.
     * All protocols which are not defined in the collection will be skipped.
     * Default: all protocols are accepted (FILE, HTTP, HTTPS, LDAP, FTP).
     *
     * @param acceptedProtocols a collection of accepted {@link Protocol}s
     */
    public void setAcceptedProtocols(Collection<Protocol> acceptedProtocols) {
        this.acceptedProtocols = acceptedProtocols;
    }

    @Override
    public Set<CertificateToken> getCertificatesByAIA(final CertificateToken certificateToken) {
        Objects.requireNonNull(certificateToken, "CertificateToken cannot be null!");
        Objects.requireNonNull(dataLoader, "DataLoader is not provided!");

        final List<String> caIssuersUrls = getCAIssuersUrls(certificateToken);

        for (String caIssuersUrl : caIssuersUrls) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to retrieve CA issuers from URL '{}'...", caIssuersUrl);
            }

            try {
                byte[] bytes = executeCAIssuersRequest(caIssuersUrl);

                try (InputStream is = new ByteArrayInputStream(bytes)) {
                    List<CertificateToken> loadedCertificates = DSSUtils.loadCertificateFromP7c(is);
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("{} certificate(s) loaded from '{}'", loadedCertificates.size(), caIssuersUrl);
                    }
                    for (CertificateToken certificate : loadedCertificates) {
                        certificate.setSourceURL(caIssuersUrl);
                    }
                    return new LinkedHashSet<>(loadedCertificates);
                }

            } catch (Exception e) {
                LOG.warn("Unable to retrieve AIA certificates with URL '{}' : {}", caIssuersUrl, e.getMessage());
            }
        }

        return Collections.emptySet();
    }

    /**
     * Returns a list of caIssuers URLs for the given {@code certificateToken}
     *
     * @param certificateToken {@link CertificateToken}
     * @return a list of {@link String}s
     */
    protected List<String> getCAIssuersUrls(CertificateToken certificateToken) {
        List<String> urls = CertificateExtensionsUtils.getCAIssuersAccessUrls(certificateToken);
        if (Utils.isCollectionEmpty(urls)) {
            LOG.info("There is no AIA extension for certificate download.");
            return Collections.emptyList();
        }
        return filterURLs(urls);
    }

    private List<String> filterURLs(List<String> urls) {
        return urls.stream().filter(this::isUrlAccepted).collect(Collectors.toList());
    }

    /**
     * Executes a GET request to retrieve caIssuers from URL {@code caIssuersUrl}
     *
     * @param caIssuersUrl {@link String} to get certificates from
     * @return byte array
     */
    protected byte[] executeCAIssuersRequest(String caIssuersUrl) {
        byte[] bytes = dataLoader.get(caIssuersUrl);
        if (Utils.isArrayNotEmpty(bytes)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Base64 content : {}", Utils.toBase64(bytes));
            }
            return bytes;
        }
        throw new DSSExternalResourceException(String.format("AIA DataLoader for certificate with url '%s' " +
                "responded with an empty byte array!", caIssuersUrl));
    }

    private boolean isUrlAccepted(String url) {
        if (Utils.isCollectionNotEmpty(acceptedProtocols)) {
            for (Protocol protocol : acceptedProtocols) {
                if (protocol.isTheSame(url)) {
                    return true;
                }
            }
        }
        return false;
    }

}
