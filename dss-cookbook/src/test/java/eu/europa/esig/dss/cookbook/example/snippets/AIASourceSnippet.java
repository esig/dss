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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.x509.aia.JdbcCacheAIASource;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Collections;
import java.util.Set;

public class AIASourceSnippet {

    @SuppressWarnings({ "unused", "null" })
    public static void main(String[] args) throws SQLException {

        CertificateToken certificateToken = null;

        // tag::demo[]
        // import eu.europa.esig.dss.spi.x509.aia.AIASource;
        // import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
        // import eu.europa.esig.dss.model.x509.CertificateToken;

        AIASource aiaSource = new DefaultAIASource();
        Set<CertificateToken> certificates = aiaSource.getCertificatesByAIA(certificateToken);
        // end::demo[]

        DataSource dataSource = null;

        // tag::demo-online[]
        // import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
        // import eu.europa.esig.dss.spi.client.http.Protocol;
        // import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
        // import java.util.Collections;

        // Instantiates a new DefaultAIASource object
        DefaultAIASource onlineAIASource = new DefaultAIASource();

        // Allows setting an implementation of the `DataLoader` interface,
        // processing a querying of a remote revocation server.
        // `CommonsDataLoader` instance is used by default.
        onlineAIASource.setDataLoader(new CommonsDataLoader());

        // Restrict the accepted protocols to HTTP
        onlineAIASource.setAcceptedProtocols(Collections.singletonList(Protocol.HTTP));

        // end::demo-online[]

        // tag::demo-cached[]
        // import eu.europa.esig.dss.model.x509.CertificateToken;
        // import eu.europa.esig.dss.service.x509.aia.JdbcCacheAIASource;
        // import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;

        // Creates an instance of JdbcCacheAIASource
        JdbcCacheAIASource cacheAIASource = new JdbcCacheAIASource();

        // Initialize the JdbcCacheConnector
        JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);

        // Set the JdbcCacheConnector
        cacheAIASource.setJdbcCacheConnector(jdbcCacheConnector);

        // Allows definition of an alternative dataLoader to be used to access a revocation
        // from online sources if a requested revocation is not present in the repository or has been expired (see below).


        // Creates an SQL table
        cacheAIASource.initTable();

        // Extract certificates by AIA
        Set<CertificateToken> aiaCertificates = cacheAIASource.getCertificatesByAIA(certificateToken);
        // end::demo-cached[]

    }

}
