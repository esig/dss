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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.FileCacheCRLSource;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.client.http.Protocol;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlQuery;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

import javax.sql.DataSource;
import java.io.File;
import java.sql.SQLException;

public class CRLSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) throws SQLException {

		CRLSource crlSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		// import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

		CRLToken crlToken = crlSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

		DataSource dataSource = null;

		// tag::demo-online[]
		// import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
		// import eu.europa.esig.dss.service.crl.OnlineCRLSource;
		// import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
		// import eu.europa.esig.dss.spi.client.http.Protocol;
		// import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
		// import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

		// Instantiates a new OnlineCRLSource
		OnlineCRLSource onlineCRLSource = new OnlineCRLSource();

		// Allows setting an implementation of `DataLoader` interface,
		// processing a querying of a remote revocation server.
		// `CommonsDataLoader` instance is used by default.
		onlineCRLSource.setDataLoader(new CommonsDataLoader());

		// Sets a preferred protocol that will be used for obtaining a CRL.
		// E.g. for a list of urls with protocols HTTP, LDAP and FTP, with a defined
		// preferred
		// protocol as FTP, the FTP url will be called first, and in case of an
		// unsuccessful
		// result other url calls will follow.
		// Default : null (urls will be called in a provided order).
		onlineCRLSource.setPreferredProtocol(Protocol.FTP);

		// end::demo-online[]

		// tag::demo-cached[]
		// Creates an instance of JdbcCacheCRLSource
		JdbcCacheCRLSource cacheCRLSource = new JdbcCacheCRLSource();

		// Initialize the JdbcCacheConnector
		JdbcCacheConnector jdbcCacheConnector = new JdbcCacheConnector(dataSource);

		// Set the JdbcCacheConnector
		cacheCRLSource.setJdbcCacheConnector(jdbcCacheConnector);

		// Allows definition of an alternative dataLoader to be used to access a
		// revocation
		// from online sources if a requested revocation is not present in the
		// repository or has been expired (see below).
		cacheCRLSource.setProxySource(onlineCRLSource);

		// All setters accept values in seconds
		Long oneWeek = (long) (60 * 60 * 24 * 7); // seconds * minutes * hours * days

		// If "nextUpdate" field is not defined for a revocation token, the value of
		// "defaultNextUpdateDelay"
		// will be used in order to determine when a new revocation data should be
		// requested.
		// If the current time is not beyond the "thisUpdate" time +
		// "defaultNextUpdateDelay",
		// then a revocation data will be retrieved from the repository source,
		// otherwise a new revocation data
		// will be requested from a proxiedSource.
		// Default : null (a new revocation data will be requested of "nestUpdate" field
		// is not defined).
		cacheCRLSource.setDefaultNextUpdateDelay(oneWeek);

		// Defines a custom maximum possible nextUpdate delay. Allows limiting of a time
		// interval
		// from "thisUpdate" to "nextUpdate" defined in a revocation data.
		// Default : null (not specified, the "nextUpdate" value provided in a
		// revocation is used).
		cacheCRLSource.setMaxNextUpdateDelay(oneWeek); // force refresh every week (eg : ARL)

		// Defines if a revocation should be removed on its expiration.
		// Default : true (removes revocation from a repository if expired).
		cacheCRLSource.setRemoveExpired(true);

		// Creates an SQL table
		cacheCRLSource.initTable();

		// Extract CRL for a certificate
		CRLToken crlRevocationToken = cacheCRLSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo-cached[]

		// tag::demo-file-cached[]
		// import eu.europa.esig.dss.service.crl.FileCacheCRLSource;
		// import java.io.File;

		// Initialize the file-based CRL source
		FileCacheCRLSource fileCacheCRLSource = new FileCacheCRLSource("path/to/crl/cache");

		// Optionally, set a backup online source for when cache misses occur
		fileCacheCRLSource.setProxySource(onlineCRLSource);

		// Extract CRL for a certificate (will use cache if available, otherwise fetch
		// from proxy source)
		CRLToken fileCrlRevocationToken = fileCacheCRLSource.getRevocationToken(certificateToken, issuerCertificateToken);

		// Clear cache when needed (removes all cached CRL files)
		fileCacheCRLSource.clearCache();
		// end::demo-file-cached[]

	}

	@SuppressWarnings("serial")
	// tag::demo-postgresql[]
	public class PostgreSqlJdbcCacheCRLSource extends JdbcCacheCRLSource {

		@Override
		protected SqlQuery getCreateTableQuery() {
			// Override datatypes with BYTEA, supported by PostgreSQL
			return SqlQuery.createQuery("CREATE TABLE CACHED_CRL (ID CHAR(40), DATA BYTEA, ISSUER BYTEA)");
		}

	}
	// end::demo-postgresql[]

}
