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

import java.sql.SQLException;

import javax.sql.DataSource;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.JdbcCacheCRLSource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

public class CRLSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) throws SQLException {

		CRLSource crlSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		CRLToken crlToken = crlSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

		DataSource dataSource = null;
		OnlineCRLSource onlineCRLSource = null;

		// tag::demo-cached[]
		JdbcCacheCRLSource cacheCRLSource = new JdbcCacheCRLSource();
		cacheCRLSource.setDataSource(dataSource);
		cacheCRLSource.setProxySource(onlineCRLSource);
		Long oneWeek = (long) (60 * 60 * 24 * 7);
		cacheCRLSource.setMaxNextUpdateDelay(oneWeek); // force refresh every week (eg : ARL)
		cacheCRLSource.initTable();
		RevocationToken crlRevocationToken = cacheCRLSource.getRevocationToken(certificateToken, certificateToken);
		// end::demo-cached[]

	}

}
