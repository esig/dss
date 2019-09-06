package eu.europa.esig.dss.cookbook.example.snippets;

import java.sql.SQLException;

import javax.sql.DataSource;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.ocsp.JdbcCacheOCSPSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

public class OCSPSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) throws SQLException {

		OCSPSource ocspSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

		DataSource dataSource = null;
		OnlineOCSPSource onlineOCSPSource = null;

		// tag::demo-cached[]
		JdbcCacheOCSPSource cacheOCSPSource = new JdbcCacheOCSPSource();
		cacheOCSPSource.setDataSource(dataSource);
		cacheOCSPSource.setProxySource(onlineOCSPSource);
		Long threeMinutes = (long) (60 * 3);
		cacheOCSPSource.setDefaultNextUpdateDelay(threeMinutes); // default nextUpdateDelay (if not defined in the revocation data)
		cacheOCSPSource.initTable();
		RevocationToken ocspRevocationToken = cacheOCSPSource.getRevocationToken(certificateToken, certificateToken);
		// end::demo-cached[]

	}

}
