package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

public class OCSPSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) {

		OCSPSource ocspSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		OCSPToken ocspToken = ocspSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

	}

}
