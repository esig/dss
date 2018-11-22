package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;

public class CRLSourceSnippet {

	@SuppressWarnings({ "unused", "null" })
	public static void main(String[] args) {

		CRLSource crlSource = null;
		CertificateToken certificateToken = null;
		CertificateToken issuerCertificateToken = null;

		// tag::demo[]
		CRLToken crlToken = crlSource.getRevocationToken(certificateToken, issuerCertificateToken);
		// end::demo[]

	}

}
