package eu.europa.ec.markt.dss.cookbook.sources;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.List;

import eu.europa.ec.markt.dss.cookbook.example.Cookbook;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.JKSSignatureToken;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class JksCertificateInformation {

	public static void main(final String[] args) {

		URL url = null;
		try {
			url = new File(Cookbook.getPathFromResource("/myJks.jks")).toURI().toURL();
		} catch (final MalformedURLException e) {
			e.printStackTrace();
		}
		System.out.println(url.toString());
		JKSSignatureToken jksSignatureToken = new JKSSignatureToken(url.toString(), "password");

		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

		List<DSSPrivateKeyEntry> keys = jksSignatureToken.getKeys();
		for (DSSPrivateKeyEntry key : keys) {

			CertificateToken certificate = key.getCertificate();
			System.out.println(dateFormat.format(certificate.getNotAfter()) + ": " + certificate.getSubjectX500Principal());
			CertificateToken[] certificateChain = key.getCertificateChain();
			for (CertificateToken x509Certificate : certificateChain) {

				System.out.println("/t" + dateFormat.format(x509Certificate.getNotAfter()) + ": " + x509Certificate.getSubjectX500Principal());

			}
		}
		System.out.println("DONE");
	}
}
