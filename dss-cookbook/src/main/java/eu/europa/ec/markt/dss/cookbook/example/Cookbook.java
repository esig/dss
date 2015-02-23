package eu.europa.ec.markt.dss.cookbook.example;

import java.net.URL;

import eu.europa.ec.markt.dss.cookbook.sources.MockTSPSource;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.token.AbstractSignatureTokenConnection;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.Pkcs12SignatureToken;

/**
 * Super-class for all cookbook examples.
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class Cookbook {

	/**
	 * The document to sign
	 */
	static protected DSSDocument toSignDocument;

	/**
	 * The document to extend
	 */
	static protected DSSDocument toExtendDocument;

	/**
	 * The object which is in charge of digesting ans encrypting the data to sign.
	 */
	static protected AbstractSignatureTokenConnection signingToken;

	/**
	 * This object contains the private key associated to the signing certificate.
	 */
	static protected DSSPrivateKeyEntry privateKey;

	/**
	 * This method converts the resource path to the absolute path.
	 *
	 * @param resourcePath
	 *            resource path
	 * @return
	 */
	public static String getPathFromResource(final String resourcePath) {

		URL uri = Cookbook.class.getResource(resourcePath);
		String absolutePath = uri.getPath();
		return absolutePath;
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void prepareXmlDoc() {
		String toSignFilePath = getPathFromResource("/xml_example.xml");
		toSignDocument = new FileDocument(toSignFilePath);
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePdfDoc() {
		String toSignFilePath = getPathFromResource("/hello-world.pdf");
		toSignDocument = new FileDocument(toSignFilePath);
	}

	/**
	 * This method sets the common parameters.
	 */
	protected static void preparePKCS12TokenAndKey() {
		String pkcs12TokenFile = getPathFromResource("/user_a_rsa.p12");
		signingToken = new Pkcs12SignatureToken("password", pkcs12TokenFile);
		privateKey = signingToken.getKeys().get(0);
	}

	protected static MockTSPSource getMockTSPSource() {
		return new MockTSPSource();
	}
}
