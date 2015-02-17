package eu.europa.ec.markt.dss.mock;

import java.io.InputStream;
import java.security.cert.X509CRL;
import java.util.ArrayList;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;

/**
 * This class allows to provide a mock CRL source based on the list of
 * individual CRL(s);
 *
 */
public class MockCRLSource extends OfflineCRLSource {

	private static final long serialVersionUID = -985602836642741439L;

	/**
	 * This constructor allows to build a mock CRL source from a list of
	 * resource paths.
	 *
	 * @param paths
	 */
	public MockCRLSource(final String... paths) {
		x509CRLList = new ArrayList<X509CRL>();
		for (final String pathItem : paths) {
			final InputStream inputStream = getClass().getResourceAsStream(pathItem);
			addCRLToken(inputStream);
		}
	}

	/**
	 * This constructor allows to build a mock CRL source from a list of
	 * <code>InputStream</code>.
	 *
	 * @param inputStreams
	 *            the list of <code>InputStream</code>
	 */
	public MockCRLSource(final InputStream... inputStreams) {
		x509CRLList = new ArrayList<X509CRL>();
		for (final InputStream inputStream : inputStreams) {
			addCRLToken(inputStream);
		}
	}

	private void addCRLToken(final InputStream inputStream) {
		final X509CRL x509CRL = DSSUtils.loadCRL(inputStream);
		if (!x509CRLList.contains(x509CRL)) {
			x509CRLList.add(x509CRL);
		}
	}
}
