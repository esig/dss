package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.cert.X509CRL;
import java.util.ArrayList;

/**
 * This class allows to handle a list CRL source.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ListCRLSource extends OfflineCRLSource {

	/**
	 * This is the constructor for this class, it allows to instantiate the list which will contain all {@code X509CRL}.
	 */
	public ListCRLSource() {
		x509CRLList = new ArrayList<X509CRL>();
	}

	/**
	 * This constructor allows to initialize the list of {@code X509CRL} from an {@code OfflineCRLSource}.
	 *
	 * @param crlSource
	 */
	public ListCRLSource(final OfflineCRLSource crlSource) {

		x509CRLList = new ArrayList<X509CRL>(crlSource.getContainedX509CRLs());
	}

	/**
	 * This method allows to add all {@code X509CRL} from one {@code OfflineCRLSource} to this one. If the {@code X509CRL} exists already within the current source then it is
	 * ignored.
	 *
	 * @param offlineCRLSource the source to be added
	 */
	public void addAll(final OfflineCRLSource offlineCRLSource) {

		for (X509CRL x509CRL : offlineCRLSource.x509CRLList) {

			if (!x509CRLList.contains(x509CRL)) {
				x509CRLList.add(x509CRL);
			}
		}
	}
}
