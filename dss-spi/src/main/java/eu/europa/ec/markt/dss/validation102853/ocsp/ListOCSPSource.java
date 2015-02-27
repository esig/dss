package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;

import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ListOCSPSource extends OfflineOCSPSource {

	protected List<BasicOCSPResp> basicOCSPRespList = null;

	public ListOCSPSource() {

		basicOCSPRespList = new ArrayList<BasicOCSPResp>();
	}

	/**
	 * This constructor allows to initialize the list of {@code BasicOCSPResp} from an {@code OfflineOCSPSource}.
	 *
	 * @param ocspSource
	 */
	public ListOCSPSource(final OfflineOCSPSource ocspSource) {

		basicOCSPRespList = new ArrayList<BasicOCSPResp>(ocspSource.getContainedOCSPResponses());
	}

	@Override
	public List<BasicOCSPResp> getContainedOCSPResponses() {
		return basicOCSPRespList;
	}

	/**
	 * This method allows to add all {@code BasicOCSPResp} from one {@code OfflineOCSPSource} to this one. If the {@code BasicOCSPResp} exists already within the current source
	 * then it is ignored.
	 *
	 * @param offlineOCSPSource the source to be added
	 */
	public void addAll(final OfflineOCSPSource offlineOCSPSource) {

		for (BasicOCSPResp basicOCSPResp : offlineOCSPSource.getContainedOCSPResponses()) {

			if (!basicOCSPRespList.contains(basicOCSPResp)) {
				basicOCSPRespList.add(basicOCSPResp);
			}
		}
	}
}
