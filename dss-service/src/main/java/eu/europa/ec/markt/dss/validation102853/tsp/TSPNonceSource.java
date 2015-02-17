package eu.europa.ec.markt.dss.validation102853.tsp;

import java.math.BigInteger;

/**
 * This class implements a dedicated  nonce source.
 *
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class TSPNonceSource {


	public BigInteger getNonce() {

		final long nonceValue = System.currentTimeMillis();
		final BigInteger nonce = BigInteger.valueOf(nonceValue);
		return nonce;
	}
}
