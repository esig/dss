package eu.europa.esig.dss.xades.extension;

/* DSS-1765 */
public class XAdESExtensionTToLTWithSelfSignedTest extends XAdESExtensionTToLTTest {

	@Override
	protected String getSigningAlias() {
		return SELF_SIGNED_USER;
	}

}
