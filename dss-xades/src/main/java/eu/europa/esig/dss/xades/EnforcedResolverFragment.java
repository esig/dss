package eu.europa.esig.dss.xades;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.implementations.ResolverFragment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.utils.Utils;

public class EnforcedResolverFragment extends ResolverFragment {

	private static final Logger LOG = LoggerFactory.getLogger(EnforcedResolverFragment.class);

	private static final String XPATH_CHAR_FILTER = "()='[]:,*/ ";

	@Override
	public boolean engineCanResolveURI(ResourceResolverContext context) {
		return super.engineCanResolveURI(context) && checkValueForXpathInjection(context.uriToResolve);
	}

	/**
	 * This method tests the xpath expression against injection.
	 * 
	 * See https://www.owasp.org/index.php/XPATH_Injection_Java
	 * 
	 * @param xpathString
	 *                    the xpath expression to be tested
	 * @return false if the xpath contains forbidden character or if the xpath
	 *         cannot be decoded
	 */
	public boolean checkValueForXpathInjection(String xpathString) {
		if (Utils.isStringEmpty(xpathString)) {
			try {
				String decodedValue = URLDecoder.decode(xpathString, StandardCharsets.UTF_8.name());
				for (char c : decodedValue.toCharArray()) {
					if (XPATH_CHAR_FILTER.indexOf(c) != -1) {
						LOG.warn("Forbidden char '{}' detected", c);
						return false;
					}
				}
			} catch (UnsupportedEncodingException e) {
				LOG.warn("Unable to decode '{}' : {}", xpathString, e.getMessage());
				return false;
			}
		}
		return true;
	}

}
