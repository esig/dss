package eu.europa.esig.dss.service.http.commons;

import java.net.URLDecoder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapURLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(LdapURLUtils.class);
	
	private LdapURLUtils() {
	}
	
	/**
	 * RFC 4516 Lightweight Directory Access Protocol (LDAP):
     * Uniform Resource Locator
     *                  
     * 2.1.  Percent-Encoding
     * An octet MUST be encoded using the percent-encoding mechanism
     * described in section 2.1 of [RFC3986] in any of these situations:
     * - The octet is not in the reserved set defined in section 2.2 of
     *   [RFC3986] or in the unreserved set defined in section 2.3 of [RFC3986].
     *   
     *   Must be implemented by URI provider:
     * - It is the single Reserved character '?' and occurs inside a 'dn',
     *   'filter', or other element of an LDAP URL.
     * - It is a comma character ',' that occurs inside an 'exvalue'.
	 * @param str {@link String} ldap uri to encode
	 * @return encoded {@link String} ldap uri
	 */
	public static String encode(String str) {
		
		char[] legalChars = { 
				// reserved characters
				':' , '/' , '?' , '#' , '[' , ']' , '@', // gen-delims
				'!' , '$' , '&' , '\'' , '(' , ')', // sub-delims
	            '*' , '+' , ',' , ';' , '=',
	            // unreserved characters
	            '-' , '.' , '_' , '~',
		};
		
		StringBuilder url = new StringBuilder();
		char curChar;
		boolean encoded = false;
		
		for (int i = 0; i < str.length(); i++) {
			curChar = str.charAt(i);
			if (Character.isLetter(curChar) || Character.isDigit(curChar) || contains(legalChars, curChar) || charIsEncoded(str, i)) {
				url.append(curChar);
			} else {
				url.append(getEncodedChar(curChar));
				encoded = true;
			}
		}
		if (encoded) {
			LOG.warn("The obtained ldap url [{}] contains illegal characters. Use encoded address instead : [{}]", str, url);
		}
		return url.toString();
	}
	
	private static boolean contains(char[] chars, char c) {
		for (char ch : chars) {
			if (ch == c) {
				return true;
			}
		}
		return false;
	}
	
	private static String getEncodedChar(char c) {
		String enc = Integer.toHexString(c);
		return enc.length() == 1 ? "%0" + enc : "%" + enc;
	}
	
	private static boolean charIsEncoded(String str, int i) {
		try {
			if (str.charAt(i) != '%') {
				return false;
			}
			String subString = str.substring(i, i+3);
			if (!subString.equals(URLDecoder.decode(subString, "UTF-8"))) {
				return true;
			}
		} catch (Exception e) {
			LOG.trace("Cannot decode a part of string [{}] starting from position with index [{}]", str, i);
			return false;
		}
		return false;
	}

}
