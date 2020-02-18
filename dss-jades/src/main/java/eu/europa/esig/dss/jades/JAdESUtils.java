package eu.europa.esig.dss.jades;

import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.ADO_TST;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_D;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PID;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_PL;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SIG_T;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_ATS;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.SR_CM;
import static eu.europa.esig.dss.jades.JAdESHeaderParameterNames.X5T_O;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jose4j.base64url.Base64Url;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.lang.StringUtil;

public class JAdESUtils {
	
	/**
	 * Contains header names that are supported to be present in the critical attribute
	 */
	private static final Set<String> criticalHeaders;
	
	static {
		// JAdES EN 119-812 constraints
		criticalHeaders = Stream.of(SIG_T, X5T_O, SR_CM, SIG_PL, SR_ATS, ADO_TST, SIG_PID, SIG_D)
				.collect(Collectors.toSet());
		criticalHeaders.add(HeaderParameterNames.BASE64URL_ENCODE_PAYLOAD); // b64 #RFC7797
	}
	
	/**
	 * Returns ASCII-encoded array
	 * 
	 * @param str {@link String} to encode to ASCII
	 * @return byte array
	 */
	public static byte[] getAsciiBytes(String str) {
		return StringUtil.getBytesAscii(str);
	}
	
	/**
	 * Returns a base64Url encoded string
	 * 
	 * @param binary a byte array to encode
	 * @return base64Url encoded {@link String}
	 */
	public static String toBase64Url(byte[] binary) {
		return Base64Url.encode(binary);
	}
	
	/**
	 * Concatenates the given strings with a '.' (dot) between.
	 * Example: "xxx", "yyy", "zzz" -> "xxx.yyy.zzz"
	 * 
	 * @param strings a list of {@link String}s to concatenate
	 * @return a concatenation string result
	 */
	public static String concatenate(String... strings) {
		return CompactSerializer.serialize(strings);
	}
	
	/**
	 * Returns array of supported critical headers
	 * 
	 * @return array of supported critical header strings
	 */	
	public static String[] getSupportedCriticalHeaders() {
		return criticalHeaders.toArray(new String[criticalHeaders.size()]);
	}

}
