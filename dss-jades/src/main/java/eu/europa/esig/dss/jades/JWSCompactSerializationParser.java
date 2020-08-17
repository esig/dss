package eu.europa.esig.dss.jades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import org.jose4j.jwx.CompactSerializer;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;

/**
 * The class is used to parse a Compact JWS
 *
 */
public class JWSCompactSerializationParser {

	private final static int NUMBER_DOTS = 2;

	private final DSSDocument document;

	public JWSCompactSerializationParser(DSSDocument document) {
		this.document = document;
	}

	/**
	 * Parses the provided document and returns a JWS Compact signature if found
	 * 
	 * @return {@link JWS}
	 */
	public JWS parse() {
		try (Scanner scanner = new Scanner(document.openStream(), StandardCharsets.UTF_8.name())) {
			String compactSerialization = scanner.nextLine();
			String[] parts = CompactSerializer.deserialize(compactSerialization);
			return new JWS(parts);
		}
	}
	
	/**
	 * Verifies if the provided file is a Compact JWS
	 * 
	 * @return TRUE if the document is a Compact JWS and supported by the parser, FALSE otherwise
	 */
	public boolean isSupported() {
		int separatorCounter = 0;
		try (InputStream is = document.openStream()) {
			int b = -1;
			while ((b = is.read()) != -1) {
				byte currentByte = (byte) b;
				
				if (currentByte == '.') {
					separatorCounter++;
					if (separatorCounter > NUMBER_DOTS) {
						return false;
					}
				} else if (JAdESUtils.isBase64UrlEncoded(currentByte)) {
					// continue
				} else if (separatorCounter == 1 && JAdESUtils.isUrlSafe(currentByte)) {
					// continue (payload can be not Base64Url encoded)
				} else {
					return false;
				}
			}

			if (separatorCounter != NUMBER_DOTS) {
				return false;
			}

		} catch (IOException e) {
			throw new DSSException(String.format("Cannot read the document. Reason : %s", e.getMessage()), e);
		}
		return true;
	}

}
