package eu.europa.esig.dss.jades;

import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import org.jose4j.jwx.CompactSerializer;

import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.model.DSSDocument;

public class JWSCompactSerializationParser {

	private final DSSDocument document;

	public JWSCompactSerializationParser(DSSDocument document) {
		this.document = document;
	}

	public JWS parse() {
		try (Scanner scanner = new Scanner(document.openStream(), StandardCharsets.UTF_8.name())) {
			String compactSerialization = scanner.nextLine();
			String[] parts = CompactSerializer.deserialize(compactSerialization);
			return new JWS(parts);
		}
	}

}
