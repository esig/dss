/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JWSCompactSerializationParser;
import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;

import java.util.Collections;
import java.util.List;

/**
 * Validates a JWS Compact signature
 */
public class JWSCompactDocumentAnalyzer extends AbstractJWSDocumentAnalyzer {

	/**
	 * Empty constructor
	 */
	public JWSCompactDocumentAnalyzer() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} to validate
	 */
	public JWSCompactDocumentAnalyzer(DSSDocument document) {
		super(document);
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		JWSCompactSerializationParser parser = new JWSCompactSerializationParser(dssDocument);
		return parser.isSupported();
	}

	@Override
	protected List<AdvancedSignature> buildSignatures() {
		JWSJsonSerializationObject jwsJsonSerializationObject = getJwsJsonSerializationObject();
		List<JWS> foundSignatures = jwsJsonSerializationObject.getSignatures();
		if (Utils.isCollectionEmpty(foundSignatures)) {
			throw new DSSException("No signatures is present in the document!");
		}
		// only one signature is supported by compact serialization
		JWS jws = foundSignatures.get(0);
		JAdESSignature jadesSignature = new JAdESSignature(jws);
		jadesSignature.setFilename(document.getName());
		jadesSignature.setSigningCertificateSource(signingCertificateSource);
		jadesSignature.setDetachedContents(detachedContents);
		jadesSignature.initBaselineRequirementsChecker(certificateVerifier);
		validateSignaturePolicy(jadesSignature);
		return Collections.singletonList(jadesSignature);
	}

	@Override
	protected JWSJsonSerializationObject buildJwsJsonSerializationObject() {
		JWSCompactSerializationParser jwsCompactSerializationParser = new JWSCompactSerializationParser(document);
		if (jwsCompactSerializationParser.isSupported()) {
			JWS jws = jwsCompactSerializationParser.parse();
			JWSJsonSerializationObject jwsJsonSerializationObject = DSSJsonUtils.toJWSJsonSerializationObject(jws);
			jwsJsonSerializationObject.setJWSSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
			return jwsJsonSerializationObject;
		}
		throw new IllegalInputException("The given document is not supported by JWSCompactDocumentValidator!");
	}

}
