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

import eu.europa.esig.dss.jades.JWSJsonSerializationObject;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.policy.DefaultSignaturePolicyValidatorLoader;
import eu.europa.esig.dss.spi.policy.NonASN1SignaturePolicyValidator;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidatorLoader;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * The abstract class for a JWS signature validation
 */
public abstract class AbstractJWSDocumentAnalyzer extends DefaultDocumentAnalyzer {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractJWSDocumentAnalyzer.class);

	/** Cached copy of JWS Json Serialization object */
	private JWSJsonSerializationObject jwsJsonSerializationObject;

	/**
	 * Empty constructor
	 */
	protected AbstractJWSDocumentAnalyzer() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param document {@link DSSDocument} to validate
	 */
	protected AbstractJWSDocumentAnalyzer(DSSDocument document) {
		super();
		Objects.requireNonNull(document, "Document to be validated cannot be null!");

		this.document = document;
		this.jwsJsonSerializationObject = buildJwsJsonSerializationObject();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		final JAdESSignature jadesSignature = (JAdESSignature) advancedSignature;
		try {
			return jadesSignature.getOriginalDocuments();
		} catch (DSSException e) {
			LOG.error("Cannot retrieve a list of original documents");
			return Collections.emptyList();
		}
	}

	/**
	 * Gets the {@code JWSJsonSerializationObject}
	 *
	 * @return {@link JWSJsonSerializationObject}
	 */
	public JWSJsonSerializationObject getJwsJsonSerializationObject() {
		return jwsJsonSerializationObject;
	}

	/**
	 * Builds a {@code JWSJsonSerializationObject}
	 *
	 * @return {@link JWSJsonSerializationObject}
	 */
	protected abstract JWSJsonSerializationObject buildJwsJsonSerializationObject();

	@Override
	public SignaturePolicyValidatorLoader getSignaturePolicyValidatorLoader() {
		DefaultSignaturePolicyValidatorLoader signaturePolicyValidatorLoader = new DefaultSignaturePolicyValidatorLoader();
		signaturePolicyValidatorLoader.setDefaultSignaturePolicyValidator(new NonASN1SignaturePolicyValidator());
		return signaturePolicyValidatorLoader;
	}

}
