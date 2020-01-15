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
package eu.europa.esig.dss.validation.timestamp;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificatePool;
import eu.europa.esig.dss.validation.AbstractDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class SingleTimestampValidator extends AbstractDocumentValidator implements TimestampValidator {

	protected final TimestampType timestampType;

	protected DSSDocument timestampedData;
	protected TimestampToken timestampToken;

	public SingleTimestampValidator(final DSSDocument timestampFile) {
		this(timestampFile, TimestampType.CONTENT_TIMESTAMP);
	}

	public SingleTimestampValidator(final DSSDocument timestampFile, TimestampType timestampType) {
		this.document = timestampFile;
		this.timestampType = timestampType;
	}

	@Override
	protected void assertConfigurationValid() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
	}

	@Override
	protected List<TimestampToken> getExternalTimestamps() {
		return Collections.singletonList(getTimestamp());
	}
	
	/**
	 * Returns a single TimestampToken to be validated
	 * 
	 * @return {@link TimestampToken}
	 */
	@Override
	public TimestampToken getTimestamp() {
		if (timestampToken == null) {
			Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
			Objects.requireNonNull(document, "The timestampFile must be defined!");
			Objects.requireNonNull(timestampedData, "The timestampedData must be defined!");
			Objects.requireNonNull(timestampType, "The TimestampType must be defined!");

			try {
				timestampToken = new TimestampToken(DSSUtils.toByteArray(document), timestampType, validationCertPool);
				timestampToken.setFileName(document.getName());

				timestampToken.matchData(timestampedData);
			} catch (CMSException | TSPException | IOException e) {
				throw new DSSException("Unable to parse timestamp", e);
			}
		}

		return timestampToken;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		if (ValidationLevel.BASIC_SIGNATURES == validationLevel) {
			throw new IllegalArgumentException("Minimal level is " + ValidationLevel.TIMESTAMPS);
		}
		super.setValidationLevel(validationLevel);
	}

	@Override
	public void setDetachedContent(DSSDocument document) {
		this.timestampedData = document;
	}

	@Override
	public void setValidationCertPool(CertificatePool validationCertPool) {
		this.validationCertPool = validationCertPool;
	}

	/**
	 * Returns a list of timestamp signature scopes (timestamped data)
	 * 
	 * @return a list of {@link SignatureScope}s
	 */
	protected List<SignatureScope> getTimestampSignatureScope() {
		SignatureScope signatureScope = null;
		if (timestampedData instanceof DigestDocument) {
			signatureScope = new DigestSignatureScope("Digest document", ((DigestDocument) timestampedData).getExistingDigest());
		} else {
			signatureScope = new FullSignatureScope("Full document", DSSUtils.getDigest(getDefaultDigestAlgorithm(), timestampedData));
		}
		return Arrays.asList(signatureScope);
	}

}
