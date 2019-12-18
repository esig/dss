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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class SingleTimestampValidator extends AbstractDocumentValidator implements TimestampValidator {

	protected final TimestampToken timestampToken;
	protected final DSSDocument timestampedData;

	public SingleTimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData, final TimestampType timestampType,
			CertificatePool validationCertPool) {
		this(buildTimestampToken(timestampFile, timestampType, validationCertPool), timestampedData, validationCertPool);
		this.document = timestampFile;
	}

	public SingleTimestampValidator(final TimestampToken timestampToken, final DSSDocument timestampedData, CertificatePool validationCertPool) {
		Objects.requireNonNull(timestampToken, "The TimestampToken must be defined!");
		Objects.requireNonNull(timestampedData, "The timestampedData must be defined!");
		this.timestampToken = timestampToken;
		this.timestampedData = timestampedData;
		this.validationCertPool = validationCertPool;

		timestampToken.matchData(timestampedData);
	}

	@Override
	protected void assertConfigurationValid() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
	}

	private static TimestampToken buildTimestampToken(final DSSDocument timestampFile, final TimestampType timestampType, CertificatePool validationCertPool) {
		Objects.requireNonNull(timestampFile, "The timestampFile must be defined!");
		Objects.requireNonNull(timestampType, "The TimestampType must be defined!");

		TimestampToken timestampToken;
		try {
			timestampToken = new TimestampToken(DSSUtils.toByteArray(timestampFile), timestampType, validationCertPool);
		} catch (CMSException | TSPException | IOException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
		timestampToken.setFileName(timestampFile.getName());
		return timestampToken;
	}

	@Override
	public Map<TimestampToken, List<SignatureScope>> getTimestamps() {
		Map<TimestampToken, List<SignatureScope>> timestamps = new HashMap<TimestampToken, List<SignatureScope>>();
		timestamps.put(getTimestamp(), getTimestampSignatureScope());
		return timestamps;
	}
	
	/**
	 * Returns a list of timestamp signature scopes (timestamped data)
	 * 
	 * @return a list of {@link SignatureScope}s
	 */
	protected List<SignatureScope> getTimestampSignatureScope() {
		SignatureScope signatureScope = null;
		if (timestampedData instanceof DigestDocument) {
			signatureScope = new DigestSignatureScope("Digest document", ((DigestDocument)timestampedData).getExistingDigest());
		} else {
			signatureScope = new FullSignatureScope("Full document", DSSUtils.getDigest(getDefaultDigestAlgorithm(), timestampedData));
		}
		return Arrays.asList(signatureScope);
	}
	
	/**
	 * Returns a single TimestampToken to be validated
	 * 
	 * @return {@link TimestampToken}
	 */
	public TimestampToken getTimestamp() {
		return timestampToken;
	}

}
