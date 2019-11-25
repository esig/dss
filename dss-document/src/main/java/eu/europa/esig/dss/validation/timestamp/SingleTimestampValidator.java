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

import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AbstractDocumentValidator;
import eu.europa.esig.dss.validation.executor.timestamp.SignatureAndTimestampProcessExecutor;
import eu.europa.esig.dss.validation.executor.timestamp.TimestampProcessExecutor;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class SingleTimestampValidator extends AbstractDocumentValidator implements TimestampValidator {

	protected final DSSDocument timestampedData;
	protected final TimestampType timestampType;
	
	public SingleTimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData) {
		this(timestampFile, timestampedData, null);
	}
	
	public SingleTimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData, final TimestampType timestampType) {
		Objects.requireNonNull(timestampFile, "The timestampFile must be defined!");
		Objects.requireNonNull(timestampedData, "The timestampedData must be defined!");
		this.document = timestampFile;
		this.timestampedData = timestampedData;
		this.timestampType = timestampType;
	}
	
	@Override
	public TimestampProcessExecutor getDefaultProcessExecutor() {
		return new SignatureAndTimestampProcessExecutor();
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
			signatureScope = new FullSignatureScope("Full document", getDigest(timestampedData));
		}
		return Arrays.asList(signatureScope);
	}
	
	protected Digest getDigest(DSSDocument dssDocument) {
		return new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(dssDocument.getDigest(getDefaultDigestAlgorithm())));
	}
	
	/**
	 * Returns a single TimestampToken to be validated
	 * 
	 * @return {@link TimestampToken}
	 */
	protected TimestampToken getTimestamp() {
		TimestampToken timestampToken;
		try {
			timestampToken = new TimestampToken(DSSUtils.toCMSSignedData(document), timestampType, validationCertPool);
		} catch (TSPException | IOException e) {
			throw new DSSException("Unable to parse timestamp", e);
		}
		timestampToken.setFileName(document.getName());
		timestampToken.matchData(timestampedData);
		return timestampToken;
	}

}
