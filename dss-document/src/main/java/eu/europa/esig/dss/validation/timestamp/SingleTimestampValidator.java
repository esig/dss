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
import java.util.List;

import org.bouncycastle.tsp.TSPException;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.AbstractDocumentValidator;
import eu.europa.esig.dss.validation.DiagnosticDataBuilder;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.executor.SignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.timestamp.SignatureAndTimestampProcessExecutor;

public class SingleTimestampValidator extends AbstractDocumentValidator implements TimestampValidator {

	private final DSSDocument timestampedData;
	private final TimestampType timestampType;
	
	public SingleTimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData) {
		this(timestampFile, timestampedData, null);
	}
	
	public SingleTimestampValidator(final DSSDocument timestampFile, final DSSDocument timestampedData, final TimestampType timestampType) {
		this.document = timestampFile;
		this.timestampedData = timestampedData;
		this.timestampType = timestampType;
	}
	
	@Override
	protected SignatureProcessExecutor getDefaultProcessExecutor() {
		return new SignatureAndTimestampProcessExecutor();
	}
	
	@Override
	public List<TimestampToken> getTimestamps() {
		return Arrays.asList(getTimestamp());
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
	
	@Override
	protected DiagnosticDataBuilder prepareDiagnosticDataBuilder(final ValidationContext validationContext, final ValidationPolicy validationPolicy) {
		
		List<TimestampToken> timestampTokens = getTimestamps();
		for (TimestampToken timestampToken : timestampTokens) {
			validationContext.addTimestampTokenForVerification(timestampToken);
			CertificateToken issuer = validationCertPool.getIssuer(timestampToken);
			if (issuer != null) {
				validationContext.addCertificateTokenForVerification(issuer);
			}
		}
		
		validationContext.initialize(certificateVerifier);
		validationContext.validate();
		
		return super.prepareDiagnosticDataBuilder(validationContext, validationPolicy).setExternalTimestamps(timestampTokens);
	}

}
