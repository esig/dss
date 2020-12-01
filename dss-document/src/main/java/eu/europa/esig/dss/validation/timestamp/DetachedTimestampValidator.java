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

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Detached CMS TimestampToken Validator
 *
 */
public class DetachedTimestampValidator extends SignedDocumentValidator {

	protected TimestampType timestampType;
	protected TimestampToken timestampToken;

	DetachedTimestampValidator() {
	}

	public DetachedTimestampValidator(final DSSDocument timestampFile) {
		this(timestampFile, TimestampType.CONTENT_TIMESTAMP);
	}

	public DetachedTimestampValidator(final DSSDocument timestampFile, TimestampType timestampType) {
		this.document = timestampFile;
		this.timestampType = timestampType;
	}

	@Override
	public boolean isSupported(DSSDocument dssDocument) {
		byte firstByte = DSSUtils.readFirstByte(dssDocument);
		if (DSSASN1Utils.isASN1SequenceTag(firstByte)) {
			return DSSUtils.isTimestampToken(dssDocument);
		}
		return false;
	}

	@Override
	protected void assertConfigurationValid() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
	}

	@Override
	public List<TimestampToken> getDetachedTimestamps() {
		return Collections.singletonList(getTimestamp());
	}

	/**
	 * Returns a single TimestampToken to be validated
	 * 
	 * @return {@link TimestampToken}
	 */
	public TimestampToken getTimestamp() {
		if (timestampToken == null) {
			timestampToken = createTimestampToken();
		}

		return timestampToken;
	}

	private TimestampToken createTimestampToken() {
		Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
		Objects.requireNonNull(document, "The timestampFile must be defined!");
		Objects.requireNonNull(timestampType, "The TimestampType must be defined!");
		try {
			timestampToken = new TimestampToken(DSSUtils.toByteArray(document), timestampType);
			timestampToken.setFileName(document.getName());
			timestampToken.matchData(getTimestampedData());

			List<SignatureScope> signatureScopes = getTimestampSignatureScopes();
			timestampToken.setTimestampScopes(signatureScopes);
			for (SignatureScope signatureScope : signatureScopes) {
				timestampToken.getTimestampedReferences().add(
						new TimestampedReference(signatureScope.getDSSIdAsString(), TimestampedObjectType.SIGNED_DATA));
			}
			return timestampToken;

		} catch (CMSException | TSPException | IOException e) {
			throw new DSSException(String.format("Unable to create a TimestampToken. Reason : %s", e.getMessage()), e);

		}
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		if (ValidationLevel.BASIC_SIGNATURES == validationLevel) {
			throw new IllegalArgumentException("Minimal level is " + ValidationLevel.TIMESTAMPS);
		}
		super.setValidationLevel(validationLevel);
	}

	public void setTimestampedData(DSSDocument document) {
		Objects.requireNonNull(document, "The document is null");
		setDetachedContents(Arrays.asList(document));
	}

	public DSSDocument getTimestampedData() {
		int size = Utils.collectionSize(detachedContents);
		if (size == 0) {
			return null;
		} else if (size > 1) {
			throw new DSSException("Too many files");
		}
		return detachedContents.iterator().next();
	}

	/**
	 * Returns a list of timestamp signature scopes (timestamped data)
	 * 
	 * @return a list of {@link SignatureScope}s
	 */
	protected List<SignatureScope> getTimestampSignatureScopes() {
		DSSDocument timestampedData = getTimestampedData();
		if (timestampedData != null) {
			if (timestampedData instanceof DigestDocument) {
				return Arrays.asList(new DigestSignatureScope("Digest document", ((DigestDocument) timestampedData).getExistingDigest()));
			} else {
				return Arrays.asList(new FullSignatureScope("Full document", DSSUtils.getDigest(getDefaultDigestAlgorithm(), timestampedData)));
			}
		}
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(String signatureId) {
		// TODO
		throw new UnsupportedOperationException();
	}

	@Override
	public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
		// TODO
		throw new UnsupportedOperationException();
	}

}
