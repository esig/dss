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
package eu.europa.esig.dss.cookbook.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.TimestampParameters;
import eu.europa.esig.dss.XPathQueryHolder;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.TimestampInclude;
import eu.europa.esig.dss.validation.TimestampToken;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.TimestampType;
import eu.europa.esig.dss.x509.tsp.TSPSource;
import eu.europa.esig.dss.xades.DSSReference;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESLevelBaselineB;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;

/**
 * Class providing (content) timestamp generating methods
 */
public class TimestampService {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampService.class);

	private final TSPSource tspSource;
	private final CertificatePool certificatePool;
	private final XPathQueryHolder xPathQueryHolder;
	private final CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier(true);


	// TODO (12/09/2014): To be replaced for the new release (4.2.0)
	private final String fakeSignatureValue = "kKk8sPvKC4RN1/W8Uqan2zgqNCH2Uh6I4/uQPha25W6Lz6poWuxmi9y8/iCR2anbFb1k4n3d0eJxzWzdD4ubz478it9J0jhFi/4ANFJG+FVrWqH9gw/nXnfy2nULQOY466HE172mIAjKjWdPrpo6z1IRWHYbzNbL4iSO8BxqMx0=";

	/**
	 * Basic constructor, new CertificatePool created
	 *
	 * @param tspSource The TSPSource to be used for the Timestamp generation
	 */
	public TimestampService(final TSPSource tspSource) {
		if (tspSource == null) {
			throw new NullPointerException();
		}
		this.tspSource = tspSource;
		certificatePool = new CertificatePool();
		xPathQueryHolder = new XPathQueryHolder();
	}


	/**
	 * Alternative constructor
	 *
	 * @param tspSource       The TSPSource to be used for the Timestamp generation
	 * @param certificatePool The CertificatePool to be used for the TimestampToken
	 */
	public TimestampService(final TSPSource tspSource, final CertificatePool certificatePool) {

		if (tspSource == null) {
			throw new NullPointerException();
		}
		this.tspSource = tspSource;

		if (certificatePool == null) {
			throw new NullPointerException();
		}
		this.certificatePool = certificatePool;
		xPathQueryHolder = new XPathQueryHolder();
	}

	/**
	 * Method that generates a ContentTimestamp as a DSSDocument
	 *
	 * @param externalParameters the original signature parameters
	 * @return contentTimestamp as an InMemoryDocument
	 */
	public DSSDocument generateCAdESContentTimestamp(final XAdESSignatureParameters externalParameters) {

		final TimestampToken contentTimestampToken = generateCAdESContentTimestampAsTimestampToken(externalParameters);
		final InMemoryDocument document = new InMemoryDocument(contentTimestampToken.getEncoded());

		return document;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSS TimestampToken
	 * *
	 *
	 * @param externalParameters the original signature parameters
	 * @return the ContentTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateCAdESContentTimestampAsTimestampToken(final XAdESSignatureParameters externalParameters) {

		final byte[] bytes = externalParameters.getDetachedContent().getBytes();
		final TimestampToken token = generateTimestampToken(TimestampType.CONTENT_TIMESTAMP, externalParameters, bytes);
		return token;
	}

	/**
	 * Method that generates a XAdES ContentTimestamp (either an ALL DATA OBJECTS TIMESTAMP or an INDIVIDUAL DATA OBJECTS TIMESTAMP) and returns
	 * it as a TimestampToken
	 *
	 * @param toSignDocument
	 * @param externalParameters
	 * @param timestampType
	 * @return
	 */
	public TimestampToken generateXAdESContentTimestampAsTimestampToken(final DSSDocument toSignDocument, final XAdESSignatureParameters externalParameters,
			final TimestampType timestampType) {

		if (externalParameters == null) {
			throw new NullPointerException();
		}
		//1. Set initial parameters
		final XAdESSignatureParameters signatureParameters = setSignatureParameters(externalParameters);

		//2. Build temporary signature structure
		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(commonCertificateVerifier);

		byte[] signatureValueBytes = Base64.decodeBase64(fakeSignatureValue);
		final DSSDocument fullSignature = levelBaselineB.signDocument(toSignDocument, signatureParameters, signatureValueBytes);

		final List<Reference> references = getReferencesFromValidatedSignature(toSignDocument, fullSignature);

		//4. Concatenate byte value of references, excluding references of type SignedProperties
		byte[] concatenatedReferences = concatenateReferencesAsByteArray(references);

		//5. Generate ContentTimestamp using the concatenated references
		switch (timestampType) {
			case ALL_DATA_OBJECTS_TIMESTAMP:
			case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
				return generateTimestampToken(timestampType, externalParameters, concatenatedReferences);
			default:
				throw new DSSException("Incompatible timestamp type");
		}
	}

	/**
	 * Concatenates a set of given {@code Reference} into a byte array
	 *
	 * @param references the references to concatenate
	 * @return the concatenated references as a byte array
	 */
	private byte[] concatenateReferencesAsByteArray(final List<Reference> references) {

		LOG.debug("Building ContentTimestamp - Concatenating references...");
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		for (final Reference reference : references) {
			//References of type "SignedProperties" are excluded
			if (!xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType())) {
				try {
					final byte[] referencedBytes = reference.getReferencedBytes();
					buffer.write(referencedBytes);
				} catch (XMLSignatureException e) {
					throw new DSSException(e);
				} catch (IOException e) {
					throw new DSSException(e);
				}
			}
		}
		LOG.debug("Result: " + new String(buffer.toByteArray()));
		return buffer.toByteArray();
	}

	/**
	 * Method that generates a XAdES ContentTimestamp (either an ALL DATA OBJECTS TIMESTAMP or an INDIVIDUAL DATA OBJECTS TIMESTAMP) and returns
	 * it as a DSSDocument
	 *
	 * @param toSignDocument     the document for which a content timestamp must be generated
	 * @param externalParameters the original signature parameters
	 * @param timestampType      the contentTimestamp type, either ALL_DATA_OBJECTS_TIMESTAMP or INDIVIDUAL_DATA_OBJECTS_TIMESTAMP
	 * @return a ContentTimestamp as a DSSDocument
	 */
	public DSSDocument generateXAdESContentTimestampAsDSSDocument(final DSSDocument toSignDocument, final XAdESSignatureParameters externalParameters,
			final TimestampType timestampType) {
		final TimestampToken timestampToken = generateXAdESContentTimestampAsTimestampToken(toSignDocument, externalParameters, timestampType);
		return new InMemoryDocument(timestampToken.getEncoded());
	}

	/**
	 * Method that generates a TimestampToken given a TimestampType, a set of signature parameters and a byte array containing the concatenated references
	 *
	 * @param timestampType       The TimestampType for the TimestampToken
	 * @param signatureParameters The signature parameters from which the contentTimestamp parameters must be retrieved
	 * @param references
	 * @return
	 */
	public TimestampToken generateTimestampToken(final TimestampType timestampType, final XAdESSignatureParameters signatureParameters, final byte[] references) {

		if (timestampType == null) {
			throw new NullPointerException();
		}
		if (signatureParameters == null) {
			throw new NullPointerException();
		}
		final TimestampParameters contentTimestampParameters = signatureParameters.getContentTimestampParameters();
		if (contentTimestampParameters == null) {
			throw new NullPointerException();
		}

		final DigestAlgorithm digestAlgorithm = contentTimestampParameters.getDigestAlgorithm();
		if (digestAlgorithm == null) {

			throw new NullPointerException();
		}
		byte[] digest = DSSUtils.digest(digestAlgorithm, references);
		if (LOG.isTraceEnabled()) {

			LOG.trace("Bytes to digest : [" + new String(references) + "]");
			LOG.trace("Digest to timestamp: " + Base64.encodeBase64String(digest));
		}
		final TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, digest);
		final TimestampToken token = new TimestampToken(timeStampResponse, timestampType, certificatePool);

		token.setCanonicalizationMethod(contentTimestampParameters.getCanonicalizationMethod());

		//Case of XAdES INDIVIDUAL DATA OBJECTS TIMESTAMP: Timestamp Includes must be generated for each reference
		if (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timestampType)) {
			addTimestampTokenIncludes(signatureParameters.getReferences(), token);
		}
		return token;
	}

	/**
	 * Method setting the signature parameters used to generate the intermediary signature (XAdES-specific)
	 *
	 * @param externalParameters the original signature parameters
	 * @return a set of signature parameters
	 */
	private XAdESSignatureParameters setSignatureParameters(final XAdESSignatureParameters externalParameters) {

		final XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		signatureParameters.setReferences(externalParameters.getReferences());
		signatureParameters.setSignatureTimestampParameters(externalParameters.getSignatureTimestampParameters());
		signatureParameters.setSigningCertificate(externalParameters.getSigningCertificate());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		return signatureParameters;
	}

	/**
	 * @param toSignDocument
	 * @param signature
	 * @return
	 */
	private SignedDocumentValidator validateTemporarySignature(final DSSDocument toSignDocument, final DSSDocument signature) {

		final SignedDocumentValidator validator = XMLDocumentValidator.fromDocument(signature);
		validator.setCertificateVerifier(commonCertificateVerifier);
		final List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(toSignDocument);
		validator.setDetachedContents(detachedContents);

		return validator;
	}

	/**
	 * Retrieves the references from a validated signature
	 *
	 * @param toSignDocument the document for which a content timestamp must be generated
	 * @param signature      the signature value
	 * @return
	 */
	private List<Reference> getReferencesFromValidatedSignature(final DSSDocument toSignDocument, final DSSDocument signature) {

		final SignedDocumentValidator validator = validateTemporarySignature(toSignDocument, signature);
		// validator.validateDocument();
		final List<AdvancedSignature> signatures = validator.getSignatures();
		final XAdESSignature xAdESSignature = (XAdESSignature) signatures.get(0);
		xAdESSignature.checkSignatureIntegrity();
		final List<Reference> references = xAdESSignature.getReferences();

		return references;
	}

	/**
	 * Adds a set of Timestamp Includes to a given Timestamp Token, based on the references that the Timestamp Token was built upon
	 *
	 * @param references the references the timestamp token was built upon
	 * @param token      the timestamp token to which the includes must be added
	 * @return the updated Timestamp token, containing the set of Includes
	 */
	private TimestampToken addTimestampTokenIncludes(final List<DSSReference> references, final TimestampToken token) {

		final List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
		for (DSSReference reference : references) {

			TimestampInclude include = new TimestampInclude(reference.getUri(), "true");
			includes.add(include);
		}
		token.setTimestampIncludes(includes);

		return token;
	}
}
