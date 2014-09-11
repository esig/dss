/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESLevelBaselineB;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.TimestampInclude;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimestampService {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampService.class);

	private TSPSource tspSource;
	private CertificatePool certificatePool;
	private XPathQueryHolder xPathQueryHolder;

	//These two variables are used as envelopes in order to create a fake, temporary signature aimed at building XAdES content timestamps
	private final String begin = "<?xml version=\"1.0\" encoding=\"utf-8\"?><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"Signature-51473554\">";
	private final String end = "<ds:SignatureValue Id=\"ID_2640579564\">bUkiVxIMU1ixRho/W1gJWaPLvahcpmDMoVtNUuJLxSEvGxIfZaXzsGuZMKRLoyPVmWodivwDah5DhQ77SMolHDFbi/0nfDJ7l2h2dhQsoQNbZJODF/WAhuw0zfs8PsdGirRhIdjs/M1m8Y7DXFL4Wy84dFKDDaYRWOZby0GJ9oc=</ds:SignatureValue>" +
			"<ds:KeyInfo>" +
			"<ds:KeyValue>" +
			"<ds:RSAKeyValue>" +
			"<ds:Modulus>kKk8sPvKC4RN1/W8Uqan2zgqNCH2Uh6I4/uQPha25W6Lz6poWuxmi9y8/iCR2anbFb1k4n3d0eJxzWzdD4ubz478it9J0jhFi/4ANFJG+FVrWqH9gw/nXnfy2nULQOY466HE172mIAjKjWdPrpo6z1IRWHYbzNbL4iSO8BxqMx0=</ds:Modulus>" +
			"<ds:Exponent>AQAB</ds:Exponent>" +
			"</ds:RSAKeyValue>" +
			"</ds:KeyValue>" +
			"</ds:KeyInfo>" +
			"</ds:Signature>";

	public TimestampService(TSPSource tspSource, CertificatePool certificatePool) {
		this.tspSource = tspSource;
		this.certificatePool = certificatePool;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSSDocument
	 *
	 * @param externalParameters
	 * @return contentTimestamp as an InMemoryDocument
	 */
	public DSSDocument generateCAdESContentTimestamp(final SignatureParameters externalParameters) {

		TimestampToken contentTimestampToken = generateCAdESContentTimestampAsTimestampToken(externalParameters);
		InMemoryDocument document = new InMemoryDocument(contentTimestampToken.getEncoded());

		return document;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSS TimestampToken
	 * @param externalParameters the timestamp parameters to consider
	 * @return the ContentTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateCAdESContentTimestampAsTimestampToken( final SignatureParameters externalParameters) {

		TimestampToken token = generateTimestampToken(TimestampType.CONTENT_TIMESTAMP, externalParameters, externalParameters.getDetachedContent().getBytes());
		return token;
	}


	/**
	 * @param externalParameters
	 * @param timestampType
	 * @return
	 */
	public TimestampToken generateXAdESContentTimestampAsTimestampToken(final DSSDocument toSignDocument, final SignatureParameters externalParameters, final TimestampType timestampType) {

		xPathQueryHolder = new XPathQueryHolder();

		//1. Set initial parameters
		SignatureParameters signatureParameters = new SignatureParameters();
		signatureParameters.setReferences(externalParameters.getReferences());
		signatureParameters.setSignatureTimestampParameters(externalParameters.getSignatureTimestampParameters());

		//2. Build temporary signature structure
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier(true);
		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(commonCertificateVerifier);
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		final byte[] dataToSign = levelBaselineB.getDataToSign(toSignDocument, signatureParameters);
		final String signatureValue = new String(dataToSign);

		final String signature = begin + signatureValue + end;

		//3. Validate signature, in order to retrieve the references from the validator
		DSSDocument toValidate = new InMemoryDocument(signature.getBytes());
		final SignedDocumentValidator validator = XMLDocumentValidator.fromDocument(toValidate);
		validator.setCertificateVerifier(commonCertificateVerifier);
		List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(toSignDocument);
		validator.setDetachedContents(detachedContents);
		final Reports reports = validator.validateDocument();

		final List<AdvancedSignature> signatures = validator.getSignatures();
		final XAdESSignature xAdESSignature = (XAdESSignature) signatures.get(0);
		final List<Reference> references = xAdESSignature.getReferences();

		LOG.debug("Building ContentTimestamp - Concatenating references...");

		//4. Concatenate byte value of references, excluding references of type SignedProperties
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		for (final Reference reference : references) {
			if (! xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType())) {
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

		//5. Generate ContentTimestamp using the concatenated references
		switch (timestampType) {
			case ALL_DATA_OBJECTS_TIMESTAMP: return generateTimestampToken(timestampType, externalParameters, buffer.toByteArray());
			case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP: return generateTimestampToken(timestampType, externalParameters, buffer.toByteArray());
			default: throw new DSSException("Incompatible timestamp type");
		}
	}

	/**
	 *
	 * @param externalParameters
	 * @param timestampType
	 * @return
	 */
	public DSSDocument generateXAdESContentTimestampAsDSSDocument(final DSSDocument toSignDocument, final SignatureParameters externalParameters, final TimestampType timestampType) {
		return new InMemoryDocument(generateXAdESContentTimestampAsTimestampToken(toSignDocument, externalParameters, timestampType).getEncoded());
	}

	/**
	 * @param timestampType
	 * @return
	 */
	public TimestampToken generateTimestampToken(final TimestampType timestampType, final SignatureParameters signatureParameters, final byte[] references) {

		byte[] digest = DSSUtils.digest(signatureParameters.getContentTimestampParameters().getDigestAlgorithm(), references);
		final TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(signatureParameters.getContentTimestampParameters().getDigestAlgorithm(), digest);
		TimestampToken token = new TimestampToken(timeStampResponse, timestampType, certificatePool);

		token.setCanonicalizationMethod(signatureParameters.getContentTimestampParameters().getCanonicalizationMethod());

		//Case of XAdES INDIVIDUAL DATA OBJECTS TIMESTAMP: Timestamp Includes must be generated for each reference
		if (TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timestampType)) {
			List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
			for (DSSReference reference : signatureParameters.getReferences()) {
				TimestampInclude include = new TimestampInclude(reference.getUri(), "true");
				includes.add(include);
			}
			token.setTimestampIncludes(includes);
		}
		return token;
	}
}
