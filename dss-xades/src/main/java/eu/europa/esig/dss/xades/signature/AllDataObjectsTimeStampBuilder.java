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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.ReferenceBuilder;
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;
import eu.europa.esig.dss.xades.reference.ReferenceProcessor;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * This class allows to create a XAdES content-timestamp which covers all documents (AllDataObjectsTimeStamp).
 * 
 */
public class AllDataObjectsTimeStampBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(AllDataObjectsTimeStampBuilder.class);

	/** The TSPSource to use */
	private final TSPSource tspSource;

	/** Signature parameters */
	private final XAdESSignatureParameters signatureParameters;

	/**
	 * Default constructor
	 *
	 * @param tspSource {@link TSPSource}
	 * @param signatureParameters {@link XAdESSignatureParameters}
	 */
	public AllDataObjectsTimeStampBuilder(TSPSource tspSource, XAdESSignatureParameters signatureParameters) {
		this.tspSource = tspSource;
		this.signatureParameters = signatureParameters;
	}

	/**
	 * Builds a message-imprint from the given document and generates a timestamp
	 *
	 * @param document {@link DSSDocument} to timestamp
	 * @return {@link TimestampToken}
	 */
	public TimestampToken build(DSSDocument document) {
		return build(Arrays.asList(document));
	}

	/**
	 * Timestamps the list of documents
	 *
	 * @param documents a list of {@link DSSDocument}s to timestamp
	 * @return {@link TimestampToken}
	 */
	public TimestampToken build(List<DSSDocument> documents) {
		// Prepare references
		ReferenceBuilder referenceBuilder = new ReferenceBuilder(documents, signatureParameters);
		List<DSSReference> references = signatureParameters.getReferences();
		if (Utils.isCollectionNotEmpty(references)) {
			referenceBuilder.checkReferencesValidity();
		} else {
			references = referenceBuilder.build();
			signatureParameters.setReferences(references);
		}

		byte[] dataToBeDigested;
		XAdESTimestampParameters contentTimestampParameters = signatureParameters.getContentTimestampParameters();
		String canonicalizationMethod = contentTimestampParameters.getCanonicalizationMethod();
		
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			for (DSSReference reference : references) {
				/*
				 * 1) process the retrieved ds:Reference element according to the reference-processing model of XMLDSIG [1]
				 * clause 4.4.3.2;
				 */
				ReferenceProcessor referenceProcessor = new ReferenceProcessor(signatureParameters);
				DSSDocument referenceContent = referenceProcessor.getReferenceOutput(reference);
				byte[] binaries = DSSUtils.toByteArray(referenceContent);
				/*
				 * 2) if the result is a XML node set, canonicalize it as specified in clause 4.5; and
				 */
				if (ReferenceOutputType.NODE_SET.equals(DSSXMLUtils.getReferenceOutputType(reference)) && DomUtils.isDOM(binaries)) {
					binaries = DSSXMLUtils.canonicalize(canonicalizationMethod, binaries);
				}
				/*
				 * 3) concatenate the resulting octets to those resulting from previously processed ds:Reference elements in
				 * ds:SignedInfo.
				 */
				baos.write(binaries);
			}
			dataToBeDigested = baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException("Unable to compute the data to be digested", e);
		}

		if (LOG.isTraceEnabled()) {
			LOG.trace("Computed AllDataObjectsTimestampData bytes:");
			LOG.trace(new String(dataToBeDigested));
		}
		
		DigestAlgorithm digestAlgorithm = contentTimestampParameters.getDigestAlgorithm();

		byte[] digestToTimestamp = DSSUtils.digest(digestAlgorithm, dataToBeDigested);
		TimestampBinary timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, digestToTimestamp);
		try {
			TimestampToken token = new TimestampToken(timeStampResponse.getBytes(), TimestampType.ALL_DATA_OBJECTS_TIMESTAMP);
			token.setCanonicalizationMethod(canonicalizationMethod);
			return token;
		} catch (TSPException | IOException | CMSException e) {
			throw new DSSException("Cannot build an AllDataObjectsTimestamp", e);
		}
	}

}
