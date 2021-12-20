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
package eu.europa.esig.dss.asic.common.signature;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.SigningOperation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

/**
 * The abstract class containing the main methods for ASiC signature creation/extension
 */
public abstract class AbstractASiCSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters, 
					CSP extends SerializableCounterSignatureParameters> extends AbstractSignatureService<SP, TP> 
					implements MultipleDocumentsSignatureService<SP, TP>, CounterSignatureService<CSP> {

	private static final long serialVersionUID = 243114076381526665L;

	/**
	 * The default constructor
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	protected AbstractASiCSignatureService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Returns the relevant signature document extension for the implemented format
	 *
	 * @return {@link String} signature extension
	 */
	protected abstract String getExpectedSignatureExtension();

	@Override
	public TimestampToken getContentTimestamp(DSSDocument toSignDocument, SP parameters) {
		return getContentTimestamp(Arrays.asList(toSignDocument), parameters);
	}

	@Override
	public ToBeSigned getDataToSign(DSSDocument toSignDocument, SP parameters) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		return getDataToSign(Arrays.asList(toSignDocument), parameters);
	}

	@Override
	public DSSDocument signDocument(DSSDocument toSignDocument, SP parameters, SignatureValue signatureValue) {
		Objects.requireNonNull(toSignDocument, "toSignDocument cannot be null!");
		return signDocument(Arrays.asList(toSignDocument), parameters, signatureValue);
	}

	@Override
	public DSSDocument timestamp(DSSDocument toTimestampDocument, TP parameters) {
		Objects.requireNonNull(toTimestampDocument, "toTimestampDocument cannot be null!");
		return timestamp(Arrays.asList(toTimestampDocument), parameters);
	}

	/**
	 * Extracts the content (documents) of the ASiC container
	 *
	 * @param archive {@link DSSDocument} representing an ASiC container
	 * @return {@link ASiCContent}
	 */
	protected ASiCContent extractCurrentArchive(DSSDocument archive) {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor(archive);
		return extractor.extract();
	}

	/**
	 * Returns a relevant ASiC container extractor for the given format
	 *
	 * @param archive {@link DSSDocument} to get an extractor for
	 * @return an instance of {@link AbstractASiCContainerExtractor}
	 */
	protected abstract AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive);

	/**
	 * Creates a ZIP-Archive by copying the provided documents to the new container
	 * 
	 * @param asicContent            {@link ASiCContent} to create a new ZIP archive from
	 * @param creationTime           {@link Date} of the archive creation (optional)
	 * @param asicParameters         {@link ASiCParameters} (optional)
	 * @return {@link DSSDocument} the created ASiC Container
	 */
	protected DSSDocument buildASiCContainer(ASiCContent asicContent, Date creationTime,
											 ASiCParameters asicParameters) {
		MimeType mimeType = getMimeType(asicContent, asicParameters);
		if (asicContent.getMimeTypeDocument() == null) {
			DSSDocument mimetypeDocument = createMimetypeDocument(mimeType);
			asicContent.setMimeTypeDocument(mimetypeDocument);
		}

		String zipComment = getZipComment(asicContent, asicParameters, mimeType);
		if (Utils.isStringEmpty(asicContent.getZipComment())) {
			asicContent.setZipComment(zipComment);
		}

		DSSDocument zipArchive = ZipUtils.getInstance().createZipArchive(asicContent, creationTime);
		zipArchive.setMimeType(mimeType);
		return zipArchive;
	}

	private MimeType getMimeType(ASiCContent asicContent, ASiCParameters asicParameters) {
		MimeType mimeType = null;
		DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();
		if (mimeTypeDocument != null) {
			// re-use the same mime-type when extending a container
			mimeType = ASiCUtils.getMimeType(mimeTypeDocument);
		}
		if (mimeType == null) {
			Objects.requireNonNull(asicParameters, "ASiCParameters shall be present for the requested operation!");
			mimeType = ASiCUtils.getMimeType(asicParameters);
		}
		return mimeType;
	}

	private String getZipComment(ASiCContent asicContent, ASiCParameters asicParameters, MimeType mimeType) {
		String zipComment = asicContent.getZipComment();
		if (Utils.isStringNotEmpty(zipComment)) {
			return zipComment;
		} else if (asicParameters != null && asicParameters.isZipComment()) {
			return ASiCUtils.getZipComment(mimeType);
		}
		return Utils.EMPTY_STRING;
	}

	private DSSDocument createMimetypeDocument(final MimeType mimeType) {
		final byte[] mimeTypeBytes = mimeType.getMimeTypeString().getBytes(StandardCharsets.UTF_8);
		return new InMemoryDocument(mimeTypeBytes, ASiCUtils.MIME_TYPE);
	}

	/**
	 * Verifies a validity of counter signature parameters
	 *
	 * @param parameters counter signature parameters to verify
	 */
	protected void assertCounterSignatureParametersValid(CSP parameters) {
		Objects.requireNonNull(parameters.getSignatureIdToCounterSign(), "The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");
	}

	/**
	 * Verifies if incorporation of a SignaturePolicyStore is possible
	 *
	 * @param asicContent {@link ASiCContent}
	 */
	protected void assertAddSignaturePolicyStorePossible(ASiCContent asicContent) {
		if (Utils.isCollectionEmpty(asicContent.getSignatureDocuments())) {
			throw new UnsupportedOperationException(
					"Signature documents of the expected format are not found in the provided ASiC Container! "
					+ "Add a SignaturePolicyStore is not possible!");
		}
	}

	/**
	 * Generates and returns a final name for the archive to create
	 *
	 * @param originalFile {@link DSSDocument} original signed/extended document container
	 * @param operation {@link SigningOperation} the performed signing operation
	 * @param containerMimeType {@link MimeType} the expected mimeType
	 * @return {@link String} the archive filename
	 */
	protected String getFinalArchiveName(DSSDocument originalFile, SigningOperation operation, MimeType containerMimeType) {
		return getFinalDocumentName(originalFile, operation, null, containerMimeType);
	}

}
