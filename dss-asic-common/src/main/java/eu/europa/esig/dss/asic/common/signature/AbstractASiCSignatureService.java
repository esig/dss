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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import eu.europa.esig.dss.asic.common.ASiCExtractResult;
import eu.europa.esig.dss.asic.common.ASiCParameters;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.common.AbstractASiCContainerExtractor;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SerializableCounterSignatureParameters;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SerializableTimestampParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.signature.AbstractSignatureService;
import eu.europa.esig.dss.signature.CounterSignatureService;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

public abstract class AbstractASiCSignatureService<SP extends SerializableSignatureParameters, TP extends SerializableTimestampParameters, 
					CSP extends SerializableCounterSignatureParameters> extends AbstractSignatureService<SP, TP> 
					implements MultipleDocumentsSignatureService<SP, TP>, CounterSignatureService<CSP> {

	private static final long serialVersionUID = 243114076381526665L;

	private static final String ZIP_ENTRY_MIMETYPE = "mimetype";

	protected ASiCExtractResult archiveContent = new ASiCExtractResult();

	protected AbstractASiCSignatureService(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

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

	protected void extractCurrentArchive(DSSDocument archive) {
		AbstractASiCContainerExtractor extractor = getArchiveExtractor(archive);
		archiveContent = extractor.extract();
	}

	protected abstract AbstractASiCContainerExtractor getArchiveExtractor(DSSDocument archive);

	protected List<DSSDocument> getEmbeddedSignatures() {
		return archiveContent.getSignatureDocuments();
	}

	protected List<DSSDocument> getEmbeddedManifests() {
		return archiveContent.getManifestDocuments();
	}

	protected List<DSSDocument> getEmbeddedArchiveManifests() {
		return archiveContent.getArchiveManifestDocuments();
	}

	protected List<DSSDocument> getEmbeddedTimestamps() {
		return archiveContent.getTimestampDocuments();
	}

	protected List<DSSDocument> getEmbeddedSignedDocuments() {
		return archiveContent.getSignedDocuments();
	}

	protected DSSDocument getEmbeddedMimetype() {
		return archiveContent.getMimeTypeDocument();
	}

	protected DSSDocument mergeArchiveAndExtendedSignatures(DSSDocument archiveDocument, List<DSSDocument> signaturesToAdd) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); ZipOutputStream zos = new ZipOutputStream(baos)) {
			copyArchiveContentWithoutSignatures(archiveDocument, zos, signaturesToAdd);
			storeDocuments(signaturesToAdd, zos);

			zos.finish();

			return new InMemoryDocument(baos.toByteArray(), null, archiveDocument.getMimeType());
		} catch (IOException e) {
			throw new DSSException("Unable to extend the ASiC container", e);
		}
	}

	private void copyArchiveContentWithoutSignatures(DSSDocument archiveDocument, ZipOutputStream zos, List<DSSDocument> documentsToAdd) throws IOException {
		List<String> documentNames = getDocumentNames(documentsToAdd);
		long containerSize = DSSUtils.getFileByteSize(archiveDocument);
		try (InputStream is = archiveDocument.openStream(); ZipInputStream zis = new ZipInputStream(is)) {
			ZipEntry entry;
			while ((entry = ASiCUtils.getNextValidEntry(zis)) != null) {
				final String name = entry.getName();
				final ZipEntry newEntry = new ZipEntry(name);
				if (!isSignatureFilename(name) && !documentNames.contains(name)) {
					zos.putNextEntry(newEntry);
					ASiCUtils.secureCopy(zis, zos, containerSize);
				}
			}
		}
	}

	protected abstract boolean isSignatureFilename(String name);
	
	private List<String> getDocumentNames(List<DSSDocument> documents) {
		List<String> names = new ArrayList<>();
		for (DSSDocument document : documents) {
			names.add(document.getName());
		}
		return names;
	}

	protected DSSDocument buildASiCContainer(List<DSSDocument> documentsToBeSigned, List<DSSDocument> signatures,
			List<DSSDocument> documentsToStore,  ASiCParameters asicParameters, DSSDocument rootContainer) {

		if (rootContainer != null) {
			return mergeArchiveAndExtendedSignatures(rootContainer, signatures);
		} else {
			return buildASiCContainerType(documentsToBeSigned, signatures, documentsToStore, asicParameters);
		}
	}
	
	private DSSDocument buildASiCContainerType(List<DSSDocument> documentsToBeSigned, List<DSSDocument> signatures, 
			List<DSSDocument> metaInfFolderDocuments, ASiCParameters asicParameters) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); ZipOutputStream zos = new ZipOutputStream(baos)) {
			storeMimetype(asicParameters, zos);
			if (ASiCUtils.isASiCE(asicParameters)) {
				storeDocuments(metaInfFolderDocuments, zos);
			}
			storeDocuments(signatures, zos);
			storeSignedFiles(documentsToBeSigned, zos);
			storeZipComment(asicParameters, zos);
			
			zos.finish();

			return new InMemoryDocument(baos.toByteArray(), null, ASiCUtils.getMimeType(asicParameters));
		} catch (IOException e) {
			throw new DSSException("Unable to build the ASiC Container", e);
		}
	}

	private void storeDocuments(List<DSSDocument> documents, ZipOutputStream zos) throws IOException {
		for (DSSDocument doc : documents) {
			final ZipEntry entrySignature = new ZipEntry(doc.getName());
			zos.putNextEntry(entrySignature);
			doc.writeTo(zos);
		}
	}

	private void storeSignedFiles(final List<DSSDocument> detachedDocuments, final ZipOutputStream zos) throws IOException {
		for (DSSDocument detachedDocument : detachedDocuments) {
			try (InputStream is = detachedDocument.openStream()) {
				final ZipEntry entryDocument = new ZipEntry(detachedDocument.getName());

				zos.setLevel(ZipEntry.DEFLATED);
				zos.putNextEntry(entryDocument);
				Utils.copy(is, zos);
			}
		}
	}

	private void storeMimetype(final ASiCParameters asicParameters, final ZipOutputStream zos) throws IOException {
		final byte[] mimeTypeBytes = ASiCUtils.getMimeTypeString(asicParameters).getBytes(StandardCharsets.UTF_8);
		final ZipEntry entryMimetype = getZipEntryMimeType(mimeTypeBytes);
		zos.putNextEntry(entryMimetype);
		Utils.write(mimeTypeBytes, zos);
	}

	private ZipEntry getZipEntryMimeType(final byte[] mimeTypeBytes) {
		final ZipEntry entryMimetype = new ZipEntry(ZIP_ENTRY_MIMETYPE);
		entryMimetype.setMethod(ZipEntry.STORED);
		entryMimetype.setSize(mimeTypeBytes.length);
		entryMimetype.setCompressedSize(mimeTypeBytes.length);
		final CRC32 crc = new CRC32();
		crc.update(mimeTypeBytes);
		entryMimetype.setCrc(crc.getValue());
		return entryMimetype;
	}

	protected void storeZipComment(final ASiCParameters asicParameters, final ZipOutputStream zos) {
		if (asicParameters.isZipComment()) {
			zos.setComment(ASiCUtils.MIME_TYPE_COMMENT + ASiCUtils.getMimeTypeString(asicParameters));
		}
	}
	
	protected void verifyAndSetCounterSignatureParameters(ASiCCounterSignatureHelper counterSignatureHelper, CSP parameters) {
		if (Utils.isStringEmpty(parameters.getSignatureIdToCounterSign())) {
			throw new DSSException("The Id of a signature to be counter signed shall be defined! "
					+ "Please use SerializableCounterSignatureParameters.setSignatureIdToCounterSign(signatureId) method.");
		}
	}

	protected void assertAddSignaturePolicyStorePossible() {
		if (Utils.isCollectionEmpty(getEmbeddedSignatures())) {
			throw new UnsupportedOperationException(
					"Signature documents of the expected format are not found in the provided ASiC Container! "
					+ "Add a SignaturePolicyStore is not possible!");
		}
	}

}
