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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * A class to generate a DataToSign for an OpenDocument signing
 */
public class DataToSignOpenDocument extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	/** The default signature filename */
	private static final String ZIP_OPEN_DOCUMENT_METAINF_XADES_SIGNATURE =
			ASiCUtils.META_INF_FOLDER + "documentsignatures.xml";

	/** The list of signed documents */
	private final List<DSSDocument> signedDocuments;

	/** The list of signature documents */
	private final List<DSSDocument> existingSignatures;

	/** The list of manifest documents */
	private final List<DSSDocument> existingManifests;

	/** The mimetype document */
	private final DSSDocument mimetype;

	/** The root container */
	private final DSSDocument rootContainer;

	/**
	 * The default constructor
	 *
	 * @param signedDocuments a list of {@link DSSDocument}s
	 * @param existingSignatures a list of {@link DSSDocument}s
	 * @param existingManifests a list of {@link DSSDocument}s
	 * @param mimetype {@link DSSDocument}
	 * @param rootContainer {@link DSSDocument}
	 */
	public DataToSignOpenDocument(final List<DSSDocument> signedDocuments, final List<DSSDocument> existingSignatures,
								  final List<DSSDocument> existingManifests, final DSSDocument mimetype,
								  final DSSDocument rootContainer) {
		this.signedDocuments = signedDocuments;
		this.existingSignatures = existingSignatures;
		this.existingManifests = existingManifests;
		this.mimetype = mimetype;
		this.rootContainer = rootContainer;
	}

	@Override
	public String getSignatureFilename() {
		return ZIP_OPEN_DOCUMENT_METAINF_XADES_SIGNATURE;
	}

	@Override
	public String getTimestampFilename() {
		throw new UnsupportedOperationException("Timestamp file cannot be added with ASiC-E + XAdES");
	}

	@Override
	public List<DSSDocument> getToBeSigned() {
		return signedDocuments;
	}

	@Override
	public DSSDocument getExistingSignature() {
		// The new signature is added in the existing file
		int nbEmbeddedSignatures = Utils.collectionSize(existingSignatures);
		if(nbEmbeddedSignatures == 1) {
			return existingSignatures.get(0);
		}else {
			return null;
		}
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		List<DSSDocument> docs = new ArrayList<>();
		// For open document we do not sign any file inside external-data
		for(DSSDocument doc: signedDocuments) {
			if(!doc.getName().startsWith("external-data/")){
				docs.add(doc);
			}
		}
		docs.addAll(existingManifests);
		docs.add(mimetype);
		return docs;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return existingManifests;
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return existingSignatures;
	}

	@Override
	public DSSDocument getRootDocument() {
		return rootContainer;
	}

}
