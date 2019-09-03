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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.asic.xades.signature.GetDataToSignASiCWithXAdESHelper;
import eu.europa.esig.dss.asic.xades.signature.asice.AbstractDataToSignASiCEWithXAdES;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignOpenDocument extends AbstractDataToSignASiCEWithXAdES implements GetDataToSignASiCWithXAdESHelper {

	private final List<DSSDocument> signedDocuments;
	private final List<DSSDocument> existingSignatures;
	private final List<DSSDocument> existingManifests;
	private final DSSDocument mimetype;
	private final DSSDocument rootContainer;

	public DataToSignOpenDocument(List<DSSDocument> signedDocuments, List<DSSDocument> existingSignatures, List<DSSDocument> existingManifests,
			DSSDocument mimetype, DSSDocument rootContainer) {
		this.signedDocuments = signedDocuments;
		this.existingSignatures = existingSignatures;
		this.existingManifests = existingManifests;
		this.mimetype = mimetype;
		this.rootContainer = rootContainer;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileNameForOpenDocument();
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
		List<DSSDocument> docs = new ArrayList<DSSDocument>();
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
