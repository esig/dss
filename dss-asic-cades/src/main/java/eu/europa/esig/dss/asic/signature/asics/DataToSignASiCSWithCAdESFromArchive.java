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
package eu.europa.esig.dss.asic.signature.asics;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.asic.ASiCParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.utils.Utils;

public class DataToSignASiCSWithCAdESFromArchive extends AbstractGetDataToSignASiCSWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> embeddedSignatures;
	private final List<DSSDocument> embeddedSignedFiles;
	private final ASiCParameters asicParameters;

	public DataToSignASiCSWithCAdESFromArchive(List<DSSDocument> embeddedSignatures, List<DSSDocument> embeddedSignedFiles, ASiCParameters asicParameters) {
		this.embeddedSignatures = embeddedSignatures;
		this.embeddedSignedFiles = embeddedSignedFiles;
		this.asicParameters = asicParameters;
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(asicParameters);
	}

	@Override
	public DSSDocument getToBeSigned() {
		int nbEmbeddedSignatures = Utils.collectionSize(embeddedSignatures);
		if (nbEmbeddedSignatures != 1) {
			throw new DSSException("Unable to select the embedded signature (nb found:" + nbEmbeddedSignatures + ")");
		}
		return embeddedSignatures.get(0);
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return getSignedDocuments();
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		int nbSignedFiles = Utils.collectionSize(embeddedSignedFiles);
		if (nbSignedFiles != 1) {
			throw new DSSException("Unable to select the document to be signed (nb found:" + nbSignedFiles + ")");
		}
		return embeddedSignedFiles;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		// No manifest file in ASiC-S
		return Collections.emptyList();
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return embeddedSignatures;
	}

}
