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
package eu.europa.esig.dss.asic.signature.asice;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.asic.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.signature.GetDataToSignASiCWithCAdESHelper;

public class DataToSignASiCEWithCAdESFromFiles extends AbstractDataToSignASiCEWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	private final List<DSSDocument> filesToBeSigned;
	private final ASiCWithCAdESSignatureParameters parameters;

	private DSSDocument toBeSigned;

	public DataToSignASiCEWithCAdESFromFiles(List<DSSDocument> filesToBeSigned, ASiCWithCAdESSignatureParameters parameters) {
		this.filesToBeSigned = filesToBeSigned;
		this.parameters = parameters;
	}

	@Override
	public DSSDocument getToBeSigned() {
		if (toBeSigned == null) {
			toBeSigned = getASiCManifest(filesToBeSigned, Collections.<DSSDocument> emptyList(), Collections.<DSSDocument> emptyList(), parameters);
		}
		return toBeSigned;
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		return Collections.emptyList();
	}

	@Override
	public String getSignatureFilename() {
		return getSignatureFileName(parameters.aSiC(), Collections.<DSSDocument> emptyList());
	}

	@Override
	public List<DSSDocument> getSignedDocuments() {
		return filesToBeSigned;
	}

	@Override
	public List<DSSDocument> getManifestFiles() {
		return Arrays.asList(getToBeSigned());
	}

	@Override
	public List<DSSDocument> getSignatures() {
		return new ArrayList<DSSDocument>();
	}

}
