/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.asic.cades.signature.asics;

import eu.europa.esig.dss.asic.cades.signature.GetDataToSignASiCWithCAdESHelper;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

/**
 * A class to generate a DataToSign with ASiC-S with CAdES from an existing archive
 */
public class DataToSignASiCSWithCAdESFromArchive extends AbstractGetDataToSignASiCSWithCAdES implements GetDataToSignASiCWithCAdESHelper {

	/**
	 * Default constructor
	 *
	 * @param asicContent {@link ASiCContent}
	 */
	public DataToSignASiCSWithCAdESFromArchive(final ASiCContent asicContent) {
		super(asicContent);
	}

	@Override
	public DSSDocument getToBeSigned() {
		// NOTE : in ASiC-S signatures are added within the same signature file,
		// and handling of detached document signing is delegated to CAdES service
		List<DSSDocument> embeddedSignatures = asicContent.getSignatureDocuments();
		int nbEmbeddedSignatures = Utils.collectionSize(embeddedSignatures);
		if (nbEmbeddedSignatures != 1) {
			throw new DSSException("Unable to select the embedded signature (nb found:" + nbEmbeddedSignatures + ")");
		}
		return embeddedSignatures.get(0);
	}

	@Override
	public List<DSSDocument> getDetachedContents() {
		List<DSSDocument> embeddedSignedFiles = asicContent.getSignedDocuments();
		int nbSignedFiles = Utils.collectionSize(embeddedSignedFiles);
		if (nbSignedFiles != 1) {
			throw new DSSException("Unable to select the document to be signed (nb found:" + nbSignedFiles + ")");
		}
		return embeddedSignedFiles;
	}

}
