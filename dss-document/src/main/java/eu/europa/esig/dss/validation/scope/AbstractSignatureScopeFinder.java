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
package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

public abstract class AbstractSignatureScopeFinder<T extends AdvancedSignature> implements SignatureScopeFinder<T> {
	
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;
	
	private static final String ASICS_PACKAGE_ZIP_NAME = "package.zip";
	
	@Override
	public void setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
		this.defaultDigestAlgorithm = defaultDigestAlgorithm;
	}
	
	protected DigestAlgorithm getDefaultDigestAlgorithm() {
		return defaultDigestAlgorithm;
	}
	
	protected Digest getDigest(DSSDocument document) {
		return new Digest(defaultDigestAlgorithm, Utils.fromBase64(document.getDigest(defaultDigestAlgorithm)));
	}
	
	protected Digest getDigest(byte[] dataBytes) {
		return new Digest(defaultDigestAlgorithm, DSSUtils.digest(defaultDigestAlgorithm, dataBytes));
	}
	
	protected boolean isASiCSArchive(AdvancedSignature advancedSignature, DSSDocument dssDocument) {
		return ASICS_PACKAGE_ZIP_NAME.equals(dssDocument.getName()) && 
				Utils.isCollectionNotEmpty(advancedSignature.getContainerContents());
	}
    
	protected boolean isASiCEArchive(AdvancedSignature advancedSignature) {
		return advancedSignature.getManifestFile() != null;
	}

}
