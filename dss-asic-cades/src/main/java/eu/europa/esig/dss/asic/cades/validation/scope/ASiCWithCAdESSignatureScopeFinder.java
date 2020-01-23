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
package eu.europa.esig.dss.asic.cades.validation.scope;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class ASiCWithCAdESSignatureScopeFinder extends CAdESSignatureScopeFinder {

    @Override
    public List<SignatureScope> findSignatureScope(final CAdESSignature cadesSignature) {
        List<SignatureScope> result = new ArrayList<>();
        DSSDocument originalDocument = getOriginalDocument(cadesSignature);
        if (originalDocument == null) {
        	return result;
        }
        
        if (isASiCSArchive(cadesSignature, originalDocument)) {
			result.add(new ContainerSignatureScope(originalDocument.getName(), DSSUtils.getDigest(getDefaultDigestAlgorithm(), originalDocument)));
			for (DSSDocument archivedDocument : cadesSignature.getContainerContents()) {
				result.add(new ContainerContentSignatureScope(DSSUtils.decodeUrl(archivedDocument.getName()), 
						DSSUtils.getDigest(getDefaultDigestAlgorithm(), archivedDocument)));
			}
			
        } else if (isASiCEArchive(cadesSignature)) {
			result.add(new ManifestSignatureScope(originalDocument.getName(), DSSUtils.getDigest(getDefaultDigestAlgorithm(), originalDocument)));
        	for (DSSDocument manifestContent : cadesSignature.getManifestedDocuments()) {
				result.add(new FullSignatureScope(manifestContent.getName(), 
						DSSUtils.getDigest(getDefaultDigestAlgorithm(), manifestContent)));
        	}
        	
        } else {
        	return getSignatureScopeFromOriginalDocument(originalDocument);
        }
        return result;
    }

}
