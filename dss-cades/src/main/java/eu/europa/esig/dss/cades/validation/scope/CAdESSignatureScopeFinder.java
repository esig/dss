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
package eu.europa.esig.dss.cades.validation.scope;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestDocument;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.AbstractSignatureScopeFinder;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.DigestSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class CAdESSignatureScopeFinder extends AbstractSignatureScopeFinder<CAdESSignature> {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESSignatureScopeFinder.class);

    @Override
    public List<SignatureScope> findSignatureScope(final CAdESSignature cAdESSignature) {
        List<SignatureScope> result = new ArrayList<SignatureScope>();
        try {
            DSSDocument originalDocument = cAdESSignature.getOriginalDocument();
            if (originalDocument instanceof DigestDocument) {
            	DigestDocument digestDocument = (DigestDocument) originalDocument;
                result.add(new DigestSignatureScope("Digest document", digestDocument.getExistingDigest()));
                
            } else if (isASiCSArchive(cAdESSignature, originalDocument)) {
            	result.add(new ContainerSignatureScope(originalDocument.getName(), getDigest(DSSUtils.toByteArray(originalDocument))));
				for (DSSDocument archivedDocument : cAdESSignature.getContainerContents()) {
					result.add(new ContainerContentSignatureScope(DSSUtils.decodeUrl(archivedDocument.getName()), 
							new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(archivedDocument.getDigest(getDefaultDigestAlgorithm())))));
				}
				
            } else if (isASiCEArchive(cAdESSignature)) {
            	result.add(new ManifestSignatureScope(originalDocument.getName(), getDigest(DSSUtils.toByteArray(originalDocument))));
            	for (DSSDocument manifestContent : cAdESSignature.getManifestedDocuments()) {
					result.add(new FullSignatureScope(manifestContent.getName(), 
							new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(manifestContent.getDigest(getDefaultDigestAlgorithm())))));
            	}
            	
            } else {
            	String digest64Base = originalDocument.getDigest(getDefaultDigestAlgorithm());
                result.add(new FullSignatureScope("Full document", new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(digest64Base))));
            }
        } catch (DSSException e) {
        	LOG.warn("A CAdES signer's original document is not found [{}].", e.getMessage());
        }
        return result;
    }
    
}
