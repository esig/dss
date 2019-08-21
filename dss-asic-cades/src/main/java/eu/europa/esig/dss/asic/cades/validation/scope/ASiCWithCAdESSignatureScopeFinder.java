package eu.europa.esig.dss.asic.cades.validation.scope;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.cades.validation.scope.CAdESSignatureScopeFinder;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.FullSignatureScope;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;

public class ASiCWithCAdESSignatureScopeFinder extends CAdESSignatureScopeFinder {

    @Override
    public List<SignatureScope> findSignatureScope(final CAdESSignature cadesSignature) {
        List<SignatureScope> result = new ArrayList<SignatureScope>();
        DSSDocument originalDocument = getOriginalDocument(cadesSignature);
        if (originalDocument == null) {
        	return result;
        }
        
        if (isASiCSArchive(cadesSignature, originalDocument)) {
        	result.add(new ContainerSignatureScope(originalDocument.getName(), getDigest(DSSUtils.toByteArray(originalDocument))));
			for (DSSDocument archivedDocument : cadesSignature.getContainerContents()) {
				result.add(new ContainerContentSignatureScope(DSSUtils.decodeUrl(archivedDocument.getName()), 
						new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(archivedDocument.getDigest(getDefaultDigestAlgorithm())))));
			}
			
        } else if (isASiCEArchive(cadesSignature)) {
        	result.add(new ManifestSignatureScope(originalDocument.getName(), getDigest(DSSUtils.toByteArray(originalDocument))));
        	for (DSSDocument manifestContent : cadesSignature.getManifestedDocuments()) {
				result.add(new FullSignatureScope(manifestContent.getName(), 
						new Digest(getDefaultDigestAlgorithm(), Utils.fromBase64(manifestContent.getDigest(getDefaultDigestAlgorithm())))));
        	}
        	
        } else {
        	return getSignatureScopeFromOriginalDocument(originalDocument);
        	
        }
        return result;
    }

}
