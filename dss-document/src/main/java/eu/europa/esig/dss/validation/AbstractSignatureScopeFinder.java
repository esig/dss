package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;

public abstract class AbstractSignatureScopeFinder<T extends AdvancedSignature> implements SignatureScopeFinder<T> {
	
	private DigestAlgorithm defaultDigestAlgorithm = DigestAlgorithm.SHA256;
	
	private static final String ASICS_PACKAGE_ZIP_NAME = "package.zip";
	
	private static final String MANIFEST_FOLDER = "META-INF/";
	private static final String MANIFEST_NAME = "ASiCManifest";
	private static final String MANIFEST_EXTENSION = ".xml";
	
	@Override
	public void setDefaultDigestAlgorithm(DigestAlgorithm defaultDigestAlgorithm) {
		this.defaultDigestAlgorithm = defaultDigestAlgorithm;
	}
	
	protected DigestAlgorithm getDigestAlgorithm() {
		return defaultDigestAlgorithm;
	}
	
	protected Digest getDigest(byte[] dataBytes) {
		return new Digest(defaultDigestAlgorithm, DSSUtils.digest(defaultDigestAlgorithm, dataBytes));
	}
	
	protected boolean isASiCSArchive(AdvancedSignature advancedSignature, DSSDocument dssDocument) {
		return ASICS_PACKAGE_ZIP_NAME.equals(dssDocument.getName()) && 
				Utils.isCollectionNotEmpty(advancedSignature.getContainerContents());
	}
    
	protected boolean isASiCEArchive(AdvancedSignature advancedSignature) {
		return Utils.isCollectionNotEmpty(advancedSignature.getManifestedDocuments()) && 
				Utils.isCollectionNotEmpty(advancedSignature.getContainerContents());
	}

}
