package eu.europa.esig.dss.validation.process.bbb.cv.checks;

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlContainerInfo;
import eu.europa.esig.dss.jaxb.diagnostic.XmlManifestFile;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class AllFilesSignedCheck extends ChainItem<XmlCV> {

	private final SignatureWrapper signature;
	private final XmlContainerInfo containerInfo;

	public AllFilesSignedCheck(XmlCV result, SignatureWrapper signature, XmlContainerInfo containerInfo, LevelConstraint constraint) {
		super(result, constraint);
		this.signature = signature;
		this.containerInfo = containerInfo;
	}

	@Override
	protected boolean process() {

		/* ASiC-S -> nb files = 1 */
		if ("ASiC-S".equals(containerInfo.getContainerType())) {
			return 1 == Utils.collectionSize(containerInfo.getContentFiles());
		} else if ("ASiC-E".equals(containerInfo.getContainerType())) {
			String signatureFilename = signature.getSignatureFilename();
			List<String> coveredFiles = getCoveredFilesBySignatureFilename(signatureFilename);
			List<String> contentFiles = containerInfo.getContentFiles();

			// check manifest <> content
			if (!sameContent(coveredFiles, contentFiles)) {
				return false;
			}

			// XAdES -> check signature scope
			if (signature.getFormat().startsWith("XAdES")) {
				List<String> coveredFilesFromScrope = getCoveredFilesFromScrope();
				return sameContent(coveredFilesFromScrope, contentFiles);
			}

			// CAdES -> manifest file is signed
			return true;
		}

		return false;
	}

	private boolean sameContent(List<String> coveredFiles, List<String> contentFiles) {
		if (Utils.collectionSize(coveredFiles) == Utils.collectionSize(contentFiles)) {
			boolean findAll = true;

			for (String content : contentFiles) {
				findAll &= coveredFiles.contains(content);
			}

			if (findAll) {
				for (String covered : coveredFiles) {
					findAll &= contentFiles.contains(covered);
				}
			}

			return findAll;
		}
		return false;
	}

	private List<String> getCoveredFilesBySignatureFilename(String signatureFilename) {
		List<XmlManifestFile> manifestFiles = containerInfo.getManifestFiles();
		for (XmlManifestFile xmlManifestFile : manifestFiles) {
			if (Utils.areStringsEqual(signatureFilename, xmlManifestFile.getSignatureFilename())) {
				return xmlManifestFile.getEntries();
			}
		}
		return new ArrayList<String>();
	}

	private List<String> getCoveredFilesFromScrope() {
		List<String> result = new ArrayList<String>();
		List<XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		for (XmlSignatureScope xmlSignatureScope : signatureScopes) {
			result.add(xmlSignatureScope.getName());
		}
		return result;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_CV_IAFS;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return MessageTag.BBB_CV_IAFS_ANS;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.FAILED;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.SIG_CRYPTO_FAILURE;
	}

}
