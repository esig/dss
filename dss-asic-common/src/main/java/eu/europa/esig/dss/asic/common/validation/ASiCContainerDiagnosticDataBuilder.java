package eu.europa.esig.dss.asic.common.validation;

import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ContainerInfo;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.SignedDocumentDiagnosticDataBuilder;

import java.util.ArrayList;
import java.util.List;

/**
 * DiagnosticDataBuilder for an ASiC container
 *
 */
public class ASiCContainerDiagnosticDataBuilder extends SignedDocumentDiagnosticDataBuilder {

	/** The information about the validating container */
	private ContainerInfo containerInfo;

	/**
	 * This method allows to set the container info (ASiC)
	 * 
	 * @param containerInfo the container information
	 * @return the builder
	 */
	public ASiCContainerDiagnosticDataBuilder containerInfo(ContainerInfo containerInfo) {
		this.containerInfo = containerInfo;
		return this;
	}

	@Override
	public XmlDiagnosticData build() {
		XmlDiagnosticData diagnosticData = super.build();
		diagnosticData.setContainerInfo(getXmlContainerInfo());
		return diagnosticData;
	}

	private XmlContainerInfo getXmlContainerInfo() {
		if (containerInfo != null) {
			XmlContainerInfo xmlContainerInfo = new XmlContainerInfo();
			xmlContainerInfo.setContainerType(containerInfo.getContainerType());
			String zipComment = containerInfo.getZipComment();
			if (Utils.isStringNotBlank(zipComment)) {
				xmlContainerInfo.setZipComment(zipComment);
			}
			xmlContainerInfo.setMimeTypeFilePresent(containerInfo.isMimeTypeFilePresent());
			xmlContainerInfo.setMimeTypeContent(containerInfo.getMimeTypeContent());
			xmlContainerInfo.setContentFiles(containerInfo.getSignedDocumentFilenames());
			xmlContainerInfo.setManifestFiles(getXmlManifests(containerInfo.getManifestFiles()));
			return xmlContainerInfo;
		}
		return null;
	}

	private List<XmlManifestFile> getXmlManifests(List<ManifestFile> manifestFiles) {
		if (Utils.isCollectionNotEmpty(manifestFiles)) {
			List<XmlManifestFile> xmlManifests = new ArrayList<>();
			for (ManifestFile manifestFile : manifestFiles) {
				XmlManifestFile xmlManifest = new XmlManifestFile();
				xmlManifest.setFilename(manifestFile.getFilename());
				xmlManifest.setSignatureFilename(manifestFile.getSignatureFilename());
				for (ManifestEntry entry : manifestFile.getEntries()) {
					xmlManifest.getEntries().add(entry.getFileName());
				}
				xmlManifests.add(xmlManifest);
			}
			return xmlManifests;
		}
		return null;
	}

}
