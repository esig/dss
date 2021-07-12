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
import java.util.Collections;
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
		return Collections.emptyList();
	}

}
