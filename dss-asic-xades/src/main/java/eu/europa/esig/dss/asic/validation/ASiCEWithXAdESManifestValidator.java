package eu.europa.esig.dss.asic.validation;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.ManifestNamespace;
import eu.europa.esig.dss.utils.Utils;

public class ASiCEWithXAdESManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithXAdESManifestValidator.class);

	static {
		DomUtils.registerNamespace("manifest", ManifestNamespace.NS);
	}

	private final DSSDocument manifestDocument;

	public ASiCEWithXAdESManifestValidator(DSSDocument manifestDocument) {
		this.manifestDocument = manifestDocument;
	}

	public List<String> getCoveredFiles() {
		List<String> result = new ArrayList<String>();
		InputStream is = null;
		try {
			is = manifestDocument.openStream();
			Document manifestDom = DomUtils.buildDOM(is);
			NodeList nodeList = DomUtils.getNodeList(manifestDom, "/manifest:manifest/manifest:file-entry");
			if (nodeList != null && nodeList.getLength() > 0) {
				for (int i = 0; i < nodeList.getLength(); i++) {
					Element fileEntryElement = (Element) nodeList.item(i);
					String fullpathValue = fileEntryElement.getAttribute(ManifestNamespace.FULL_PATH);
					if (!isContainerDefinition(fullpathValue) && !isSignatureFile(fullpathValue)) {
						result.add(fullpathValue);
					}
				}
			}
		} catch (Exception e) {
			LOG.error("Unable to parse manifest file " + manifestDocument.getName(), e);
		} finally {
			Utils.closeQuietly(is);
		}
		return result;
	}

	/**
	 * Sometimes signature files can be listed in the manifest file
	 * 
	 */
	private boolean isSignatureFile(String fullpathValue) {
		return fullpathValue.matches("META-INF/.*signature.*\\.xml");
	}

	private boolean isContainerDefinition(String fullpathValue) {
		return "/".equals(fullpathValue);
	}

}
