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
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithXAdESManifestParser {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithXAdESManifestParser.class);

	static {
		DomUtils.registerNamespace("manifest", ManifestNamespace.NS);
	}

	private final DSSDocument signatureDocument;
	private final DSSDocument manifestDocument;

	public ASiCEWithXAdESManifestParser(DSSDocument signatureDocument, DSSDocument manifestDocument) {
		this.signatureDocument = signatureDocument;
		this.manifestDocument = manifestDocument;
	}

	public ManifestFile getDescription() {
		ManifestFile description = new ManifestFile();
		description.setSignatureFilename(signatureDocument.getName());
		description.setFilename(manifestDocument.getName());
		description.setEntries(getEntries());
		return description;
	}

	private List<String> getEntries() {
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
					if (!isFolder(fullpathValue)) {
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

	private boolean isFolder(String fullpathValue) {
		return fullpathValue.endsWith("/");
	}

}
