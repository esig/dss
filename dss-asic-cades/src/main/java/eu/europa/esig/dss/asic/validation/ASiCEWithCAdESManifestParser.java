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
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.validation.ManifestFile;

public class ASiCEWithCAdESManifestParser {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestParser.class);

	private final DSSDocument manifestDocument;

	public ASiCEWithCAdESManifestParser(DSSDocument manifestDocument) {
		this.manifestDocument = manifestDocument;
	}

	public ManifestFile getDescription() {
		ManifestFile description = new ManifestFile();
		description.setFilename(manifestDocument.getName());

		try (InputStream is = manifestDocument.openStream()) {
			Document manifestDom = DomUtils.buildDOM(is);
			Element root = DomUtils.getElement(manifestDom, ASiCNamespace.ASIC_MANIFEST);

			description.setSignatureFilename(DomUtils.getValue(root, ASiCNamespace.SIG_REFERENCE_URI));
			description.setEntries(getDataObjectReferenceUris(root));

		} catch (Exception e) {
			LOG.warn("Unable to analyze manifest file '{}' : {}", manifestDocument.getName(), e.getMessage());
		}

		return description;
	}

	private List<String> getDataObjectReferenceUris(Element root) {
		List<String> entries = new ArrayList<String>();
		NodeList dataObjectReferences = DomUtils.getNodeList(root, ASiCNamespace.DATA_OBJECT_REFERENCE);
		if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
			LOG.warn("No DataObjectReference found in manifest file");
		} else {
			for (int i = 0; i < dataObjectReferences.getLength(); i++) {
				Element dataObjectReference = (Element) dataObjectReferences.item(i);
				entries.add(dataObjectReference.getAttribute("URI"));
			}
		}
		return entries;
	}

}
