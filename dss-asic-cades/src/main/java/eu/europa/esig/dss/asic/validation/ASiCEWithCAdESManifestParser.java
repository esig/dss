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
import eu.europa.esig.dss.utils.Utils;
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

		InputStream is = null;
		try {
			is = manifestDocument.openStream();
			Document manifestDom = DomUtils.buildDOM(is);
			description.setSignatureFilename(DomUtils.getValue(manifestDom, ASiCNamespace.XPATH_ASIC_SIGREF_URL));

			List<String> entries = new ArrayList<String>();
			NodeList dataObjectReferences = DomUtils.getNodeList(manifestDom, ASiCNamespace.XPATH_ASIC_DATA_OBJECT_REFERENCE);
			if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
				LOG.warn("No DataObjectReference found in manifest file");
			} else {
				for (int i = 0; i < dataObjectReferences.getLength(); i++) {
					Element dataObjectReference = (Element) dataObjectReferences.item(i);
					entries.add(dataObjectReference.getAttribute("URI"));
				}
			}
			description.setEntries(entries);

		} catch (Exception e) {
			LOG.warn("Unable to analyze manifest file '" + manifestDocument.getName() + "' : " + e.getMessage());
		} finally {
			Utils.closeQuietly(is);
		}

		return description;
	}

}
