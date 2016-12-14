package eu.europa.esig.dss.asic.validation;

import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.ASiCNamespace;
import eu.europa.esig.dss.utils.Utils;

public class ASiCEWithCAdESManifestValidator {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCEWithCAdESManifestValidator.class);

	static {
		DomUtils.registerNamespace("asic", ASiCNamespace.NS);
	}

	private final DSSDocument signature;
	private final List<DSSDocument> manifestDocuments;
	private final List<DSSDocument> signedDocuments;

	public ASiCEWithCAdESManifestValidator(DSSDocument signature, List<DSSDocument> manifestDocuments, List<DSSDocument> signedDocuments) {
		this.signature = signature;
		this.manifestDocuments = manifestDocuments;
		this.signedDocuments = signedDocuments;
	}

	public DSSDocument getLinkedManifest() {
		String expectedSignatureURI = signature.getName();
		for (DSSDocument manifestDocument : manifestDocuments) {
			InputStream is = null;
			try {
				is = manifestDocument.openStream();
				Document manifestDom = DomUtils.buildDOM(is);
				String signatureURI = DomUtils.getValue(manifestDom, "/asic:ASiCManifest/asic:SigReference/@URI");
				if (Utils.areStringsEqual(expectedSignatureURI, signatureURI) && checkManifestDigests(manifestDom)) {
					return manifestDocument;
				}
			} catch (Exception e) {
				LOG.warn("Unable to analyze manifest file '" + manifestDocument.getName() + "' : " + e.getMessage());
			} finally {
				Utils.closeQuietly(is);
			}
		}
		return null;
	}

	private boolean checkManifestDigests(Document manifestDom) {
		NodeList dataObjectReferences = DomUtils.getNodeList(manifestDom, "/asic:ASiCManifest/asic:DataObjectReference");
		if (dataObjectReferences == null || dataObjectReferences.getLength() == 0) {
			LOG.warn("No DataObjectReference found in manifest file");
			return false;
		} else {
			for (int i = 0; i < dataObjectReferences.getLength(); i++) {
				Element dataObjectReference = (Element) dataObjectReferences.item(i);

				String filename = dataObjectReference.getAttribute("URI");

				DSSDocument signedFile = getSignedFileByName(filename);
				if (signedFile == null) {
					LOG.warn("Signed data with name '{}' not found", filename);
					return false;
				}

				DigestAlgorithm digestAlgo = getDigestAlgorithm(dataObjectReference);
				if (digestAlgo == null) {
					LOG.warn("Digest algo is not defined for signed data with name '{}'", filename);
					return false;
				}

				byte[] expectedDigest = getDigestValue(dataObjectReference);
				byte[] computedDigest = DSSUtils.digest(digestAlgo, signedFile);
				if (!Arrays.equals(expectedDigest, computedDigest)) {
					LOG.warn("Digest value doesn't match for signed data with name '{}'", filename);
					LOG.warn("Expected : '{}'", Utils.toBase64(expectedDigest));
					LOG.warn("Computed : '{}'", Utils.toBase64(computedDigest));
					return false;
				}

			}
		}

		return true;
	}

	private DSSDocument getSignedFileByName(String filename) {
		for (DSSDocument signedDocument : signedDocuments) {
			if (Utils.areStringsEqual(filename, signedDocument.getName())) {
				return signedDocument;
			}
		}
		return null;
	}

	private DigestAlgorithm getDigestAlgorithm(Element element) {
		final String xmlName = DomUtils.getElement(element, "ds:DigestMethod").getAttribute("Algorithm");
		return DigestAlgorithm.forXML(xmlName, null);
	}

	private byte[] getDigestValue(Element element) {
		Element digestValueElement = DomUtils.getElement(element, "ds:DigestValue");
		if (digestValueElement != null) {
			String digestBase64 = digestValueElement.getTextContent();
			return Utils.fromBase64(digestBase64);
		}
		return null;
	}

}
