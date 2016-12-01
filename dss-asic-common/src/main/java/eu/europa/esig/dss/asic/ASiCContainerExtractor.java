package eu.europa.esig.dss.asic;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

public class ASiCContainerExtractor {

	private static final Logger LOG = LoggerFactory.getLogger(ASiCContainerExtractor.class);

	private final DSSDocument asicContainer;

	public ASiCContainerExtractor(DSSDocument asicContainer) {
		this.asicContainer = asicContainer;
	}

	public ASiCExtractResult extract() {
		ASiCExtractResult result = new ASiCExtractResult();

		ZipInputStream asicsInputStream = null;
		try {
			asicsInputStream = new ZipInputStream(asicContainer.openStream());
			ZipEntry entry;
			while ((entry = asicsInputStream.getNextEntry()) != null) {
				String entryName = entry.getName();
				if (ASiCUtils.isMetaInfFolder(entryName)) {
					if (ASiCUtils.isCAdES(entryName) || ASiCUtils.isXAdES(entryName)) {
						result.getSignatureDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					} else if (ASiCUtils.isASiCManifestWithCAdES(entryName) || ASiCUtils.isASiCManifestWithXAdES(entryName)) {
						result.getManifestDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					} else if (!ASiCUtils.isFolder(entryName)) {
						result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					}
				} else if (!ASiCUtils.isFolder(entryName)) {
					if (ASiCUtils.isMimetype(entryName)) {
						result.setMimeTypeDocument(getCurrentDocument(entryName, asicsInputStream));
					} else {
						result.getSignedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
					}
				} else {
					result.getUnsupportedDocuments().add(getCurrentDocument(entryName, asicsInputStream));
				}
			}

			if (Utils.isCollectionNotEmpty(result.getUnsupportedDocuments())) {
				LOG.warn("Unsupported files : " + result.getUnsupportedDocuments());
			}

		} catch (IOException e) {
			LOG.warn("Unable to parse the container " + e.getMessage());
		} finally {
			Utils.closeQuietly(asicsInputStream);
		}

		return result;
	}

	private DSSDocument getCurrentDocument(String filepath, ZipInputStream zis) throws IOException {
		ByteArrayOutputStream baos = null;
		try {
			baos = new ByteArrayOutputStream();
			Utils.copy(zis, baos);
			return new InMemoryDocument(baos.toByteArray(), filepath);
		} finally {
			Utils.closeQuietly(baos);
		}
	}

}
