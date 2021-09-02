package eu.europa.esig.dss.asic.cades.validation.scope;

import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.ManifestEntry;
import eu.europa.esig.dss.validation.ManifestFile;
import eu.europa.esig.dss.validation.scope.ContainerContentSignatureScope;
import eu.europa.esig.dss.validation.scope.ContainerSignatureScope;
import eu.europa.esig.dss.validation.scope.DetachedTimestampScopeFinder;
import eu.europa.esig.dss.validation.scope.ManifestSignatureScope;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class is used to find a timestamp source for a detached timestamp within an ASiC with CAdES container
 *
 */
public class ASiCWithCAdESTimestampScopeFinder extends DetachedTimestampScopeFinder {

    /** Represents a list of documents encapsulated within an ASiC container */
    private List<DSSDocument> containerDocuments;

    /** Represents a list of documents encapsulated within a package.zip archive, when applicable (ASiC-S) */
    private List<DSSDocument> archiveDocuments;

    /**
     * Sets a list of container original documents
     *
     * @param containerDocuments a list of {@link DSSDocument}s
     */
    public void setContainerDocuments(List<DSSDocument> containerDocuments) {
        this.containerDocuments = containerDocuments;
    }

    /**
     * Sets a list of package.zip archive documents
     *
     * @param archiveDocuments a list of {@link DSSDocument}s
     */
    public void setArchiveDocuments(List<DSSDocument> archiveDocuments) {
        this.archiveDocuments = archiveDocuments;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            if (timestampToken.getManifestFile() != null) {
                return getTimestampSignatureScopeForManifest(timestampToken.getManifestFile());
            } else {
                return getTimestampSignatureScopeForDocument(timestampedData);
            }
        }
        return Collections.emptyList();
    }

    /**
     * Extracts timestamped signature scopes from a {@code ManifestFile}
     *
     * @param manifestFile {@link ManifestFile} to extract entries from
     * @return a list of timestamped {@link SignatureScope}s
     */
    private List<SignatureScope> getTimestampSignatureScopeForManifest(ManifestFile manifestFile) {
        List<SignatureScope> result = new ArrayList<>();
        result.add(new ManifestSignatureScope(manifestFile.getFilename(), getDigest(manifestFile.getDocument())));
        if (Utils.isCollectionNotEmpty(containerDocuments)) {
            for (ManifestEntry manifestEntry : manifestFile.getEntries()) {
                if (manifestEntry.isIntact()) {
                    for (DSSDocument document : containerDocuments) {
                        if (Utils.areStringsEqual(manifestEntry.getFileName(), document.getName())) {
                            result.addAll(getTimestampSignatureScopeForDocument(document));
                        }
                    }
                }
            }
        }
        return result;
    }

    @Override
    protected List<SignatureScope> getTimestampSignatureScopeForDocument(DSSDocument document) {
        if (ASiCUtils.isASiCSArchive(document)) {
            return getTimestampSignatureScopeForZipPackage(document);
        } else {
            return super.getTimestampSignatureScopeForDocument(document);
        }
    }

    private List<SignatureScope> getTimestampSignatureScopeForZipPackage(DSSDocument document) {
        List<SignatureScope> result = new ArrayList<>();
        result.add(new ContainerSignatureScope(document.getName(), getDigest(document)));
        if (Utils.isCollectionNotEmpty(archiveDocuments)) {
            for (DSSDocument archivedDocument : archiveDocuments) {
                result.add(new ContainerContentSignatureScope(DSSUtils.decodeURI(archivedDocument.getName()),
                        getDigest(archivedDocument)));
            }
        }
        return result;
    }

}
