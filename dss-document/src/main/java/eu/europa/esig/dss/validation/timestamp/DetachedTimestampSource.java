package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.validation.ManifestFile;

import java.util.ArrayList;
import java.util.List;

/**
 * Performs processing of detached timestamps
 */
public class DetachedTimestampSource extends AbstractTimestampSource {

    /** A list of detached timestamps */
    private List<TimestampToken> detachedTimestamps = new ArrayList<>();

    /**
     * Returns a list of processed detached timestamps
     *
     * @return a list of {@link TimestampToken}s
     */
    public List<TimestampToken> getDetachedTimestamps() {
        return detachedTimestamps;
    }

    /**
     * Adds the external timestamp to the source
     *
     * @param timestamp {@link TimestampToken}
     */
    public void addExternalTimestamp(TimestampToken timestamp) {
        processExternalTimestamp(timestamp);
        detachedTimestamps.add(timestamp);
    }

    private void processExternalTimestamp(TimestampToken externalTimestamp) {
        ManifestFile manifestFile = externalTimestamp.getManifestFile();
        if (manifestFile != null) {
            for (TimestampToken timestampToken : detachedTimestamps) {
                if (manifestFile.isDocumentCovered(timestampToken.getFileName())) {
                    addReferences(externalTimestamp.getTimestampedReferences(), getReferencesFromTimestamp(timestampToken));
                }
            }
        }
    }

}
