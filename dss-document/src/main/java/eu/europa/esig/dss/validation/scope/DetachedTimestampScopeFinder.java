package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * This class finds a timestamp scope for a detached timestamp
 *
 */
public class DetachedTimestampScopeFinder extends AbstractSignatureScopeFinder implements TimestampScopeFinder {

    /** The data used to for message-imprint computation of a timestamp token */
    protected DSSDocument timestampedData;

    /**
     * Sets the timestamped data
     *
     * @param timestampedData {@link DSSDocument}
     */
    public void setTimestampedData(DSSDocument timestampedData) {
        this.timestampedData = timestampedData;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return getTimestampSignatureScopeForDocument(timestampedData);
        }
        return Collections.emptyList();
    }

    /**
     * Returns a timestamped {@code SignatureScope} for the given document
     *
     * @param document {@link DSSDocument} to get a signature scope for
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getTimestampSignatureScopeForDocument(DSSDocument document) {
        String documentName = document.getName();
        if (document instanceof DigestDocument) {
            return Arrays.asList(new DigestSignatureScope(Utils.isStringNotEmpty(documentName) ? documentName : "Digest document",
                    ((DigestDocument) document).getExistingDigest()));
        } else {
            return Arrays.asList(new FullSignatureScope(Utils.isStringNotEmpty(documentName) ? documentName : "Full document",
                    getDigest(document)));
        }
    }

}
