package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.scope.SignatureScope;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.analyzer.DefaultDocumentAnalyzer;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.analyzer.timestamp.TimestampAnalyzer;
import eu.europa.esig.dss.spi.validation.scope.DetachedTimestampScopeFinder;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * This class performs a processing of a detached timestamp document
 *
 */
public class DetachedTimestampAnalyzer extends DefaultDocumentAnalyzer implements TimestampAnalyzer {

    /** The type of the timestamp */
    protected TimestampType timestampType;

    /** The TimestampToken to be validated */
    protected TimestampToken timestampToken;

    /**
     * Empty constructor
     */
    DetachedTimestampAnalyzer() {
        // empty
    }

    /**
     * The default constructor
     *
     * @param timestampFile {@link DSSDocument} timestamp document to validate
     */
    public DetachedTimestampAnalyzer(final DSSDocument timestampFile) {
        this(timestampFile, TimestampType.CONTENT_TIMESTAMP);
    }

    /**
     * The default constructor with a type
     *
     * @param timestampFile {@link DSSDocument} timestamp document to validate
     * @param timestampType {@link TimestampType}
     */
    public DetachedTimestampAnalyzer(final DSSDocument timestampFile, TimestampType timestampType) {
        this.document = timestampFile;
        this.timestampType = timestampType;
    }

    @Override
    public boolean isSupported(DSSDocument dssDocument) {
        byte firstByte = DSSUtils.readFirstByte(dssDocument);
        if (DSSASN1Utils.isASN1SequenceTag(firstByte)) {
            return DSSUtils.isTimestampToken(dssDocument);
        }
        return false;
    }

    @Override
    protected List<TimestampToken> buildDetachedTimestamps() {
        return Collections.singletonList(getTimestamp());
    }

    @Override
    public TimestampToken getTimestamp() {
        if (timestampToken == null) {
            timestampToken = createTimestampToken();

            List<SignatureScope> timestampScopes = getTimestampScopes(timestampToken);
            timestampToken.setTimestampScopes(getTimestampScopes(timestampToken));
            timestampToken.getTimestampedReferences().addAll(getTimestampedReferences(timestampScopes));
            appendExternalEvidenceRecords(timestampToken);
        }
        return timestampToken;
    }

    /**
     * This method creates a timestamp token from the validating document
     *
     * @return {@link TimestampToken}
     */
    protected TimestampToken createTimestampToken() {
        Objects.requireNonNull(certificateVerifier, "CertificateVerifier is not defined");
        Objects.requireNonNull(document, "The timestampFile must be defined!");
        Objects.requireNonNull(timestampType, "The TimestampType must be defined!");
        try {
            final TimestampToken newTimestampToken = new TimestampToken(DSSUtils.toByteArray(document), timestampType);
            newTimestampToken.setFileName(document.getName());
            newTimestampToken.matchData(getTimestampedData());
            return newTimestampToken;

        } catch (CMSException | TSPException | IOException e) {
            throw new DSSException(String.format("Unable to create a TimestampToken. Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Sets the data that has been timestamped
     *
     * @param document {@link DSSDocument} timestamped data
     */
    public void setTimestampedData(DSSDocument document) {
        Objects.requireNonNull(document, "The document is null");
        setDetachedContents(Arrays.asList(document));
    }

    @Override
    public DSSDocument getTimestampedData() {
        int size = Utils.collectionSize(detachedContents);
        if (size == 0) {
            return null;
        } else if (size > 1) {
            throw new IllegalArgumentException("Only one detached document shall be provided for a timestamp validation!");
        }
        return detachedContents.iterator().next();
    }

    /**
     * Finds timestamp scopes
     *
     * @param timestampToken {@link TimestampToken}
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> getTimestampScopes(TimestampToken timestampToken) {
        DetachedTimestampScopeFinder timestampScopeFinder = new DetachedTimestampScopeFinder();
        timestampScopeFinder.setTimestampedData(getTimestampedData());
        return timestampScopeFinder.findTimestampScope(timestampToken);
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(String signatureId) {
        // TODO : add extraction of original documents
        throw new UnsupportedOperationException();
    }

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("getOriginalDocuments(AdvancedSignature) is " +
                "not supported for DetachedTimestampValidator!");
    }

}
