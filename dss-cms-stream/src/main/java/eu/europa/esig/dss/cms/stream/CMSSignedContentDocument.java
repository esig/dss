package eu.europa.esig.dss.cms.stream;

import eu.europa.esig.dss.model.CommonDocument;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * This class is used to extract a wrapped signed content from a CMS document.
 * The class allows providing digest in order to avoid reading the document.
 *
 */
public class CMSSignedContentDocument extends CommonDocument {

    /** Main CMS document to read content from */
    private final DSSDocument cmsDocument;

    /** Signed content type OID */
    private ASN1ObjectIdentifier signedContentType;

    /**
     * Default constructor
     *
     * @param cmsDocument {@link DSSDocument} representing the CMS document
     */
    public CMSSignedContentDocument(final DSSDocument cmsDocument) {
        this.cmsDocument = cmsDocument;
    }

    /**
     * Sets signed content type OID
     *
     * @param signedContentType {@link ASN1ObjectIdentifier}
     */
    public void setSignedContentType(ASN1ObjectIdentifier signedContentType) {
        this.signedContentType = signedContentType;
    }

    @Override
    public InputStream openStream() {
        try {
            InputStream is = cmsDocument.openStream();
            BufferedInputStream bis = new BufferedInputStream(is);
            CMSSignedDataParser cmsSignedDataParser = new CMSSignedDataParser(new BcDigestCalculatorProvider(), bis);
            CMSTypedStream signedContent = cmsSignedDataParser.getSignedContent();
            InputStream signedContentStream = signedContent.getContentStream();

            // new InputStream is created in order to ensure closing of the parent InputStream's
            return new InputStream() {

                @Override
                public int read() throws IOException {
                    return signedContentStream.read();
                }

                @Override
                public int read(byte[] b) throws IOException {
                    return signedContentStream.read(b);
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    return signedContentStream.read(b, off, len);
                }

                @Override
                public void close() throws IOException {
                    super.close();
                    Utils.closeQuietly(signedContentStream);
                    Utils.closeQuietly(bis);
                    Utils.closeQuietly(is);
                }

            };

        } catch (CMSException e) {
            throw new DSSException(String.format("Unable to extract original signed content from CMS. Reason : %s",
                    e.getMessage()), e);

        }
    }

    /**
     * Returns a {@code CMSTypedData} for a signature creation
     *
     * @return {@link CMSTypedData}
     */
    public CMSTypedData toCMSTypedData() {
        // NOTE: this object is defined because {@code CMSProcessableInputStream} class is package protected
        return new CMSTypedData() {

            @Override
            public void write(OutputStream out) throws IOException {
                try (InputStream is = openStream()) {
                    Utils.copy(is, out);
                }
            }

            @Override
            public Object getContent() {
                return openStream();
            }

            @Override
            public ASN1ObjectIdentifier getContentType() {
                return signedContentType;
            }

        };
    }

    /**
     * This method allows to add a {@code Digest} with a new digest algorithm to the current DigestDocument.
     * Overwrites the previous digest if the same DigestAlgorithm is provided.
     *
     * @param digest
     *            {@link Digest} for the current document
     */
    public void addDigest(final Digest digest) {
        Objects.requireNonNull(digest, "The Digest is not defined");
        digestMap.put(digest.getAlgorithm(), digest.getValue());
    }

    @Override
    public void save(String filePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            writeTo(fos);
        }
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Objects.hashCode(cmsDocument);
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        CMSSignedContentDocument that = (CMSSignedContentDocument) o;
        return Objects.equals(cmsDocument, that.cmsDocument);
    }

}
