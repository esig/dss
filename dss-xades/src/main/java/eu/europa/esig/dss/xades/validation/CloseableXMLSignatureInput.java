package eu.europa.esig.dss.xades.validation;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.signature.XMLSignatureInput;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * This class is a workaround of the issue {@link <a href="https://issues.apache.org/jira/browse/SANTUARIO-622">SANTUARIO-622</a>}
 * The class overrides {@code #updateOutputStream} method, which does not close InputStream in the finally block.
 *
 */
public class CloseableXMLSignatureInput extends XMLSignatureInput {

    /** Local copy of the InputStream in order to handle the closing */
    private final InputStream localCopy;

    /**
     * Default constructor
     *
     * @param inputOctetStream {@link InputStream}
     */
    public CloseableXMLSignatureInput(InputStream inputOctetStream) {
        super(inputOctetStream);
        this.localCopy = inputOctetStream;
    }

    /**
     * This constructor is used to create an {@code XMLSignatureInput} instance with a pre-calculated digest value.
     * This constructor does not use {@code InputStream}, thus it does not close it.
     *
     * @param preCalculatedDigest {@link String}
     */
    protected CloseableXMLSignatureInput(String preCalculatedDigest) {
        super(preCalculatedDigest);
        this.localCopy = null;
    }

    @Override
    public void updateOutputStream(OutputStream diOs, boolean c14n11) throws CanonicalizationException, IOException {
        try {
            super.updateOutputStream(diOs, c14n11);
        } finally {
            // force close, close is only executed in catch clause...
            if (localCopy != null) {
                localCopy.close();
            }
        }

    }
}
