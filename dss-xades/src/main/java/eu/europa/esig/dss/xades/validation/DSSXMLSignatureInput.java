package eu.europa.esig.dss.xades.validation;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.implementations.Canonicalizer11_OmitComments;
import org.apache.xml.security.c14n.implementations.Canonicalizer20010315OmitComments;
import org.apache.xml.security.c14n.implementations.CanonicalizerBase;
import org.apache.xml.security.signature.XMLSignatureInput;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DSSXMLSignatureInput extends XMLSignatureInput {

    private final InputStream localCopy;

    public DSSXMLSignatureInput(InputStream inputOctetStream) {
        super(inputOctetStream);
        this.localCopy = inputOctetStream;
    }

    public void updateOutputStream(OutputStream diOs, boolean c14n11)
            throws CanonicalizationException, IOException {

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
