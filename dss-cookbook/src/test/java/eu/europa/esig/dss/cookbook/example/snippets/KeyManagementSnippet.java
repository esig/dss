package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.MSCAPISignatureToken;
import eu.europa.esig.dss.token.predicate.AllKeyEntryPredicate;
import eu.europa.esig.dss.token.predicate.ExtendedKeyUsageKeyEntryPredicate;
import eu.europa.esig.dss.token.predicate.KeyUsageKeyEntryPredicate;
import eu.europa.esig.dss.token.predicate.ValidAtTimeKeyEntryPredicate;

import java.io.IOException;
import java.util.Date;
import java.util.List;

public class KeyManagementSnippet {

    public static void main(String[] args) throws IOException {

        // tag::demo[]
        // import eu.europa.esig.dss.enumerations.KeyUsageBit
        // import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
        // import eu.europa.esig.dss.token.Pkcs11SignatureToken;
        // import eu.europa.esig.dss.token.predicate.KeyUsageKeyEntryPredicate;

        try (MSCAPISignatureToken token = new MSCAPISignatureToken()) {

            // Set a KeyUsageKeyEntryPredicate filtering keys related to a certificate with a digitalSignature key usage bit
            token.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.DIGITAL_SIGNATURE));

            // The method will return keys corresponding to certificates with defined digitalSignature key usage
            List<DSSPrivateKeyEntry> keys = token.getKeys();
        }
        // end::demo[]

        try (MSCAPISignatureToken token = new MSCAPISignatureToken()) {

            // tag::implementations[]
            // import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
            // import eu.europa.esig.dss.enumerations.KeyUsageBit;
            // import eu.europa.esig.dss.token.predicate.AllKeyEntryPredicate;
            // import eu.europa.esig.dss.token.predicate.ExtendedKeyUsageKeyEntryPredicate;
            // import eu.europa.esig.dss.token.predicate.KeyUsageKeyEntryPredicate;
            // import eu.europa.esig.dss.token.predicate.ValidAtTimeKeyEntryPredicate;
            // import java.util.Date;

            // AllKeyEntryPredicate (default) is used to accept all keys
            token.setKeyEntryPredicate(new AllKeyEntryPredicate());

            // KeyUsageKeyEntryPredicate is used to filter keys by a keyUsage certificate attribute
            token.setKeyEntryPredicate(new KeyUsageKeyEntryPredicate(KeyUsageBit.NON_REPUDIATION));

            // ExtendedKeyUsageKeyEntryPredicate is used to filter keys by an extendedKeyUsage certificate attribute
            token.setKeyEntryPredicate(new ExtendedKeyUsageKeyEntryPredicate(ExtendedKeyUsage.TIMESTAMPING));

            // ValidAtTimeKeyEntryPredicate is used to filter keys by the certificate validity time
            token.setKeyEntryPredicate(new ValidAtTimeKeyEntryPredicate(new Date()));
            // end::implementations[]

        }

    }

}
