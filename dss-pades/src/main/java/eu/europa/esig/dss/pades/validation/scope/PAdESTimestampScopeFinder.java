package eu.europa.esig.dss.pades.validation.scope;

import eu.europa.esig.dss.pades.validation.timestamp.PdfTimestampToken;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.scope.TimestampScopeFinder;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class PAdESTimestampScopeFinder extends PdfRevisionScopeFinder implements TimestampScopeFinder {

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact() && timestampToken instanceof PdfTimestampToken) {
            return Arrays.asList(findSignatureScope(((PdfTimestampToken) timestampToken).getPdfRevision()));
        }
        return Collections.emptyList();
    }

}
