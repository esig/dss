package eu.europa.esig.dss.xades.validation.scope;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.scope.EncapsulatedTimestampScopeFinder;
import eu.europa.esig.dss.validation.scope.SignatureScope;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.apache.xml.security.signature.Reference;

import java.util.ArrayList;
import java.util.List;

/**
 * Finds a timestamp scope for a XAdES encapsulated timestamps
 *
 */
public class XAdESTimestampScopeFinder extends EncapsulatedTimestampScopeFinder {

    @Override
    protected List<SignatureScope> filterCoveredSignatureScopes(TimestampToken timestampToken) {
        final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
        if (Utils.isCollectionNotEmpty(timestampIncludes)) {
            List<SignatureScope> individualSignatureScopes = new ArrayList<>();
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            for (Reference reference : xadesSignature.getReferences()) {
                if (isContentTimestampedReference(reference, timestampIncludes)) {
                    List<SignatureScope> signatureScopes = signature.getSignatureScopes();
                    if (Utils.isCollectionNotEmpty(signatureScopes)) {
                        for (SignatureScope signatureScope : signatureScopes) {
                            if (Utils.endsWithIgnoreCase(reference.getURI(), signatureScope.getName())) {
                                individualSignatureScopes.add(signatureScope);
                            }
                        }
                    }
                }
            }
            return individualSignatureScopes;
        }
        return super.filterCoveredSignatureScopes(timestampToken);
    }

    private boolean isContentTimestampedReference(Reference reference, List<TimestampInclude> includes) {
        for (TimestampInclude timestampInclude : includes) {
            if (reference.getId().equals(timestampInclude.getURI())) {
                return true;
            }
        }
        return false;
    }

}
