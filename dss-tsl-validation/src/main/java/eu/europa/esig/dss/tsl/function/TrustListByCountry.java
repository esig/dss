package eu.europa.esig.dss.tsl.function;

import java.util.Collections;
import java.util.Set;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSLSchemeInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;

public class TrustListByCountry implements TrustedListPredicate {

    private final Set<String> countryCodes;

    public TrustListByCountry(String countryCode) {
        this(Collections.singleton(countryCode));
    }

    public TrustListByCountry(Set<String> countryCodes) {
        this.countryCodes = countryCodes;
    }

    @Override
    public boolean test(TrustStatusListType trustedList) {
        if (trustedList != null && Utils.isCollectionNotEmpty(countryCodes)) {
            TSLSchemeInformationType schemeInformation = trustedList.getSchemeInformation();
            String schemeTerritory = schemeInformation.getSchemeTerritory();

            for (String countryCode : countryCodes) {
                if (Utils.areStringsEqualIgnoreCase(countryCode, schemeTerritory)) {
                    return true;
                }
            }
        }
        return false;
    }
}