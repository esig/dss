package eu.europa.esig.dss.validation.revocation;

/**
 * This class is used to build a {@code OCSPFirstRevocationDataLoadingStrategy}
 *
 */
public class OCSPFirstRevocationDataLoadingStrategyBuilder extends RevocationDataLoadingStrategyBuilder {

    @Override
    protected RevocationDataLoadingStrategy instantiate() {
        return new OCSPFirstRevocationDataLoadingStrategy();
    }

}
