package eu.europa.esig.dss.validation.revocation;

/**
 * This class build a {@code CRLFirstRevocationDataLoadingStrategy}
 *
 */
public class CRLFirstRevocationDataLoadingStrategyBuilder extends RevocationDataLoadingStrategyBuilder {

    @Override
    protected RevocationDataLoadingStrategy instantiate() {
        return new CRLFirstRevocationDataLoadingStrategy();
    }

}
