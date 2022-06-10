package eu.europa.esig.dss.validation;

/**
 * This interface is used to initialize a new {@code RevocationDataLoadingStrategy}.
 *
 */
public interface RevocationDataLoadingStrategyFactory {

    /**
     * This method initializes a new {@code RevocationDataLoadingStrategy}
     *
     * @return {@link RevocationDataLoadingStrategy}
     */
    RevocationDataLoadingStrategy create();

}
