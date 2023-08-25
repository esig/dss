package eu.europa.esig.dss.asic.common;

/**
 * Builds a new instance of {@code ZipContainerHandler}
 *
 * @param <T> {@code eu.europa.esig.dss.asic.common.ZipContainerHandler}
 */
public interface ZipContainerHandlerBuilder<T extends ZipContainerHandler> {

    /**
     * Builds a new instance of {@code ZipContainerHandler}
     *
     * @return {@link eu.europa.esig.dss.asic.common.ZipContainerHandler}
     */
    T build();

}
