package eu.europa.esig.dss.signature.resources;

import java.util.Objects;

/**
 * This class provides to define a logic to be used across all implementations using a customizable
 * {@code eu.europa.esig.dss.signature.resources.DSSResourcesFactory}
 *
 */
public class ResourcesFactoryProvider {

    /**
     * Singleton class
     */
    private static ResourcesFactoryProvider singleton;

    /**
     * The builder to be used to create a new {@code DSSResourcesFactory} for each internal call
     */
    private DSSResourcesFactoryBuilder<?> resourcesFactoryBuilder = new InMemoryResourcesFactoryBuilder();

    /**
     * Singleton class
     */
    private ResourcesFactoryProvider() {
    }

    /**
     * This method returns the instance of the current class
     *
     * @return {@link ResourcesFactoryProvider}
     */
    public static ResourcesFactoryProvider getInstance() {
        if (singleton == null) {
            singleton = new ResourcesFactoryProvider();
        }
        return singleton;
    }

    /**
     * Sets {@code DSSResourcesFactoryBuilder} to be used for a {@code DSSResourcesFactory} creation in internal methods
     *
     * @param resourcesFactoryBuilder {@link DSSResourcesFactoryBuilder}
     */
    public void setResourcesFactoryBuilder(DSSResourcesFactoryBuilder<?> resourcesFactoryBuilder) {
        Objects.requireNonNull(resourcesFactoryBuilder, "DSSResourcesFactoryBuilder cannot be null!");
        this.resourcesFactoryBuilder = resourcesFactoryBuilder;
    }

    /**
     * This method instantiates a new {@code DSSResourcesFactory}
     *
     * @return {@link DSSResourcesFactory}
     */
    public DSSResourcesFactory getFactory() {
        return resourcesFactoryBuilder.instantiateFactory();
    }

}
