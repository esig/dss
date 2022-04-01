package eu.europa.esig.dss.signature.resources;

/**
 * This class creates an {@code InMemoryResourcesFactory} to create in-memory objects
 *
 * NOTE: This implementation is used by default
 */
public class InMemoryResourcesFactoryBuilder implements DSSResourcesFactoryBuilder<InMemoryResourcesFactory> {

    @Override
    public InMemoryResourcesFactory instantiateFactory() {
        return new InMemoryResourcesFactory();
    }

}
