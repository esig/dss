package eu.europa.esig.dss.pki.jaxb.builder;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * A generic builder class that facilitates the creation of instances of various classes
 * by allowing attributes to be modified through chained method calls.
 *
 * @param <F> The type of object that this builder creates.
 */
public class PKIJaxbGenericBuilder<F> {

    private final List<Consumer<F>> instanceModifiers = new ArrayList<>();
    private final Supplier<F> instantiator;

    /**
     * Creates a new instance of the GenericBuilder class.
     *
     * @param instantiator A supplier function that provides instances of the desired type.
     */
    public PKIJaxbGenericBuilder(Supplier<F> instantiator) {
        this.instantiator = instantiator;
    }

    /**
     * Creates a new GenericBuilder instance with the provided instantiator function.
     *
     * @param instantiator A supplier function that provides instances of the desired type.
     * @param <F>          The type of object that this builder creates.
     * @return A new GenericBuilder instance.
     */
    public static <F> PKIJaxbGenericBuilder<F> of(Supplier<F> instantiator) {
        return new PKIJaxbGenericBuilder<>(instantiator);
    }

    /**
     * Configures an attribute of the instance being built using the provided consumer function.
     *
     * @param consumer The consumer function to modify an attribute of the instance.
     * @param value    The value to set for the attribute.
     * @param <U>      The type of the value being set.
     * @return The current GenericBuilder instance.
     */
    public <U> PKIJaxbGenericBuilder<F> with(BiConsumer<F, U> consumer, U value) {
        Consumer<F> c = instance -> consumer.accept(instance, value);
        instanceModifiers.add(c);
        return this;
    }

    /**
     * Constructs an instance of the specified type with the configured attribute modifications.
     *
     * @return A new instance of the specified type with the configured attributes.
     */
    public F build() {
        F value = instantiator.get();
        instanceModifiers.forEach(modifier -> modifier.accept(value));
        instanceModifiers.clear();
        return value;
    }
}
